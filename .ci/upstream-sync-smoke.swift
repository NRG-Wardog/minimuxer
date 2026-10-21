// Source-only harness: the runner concatenates reviewed production Swift files.
// No native backend, networking, credentials, or app authentication is loaded.
import Foundation

actor FakeEndGate {
    private var continuation: CheckedContinuation<Void, Never>?
    private var entered = false
    func pause() async {
        await withCheckedContinuation { continuation in
            self.continuation = continuation
            entered = true
        }
    }
    func waitUntilPaused() async { while !entered { await Task.yield() } }
    func resume() { continuation?.resume(); continuation = nil }
}

final class FakeGateway: DeviceGatewayAPI, @unchecked Sendable {
    private let lock = NSLock()
    private var started = 0
    private var ended = 0
    private var port: UInt16
    private var portWrites = 0
    let backend: GatewayBackend
    let initialized = true
    let endGate: FakeEndGate?
    init(backend: GatewayBackend = .idevice, port: UInt16 = 49151, endGate: FakeEndGate? = nil) {
        self.backend = backend
        self.port = port
        self.endGate = endGate
    }
    var counts: (Int, Int) { lock.withLock { (started, ended) } }
    var portState: (UInt16, Int) { lock.withLock { (port, portWrites) } }
    func setPort(_ port: UInt16, for protocolType: PairingProtocol) {
        lock.withLock { self.port = port; portWrites += 1 }
    }
    func beginTransportBatch() async { lock.withLock { started += 1 } }
    func endTransportBatch() async {
        let firstEnd = lock.withLock { ended += 1; return ended == 1 }
        if firstEnd, let endGate { await endGate.pause() }
    }
}

final class FakeProbeCore {
    var timeout = 0
    func setDeviceProbeTimeout(_ timeout: Int) { self.timeout = timeout }
}

// The runner inserts the exact production Minimuxer.set method, not a copy of
// its algorithm. Only gateway construction and unrelated dependencies are fake.
final class FakeConfigurationFacade: MinimuxerFacade, @unchecked Sendable {
    private static let lock = NSLock()
    private static var currentBackend: GatewayBackend = .idevice
    private static var currentRemotePairingPort: UInt16 = 41000
    private static var currentDeviceProbeTimeout: Int = 1000
    private(set) static var constructed: [FakeGateway] = []
    let deviceProvider: DeviceProvider
    let core = FakeProbeCore()
    init(gateway: FakeGateway) {
        Self.currentBackend = gateway.backend
        Self.currentRemotePairingPort = gateway.portState.0
        Self.currentDeviceProbeTimeout = 1000
        Self.constructed = []
        self.deviceProvider = DeviceProvider(gateway: gateway)
    }
    var gateway: FakeGateway { deviceProvider.gateway as! FakeGateway }
    private static func makeGateway(for backend: GatewayBackend) -> any DeviceGatewayAPI {
        let gateway = FakeGateway(backend: backend)
        constructed.append(gateway)
        return gateway
    }
    // PRODUCTION_SET_METHOD
}

@main struct UpstreamSyncSmoke {
    static func require(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() { fatalError(message) }
    }

    static func main() async throws {
        let lockdownKeys = ["WiFiMACAddress", "SystemBUID", "RootPrivateKey", "HostPrivateKey", "HostID", "RootCertificate", "UDID", "EscrowBag", "HostCertificate", "DeviceCertificate"]
        let remoteKeys = ["private_key", "public_key", "identifier"]
        var lockdown: [String: any Sendable] = [:]
        for key in lockdownKeys { lockdown[key] = "synthetic-test-value" }
        var remote: [String: any Sendable] = [:]
        for key in remoteKeys { remote[key] = "synthetic-test-value" }
        let composite = lockdown.merging(remote) { old, _ in old }
        let defaultComposite = try PairingFileParser.validatePairingFile(from: composite)
        let explicitRemote = try PairingFileParser.validatePairingFile(from: composite, preferred: .rppairing)
        let explicitLockdown = try PairingFileParser.validatePairingFile(from: composite, preferred: .lockdown)
        require(defaultComposite == .lockdown, "Composite default lost Lockdown-first policy")
        require(explicitRemote == .rppairing, "Explicit remote pairing ignored")
        require(explicitLockdown == .lockdown, "Explicit Lockdown ignored")
        for (data, preferred) in [(remote, PairingProtocol.lockdown), (lockdown, .rppairing), (composite, .unknown)] {
            do {
                _ = try PairingFileParser.validatePairingFile(from: data, preferred: preferred)
                fatalError("Invalid explicit pairing selection was accepted")
            } catch is PairingError { }
        }
        do {
            _ = try PairingFileParser.validatePairingFile(from: nil)
            fatalError("Missing pairing data accepted")
        } catch is PairingError { }

        var cases = 0
        for modern in [false, true] {
            for mode in [DeviceConnectionMode.notConfigured, .localVPN, .remoteServer] {
                for pairing in [PairingProtocol.unknown, .lockdown, .rppairing] {
                    for utun in [false, true] {
                        for ipsec in [false, true] {
                            for supported in [false, true] {
                                let selected = RefreshTransportPolicy.select(modernOS: modern, mode: mode, pairing: pairing, utun: utun, ipsec: ipsec, coreDeviceSupported: supported).transport
                                let expected: RefreshTransport
                                if pairing == .unknown { expected = .unavailable }
                                else if mode == .remoteServer { expected = .proxy }
                                else if mode != .localVPN || !utun { expected = .unavailable }
                                else if pairing == .rppairing { expected = .remotePairing }
                                else if modern && supported { expected = .coreDevice }
                                else if ipsec { expected = .lockdownIPSec }
                                else if !modern { expected = .lockdownLegacy }
                                else { expected = .unavailable }
                                require(selected == expected, "Transport matrix mismatch")
                                cases += 1
                            }
                        }
                    }
                }
            }
        }
        require(cases == 144, "Incomplete transport matrix")

        let first = FakeGateway()
        let second = FakeGateway()
        let provider = DeviceProvider(gateway: first)
        await provider.beginTransportBatch()
        await provider.beginTransportBatch()
        provider.setConfiguration(gateway: second, remotePairingPort: 49151)
        require(provider.gateway === first, "Gateway switched inside a batch")
        await provider.endTransportBatch()
        require(provider.gateway === first, "Gateway switched before nested batch ended")
        await provider.endTransportBatch()
        require(provider.gateway === second, "Deferred gateway did not apply")
        require(first.counts == (2, 2), "Original gateway did not receive paired begin/end")
        require(second.counts == (0, 0), "New gateway received stale batch callbacks")
        await provider.endTransportBatch()
        require(second.counts == (0, 0), "Unpaired end reached new gateway")
        await provider.beginTransportBatch()
        await provider.endTransportBatch()
        require(second.counts == (1, 1), "New gateway could not start a fresh batch")
        // Combined backend+port stays atomic through a nested native lease.
        let combinedOld = FakeGateway(port: 41000)
        let combined = FakeConfigurationFacade(gateway: combinedOld)
        await combined.deviceProvider.beginTransportBatch()
        await combined.deviceProvider.beginTransportBatch()
        combined.set(MinimuxerParams(backend: .libimobiledevice, remotePairingPort: 42000))
        let combinedNew = FakeConfigurationFacade.constructed.last!
        require(combined.gateway === combinedOld && combinedOld.portState == (41000, 0), "Combined set mutated active route")
        require(combinedNew.portState.1 == 0, "Pending configuration applied before lease release")
        await combined.deviceProvider.endTransportBatch()
        require(combined.gateway === combinedOld && combinedOld.portState == (41000, 0), "Penultimate end applied combined set")
        await combined.deviceProvider.endTransportBatch()
        require(combined.gateway === combinedNew && combinedNew.portState == (42000, 1), "Combined configuration was stale or split")
        require(combinedOld.counts == (2, 2), "Combined change lost original lease pairing")
        await combined.deviceProvider.beginTransportBatch()
        require(combined.gateway === combinedNew && combinedNew.portState.0 == 42000, "Next batch started on stale config")
        await combined.deviceProvider.endTransportBatch()
        require(combinedNew.counts == (1, 1), "Next batch did not use new backend")

        // Port-only changes preserve the loaded gateway and never invalidate a lease.
        let portOld = FakeGateway(port: 41000)
        let portOnly = FakeConfigurationFacade(gateway: portOld)
        await portOnly.deviceProvider.beginTransportBatch()
        await portOnly.deviceProvider.beginTransportBatch()
        portOnly.set(MinimuxerParams(remotePairingPort: 43000))
        require(portOld.portState == (41000, 0), "Port-only set mutated active transport")
        await portOnly.deviceProvider.endTransportBatch()
        require(portOld.portState == (41000, 0), "Port-only set ignored nested lease")
        await portOnly.deviceProvider.endTransportBatch()
        require(portOnly.gateway === portOld && portOld.portState == (43000, 1), "Port-only set replaced or missed gateway")
        require(portOld.initialized && FakeConfigurationFacade.constructed.isEmpty, "Port-only set lost initialized gateway")
        await portOnly.deviceProvider.endTransportBatch()
        require(portOld.counts == (2, 2) && portOld.portState == (43000, 1), "Unpaired end changed native lease or config")

        // Later port-only updates follow the pending backend; reversals are last-wins.
        let coalescedOld = FakeGateway(port: 41000)
        let coalesced = FakeConfigurationFacade(gateway: coalescedOld)
        await coalesced.deviceProvider.beginTransportBatch()
        coalesced.set(MinimuxerParams(backend: .libimobiledevice))
        let pendingB = FakeConfigurationFacade.constructed.last!
        coalesced.set(MinimuxerParams(remotePairingPort: 44000))
        require(coalescedOld.portState == (41000, 0) && pendingB.portState.1 == 0, "Port update mutated active or pending gateway early")
        await coalesced.deviceProvider.endTransportBatch()
        require(coalesced.gateway === pendingB && pendingB.portState == (44000, 1), "Later port-only change missed pending backend")
        await coalesced.deviceProvider.beginTransportBatch()
        coalesced.set(MinimuxerParams(backend: .idevice, remotePairingPort: 45000))
        let supersededA = FakeConfigurationFacade.constructed.last!
        coalesced.set(MinimuxerParams(backend: .libimobiledevice, remotePairingPort: 46000))
        let latestB = FakeConfigurationFacade.constructed.last!
        coalesced.set(MinimuxerParams(remotePairingPort: 47000))
        require(coalesced.gateway === pendingB && pendingB.portState == (44000, 1), "Backend reversal changed current lease")
        await coalesced.deviceProvider.endTransportBatch()
        require(coalesced.gateway === latestB && latestB.portState == (47000, 1), "Latest backend/port did not win")
        require(supersededA.portState.1 == 0 && supersededA.counts == (0, 0), "Superseded backend received mutation or lease")
        await coalesced.deviceProvider.beginTransportBatch()
        await coalesced.deviceProvider.endTransportBatch()
        require(latestB.counts == (1, 1), "Final backend missed next batch")

        // A native end suspended in flight still owns the lease. A concurrent
        // extra end is ignored, and config cannot apply until that callback ends.
        let endGate = FakeEndGate()
        let endingOld = FakeGateway(port: 41000, endGate: endGate)
        let ending = FakeConfigurationFacade(gateway: endingOld)
        await ending.deviceProvider.beginTransportBatch()
        ending.set(MinimuxerParams(remotePairingPort: 47500))
        let endTask = Task { await ending.deviceProvider.endTransportBatch() }
        await endGate.waitUntilPaused()
        await ending.deviceProvider.endTransportBatch()
        require(endingOld.counts == (1, 1) && endingOld.portState == (41000, 0), "In-flight native end lost its lease reservation")
        await endGate.resume()
        await endTask.value
        require(ending.gateway === endingOld && endingOld.portState == (47500, 1), "Native callback completion did not commit pending config")

        // Current boot route remains immediate when no native lease is active.
        let boot = FakeConfigurationFacade(gateway: FakeGateway(port: 41000))
        boot.set(MinimuxerParams(backend: .libimobiledevice, remotePairingPort: 48000, deviceProbeTimeout: 2000))
        let bootGateway = boot.gateway
        require(bootGateway.backend == .libimobiledevice && bootGateway.portState == (48000, 1), "Boot configuration was not immediate")
        require(boot.core.timeout == 2000, "Probe timeout behavior changed")
        boot.set(MinimuxerParams(remotePairingPort: 48001))
        require(boot.gateway === bootGateway && bootGateway.portState == (48001, 2), "Idle port-only update replaced gateway")
        print("SOURCE_ONLY_SWIFT_SMOKE_PASS pairing=7 transport_cases=144 gateway_batch_switch=pass atomic_configuration=pass")
    }
}
