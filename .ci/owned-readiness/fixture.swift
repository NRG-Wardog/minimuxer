import Foundation
func debugLog(_ value:String) {}
func verboseLog(_ value:String) {}
public enum MinimuxerError: Error { case pairingNotLoaded(String),notStarted(String),noConnection(String),noVPN(String),invalidVPN(String),noDevice(String),notReachable(String),muxerNotListening(String) }
enum DeviceConnectionMode: String,Sendable { case localVPN,remoteServer,notConfigured }
enum Pairing { case unknown,lockdown }
enum Transport { case coreDevice,unavailable,lockdown }
enum Cause { case missingRequiredVPNInterface,unsupportedBackend }
struct Decision { var transport:Transport = .coreDevice; var reason="synthetic";var unavailableCause:Cause? }
// Inert Network.framework boundaries for actual companion-monitor source.
enum NWInterface { enum InterfaceType { case wifi, cellular, other } }
struct NWPath {
    enum Status { case satisfied, unsatisfied, requiresConnection }
    var status: Status
    var wifi: Bool
    func usesInterfaceType(_ type: NWInterface.InterfaceType) -> Bool { type == .wifi && wifi }
}
final class NWPathMonitor {
    static var instances: [NWPathMonitor] = []
    static var callbackDuringStart = false
    var currentPath = NWPath(status: .unsatisfied, wifi: false)
    var pathUpdateHandler: ((NWPath) -> Void)?
    var starts = 0
    var cancellations = 0
    var startedAfterCancellation = false
    let required: NWInterface.InterfaceType
    init(requiredInterfaceType: NWInterface.InterfaceType) {
        required = requiredInterfaceType
        Self.instances.append(self)
    }
    func start(queue: DispatchQueue) {
        startedAfterCancellation = cancellations > 0
        starts += 1
        if Self.callbackDuringStart { emit(.satisfied, wifi: true) }
    }
    func cancel() { cancellations += 1 }
    func emit(_ status: NWPath.Status, wifi: Bool) {
        currentPath = NWPath(status: status, wifi: wifi)
        pathUpdateHandler?(currentPath)
    }
}
// WIFI_HELPER

// TYPES
// The only injected observation is synchronous and follows a captured running task.
final class JoinSignal: @unchecked Sendable {
    private let lock=NSLock()
    private var signalled=false
    private var waiter:CheckedContinuation<Void,Never>?
    func signal() {
        let continuation=lock.withLock { ()->CheckedContinuation<Void,Never>? in
            signalled=true
            defer {waiter=nil}
            return waiter
        }
        continuation?.resume()
    }
    func wait() async {
        await withCheckedContinuation { (continuation:CheckedContinuation<Void,Never>) in
            let resume=lock.withLock { ()->Bool in
                if signalled{return true}
                precondition(waiter==nil)
                waiter=continuation
                return false
            }
            if resume{continuation.resume()}
        }
    }
}
let fixtureJoinSignal=JoinSignal()
actor StartPublicationGate {
    private var armed = false
    private var entered = false
    private var paused: CheckedContinuation<Void, Never>?
    private var entryWaiters: [CheckedContinuation<Void, Never>] = []
    func arm() { precondition(paused == nil); armed = true; entered = false }
    func pauseIfArmed() async {
        guard armed else { return }
        armed = false
        entered = true
        let waiters = entryWaiters
        entryWaiters = []
        for waiter in waiters { waiter.resume() }
        await withCheckedContinuation { paused = $0 }
    }
    func waitForEntry() async {
        if entered { return }
        await withCheckedContinuation { entryWaiters.append($0) }
    }
    func release() { let continuation = paused; paused = nil; continuation?.resume() }
}
let fixtureStartPublicationGate = StartPublicationGate()

// COALESCER
actor Endpoint {
    var value:String?="127.0.0.1"
    var onRead:(() async ->Void)?
    func setOnRead(_ body:@escaping () async ->Void){onRead=body}
    func ip() async throws -> String { if let onRead{await onRead()};guard let value else {throw MinimuxerError.noDevice("synthetic")};return value }
    func update(_ s:String){value=s}
    func clear(){value=nil}
}
final class Provider {
    private let lock=NSLock();var activeBatches=1;var endingBatches=0
// PROVIDER_OWNERSHIP
}
final class Gateway { var hasActiveTransportBatch=true;var requiresUsbmuxd=false }
final class Proxy {var isListening=true;var attachments=0;func notifyDeviceAttached(tunnelPeerIp:String){attachments+=1};func notifyDeviceDetached(){} }
struct Info {var name="utunFixture";var interfaceAddresses="fixture";var linkType="fixture";var linkLayerDestinationIP:String?;var destinationIPs:[String]=[];var destinationGatewayIPs:[String]=[]}
final class Config {var mode=DeviceConnectionMode.localVPN;func getConnectionMode()->DeviceConnectionMode{mode};func getOverrideTunnelPeerIp()->String{""};func getRemoteServerIp()->String{""}}
actor DeviceConnectionManager {
// CONFIG_IDENTITY
    private var connectionConfigCache:Config?=Config()
    var vpnIface:Info?=Info();var overridePeerIp:String?;var isOverridePeerIpReachable=false;var derivedPeerIp:String?="127.0.0.1";var isDerivedPeerIpReachable=true;var remoteServerIp:String?;var isRemoteServerIpReachable=false;var changed=true;var refreshCount=0;var changeDuringScan=false;var scanGate:Latch?
    func getPreferredConnectionMode()->DeviceConnectionMode{connectionConfigCache!.mode}
    func refresh() async ->Bool {refreshCount+=1;if let scanGate{await scanGate.wait()};if changeDuringScan{configurationGeneration+=1;changeDuringScan=false};return changed}
    func setMode(_ m:DeviceConnectionMode){connectionConfigCache!.mode=m;configurationGeneration+=1}
    func setGate(_ value:Latch?){scanGate=value}
    func bump(){configurationGeneration+=1}
    func staleScan(){changeDuringScan=true}
    func unchangedNext(){changed=false}
    func noPeer(){derivedPeerIp=nil;isDerivedPeerIpReachable=false}
    func readyPeer(){derivedPeerIp="127.0.0.1";isDerivedPeerIpReachable=true}
}
final class Monitor {
    var currentPath=NWPath(status:.satisfied,wifi:true)
    var pathUpdateHandler:((NWPath)->Void)?
    var starts=0
    func start(queue:DispatchQueue){starts+=1}
    func cancel(){}
}
final class Subject {func send(_ path:NWPath){}}
final class Network: @unchecked Sendable {
// NETWORK_STATE
    private let state=State();private let monitor=Monitor();private let localVPNWiFi=LocalVPNWiFiObservation();private let queue=DispatchQueue(label:"fixture.default");let pathSubject=Subject()
    let connectionManager=DeviceConnectionManager();let endpoint:Endpoint;let proxyServer=Proxy();let endpointRefresh=EndpointRefreshTransaction();var publishedConfiguration:DeviceConnectionManager.ConfigurationIdentity?;var publishedLifecycle:UInt64?;var isWifiSatisfied=true
    init(_ endpoint:Endpoint,bootstrap:Bool=true){self.endpoint=endpoint;if bootstrap{localVPNWiFi.start();NWPathMonitor.instances.last!.emit(.satisfied,wifi:true)}}
// WIFI_ACCESSORS
    func stopLocalWiFiForFixture(){localVPNWiFi.stop()}
    func setLocalWiFi(_ satisfied:Bool){NWPathMonitor.instances.last!.emit(satisfied ? .satisfied : .unsatisfied,wifi:satisfied)}
// START
    func handleNetworkChange() async {}
// NETWORK
// STOP
    func fixtureStart() async {_ = await start()}
    var fixtureDefaultStarts:Int{monitor.starts}
    func fixtureState() async ->(Bool,UInt64,Bool){await state.with{($0.started,$0.lifecycle,$0.observationTask != nil)}}
}
actor State {enum Status {case started,stopped};var status=Status.started;func with<T>(_ block:(isolated State)->T)->T{block(self)}}
final class Core {
    var isPairingFileLoaded=true;let state=State();let gateway=Gateway();let deviceProvider=Provider();var pairingFileType=Pairing.lockdown;let endpoint=Endpoint();lazy var network=Network(endpoint);let proxyServer=Proxy();var activeProtocol="fixture";var decision=Decision();var reachable=true;var udidFailure=false;var fetches=0;var mutateConfigDuringFetch=false;var stopWiFiDuringFetch=false;var duringProbe:(()->Void)?
    func getConnectionMode() async ->DeviceConnectionMode{await network.connectionManager.getPreferredConnectionMode()}
    func configureRefreshTransport() async ->Decision{decision}
    func connectionNotConfiguredError()->MinimuxerError{.noDevice("not configured")}
    func testDeviceConnection(ifaddr:String)->Bool{duringProbe?();return reachable}
    func fetchUDID() async throws(MinimuxerError)->String {fetches+=1;if mutateConfigDuringFetch{await network.connectionManager.bump()};if stopWiFiDuringFetch{await network.fixtureStart();_ = await network.stop()};if udidFailure{throw .noDevice("arbitrary native failure")};return "synthetic"}
    func isDDIMounted() async throws(MinimuxerError)->Bool{true}
// CORE
}
actor Counter {var count=0;func increment(){count+=1}}
actor Latch {var open=false;var waiters:[CheckedContinuation<Void,Never>]=[];func wait() async {if open{return};await withCheckedContinuation{waiters.append($0)}};func release(){open=true;for w in waiters{w.resume()};waiters=[]}}
@main struct Cases {
    static func expect(_ value:Bool,_ name:String){precondition(value,name);print("PASS "+name)}
    static func ready(_ o:MinimuxerOwnedReadinessObservation)->Bool{if case .success(true)=o.result{return true};return false}
    static func main() async {
        await wifiObservationCases()
        let c=Core();expect(ready(await c.ownedNetworkReadinessProbe(withNetworkCheck:true)),"owned ready requires fresh scan");expect(await c.network.connectionManager.refreshCount==1,"one scan")
        let noBatch=Core();noBatch.gateway.hasActiveTransportBatch=false;noBatch.deviceProvider.activeBatches=0;let no=await noBatch.ownedNetworkReadinessProbe(withNetworkCheck:true);expect(!ready(no) && no.transient==nil && noBatch.fetches==0,"no batch cannot initialize")
        let ui=Core();ui.gateway.hasActiveTransportBatch=false;_ = await ui.isReady(withNetworkCheck:true,withDDIMountCheck:false);expect(await ui.network.connectionManager.refreshCount==0 && ui.fetches==0,"UI checks remain noninitializing")
        let wifi=Core();wifi.network.setLocalWiFi(false);expect(await wifi.ownedNetworkReadinessProbe(withNetworkCheck:true).transient == .wifiPending,"typed wifi guard")
        let vpn=Core();vpn.decision = .init(transport:.unavailable,reason:"synthetic",unavailableCause:.missingRequiredVPNInterface);expect(await vpn.ownedNetworkReadinessProbe(withNetworkCheck:true).transient == .vpnInterfacePending,"typed interface guard")
        let peer=Core();await peer.network.connectionManager.noPeer();expect(await peer.ownedNetworkReadinessProbe(withNetworkCheck:true).transient == .peerAddressPending,"typed endpoint guard")
        await peer.network.connectionManager.readyPeer();expect(ready(await peer.ownedNetworkReadinessProbe(withNetworkCheck:true)) && peer.fetches==0,"late peer fresh probe succeeds without mutation replay")
        let probe=Core();probe.reachable=false;expect(await probe.ownedNetworkReadinessProbe(withNetworkCheck:true).transient == .peerProbePending,"typed probe guard")
        let unsupported=Core();unsupported.decision = .init(transport:.unavailable,reason:"synthetic",unavailableCause:.unsupportedBackend);expect(await unsupported.ownedNetworkReadinessProbe(withNetworkCheck:true).transient==nil,"unsupported terminal")
        let pairing=Core();pairing.isPairingFileLoaded=false;expect(await pairing.ownedNetworkReadinessProbe(withNetworkCheck:true).transient==nil,"pairing terminal")
        let legacy=Core();legacy.gateway.hasActiveTransportBatch=false;legacy.decision.transport = .lockdown;expect(ready(await legacy.ownedNetworkReadinessProbe(withNetworkCheck:true)),"legacy provider owned batch preserved")
        let remote=Core();await remote.network.connectionManager.setMode(.remoteServer);remote.reachable=false;expect(await remote.ownedNetworkReadinessProbe(withNetworkCheck:true).transient==nil,"remote terminal")
        let native=Core();native.udidFailure=true;expect(ready(await native.ownedNetworkReadinessProbe(withNetworkCheck:true)) && native.fetches==0,"network probe never enters native initialization")
        let nativeResult=await native.isReady(withNetworkCheck:true,withDDIMountCheck:false);if case .success = nativeResult{preconditionFailure("native error lost")};expect(native.fetches==1,"subsequent native readiness executes once")
        let untouched=Core();untouched.mutateConfigDuringFetch=true;expect(ready(await untouched.ownedNetworkReadinessProbe(withNetworkCheck:true)) && untouched.fetches==0,"network probe cannot trigger native config side effect")
        let changedRoute=Core();await changedRoute.endpoint.setOnRead {await changedRoute.network.connectionManager.bump()};expect(!ready(await changedRoute.ownedNetworkReadinessProbe(withNetworkCheck:true)) && changedRoute.fetches==0,"changed route before native fetch rejected")
        let scan=Core();await scan.network.connectionManager.staleScan();expect(!ready(await scan.ownedNetworkReadinessProbe(withNetworkCheck:true)) && scan.fetches==0 && scan.network.proxyServer.attachments==0,"stale scan cannot publish or fetch")
        await scan.network.connectionManager.unchangedNext();expect(ready(await scan.ownedNetworkReadinessProbe(withNetworkCheck:true)) && scan.network.proxyServer.attachments==1,"rejected scan then unchanged scan still publishes")
        let ending=Core();ending.deviceProvider.endingBatches=1;expect(!ready(await ending.ownedNetworkReadinessProbe(withNetworkCheck:true)),"ending batch cannot initialize")
        let cancelled=Task { ()->MinimuxerOwnedReadinessObservation in withUnsafeCurrentTask{$0?.cancel()};return await Core().ownedNetworkReadinessProbe(withNetworkCheck:true) };expect(!ready(await cancelled.value),"cancelled owner cannot initialize")
        let stopped=Core();await stopped.network.fixtureStart();let scanLatch=Latch();await stopped.network.connectionManager.setGate(scanLatch)
        let pending=Task{await stopped.network.refreshEndpointValidated()}
        while await stopped.network.connectionManager.refreshCount==0{await Task.yield()}
        _ = await stopped.network.stop();await scanLatch.release();expect(!(await pending.value) && stopped.network.proxyServer.attachments==0,"stop invalidates shared publication")
        await stopped.network.connectionManager.setGate(nil);await stopped.network.fixtureStart();expect(await stopped.network.refreshEndpointValidated(),"new lifecycle fresh publication")
        let transaction=EndpointRefreshTransaction();let latch=Latch();let starts=Counter()
        let first=Task {await transaction.run {await starts.increment();await latch.wait();return true}}
        while await starts.count==0 {await Task.yield()}
        let second=Task {return await transaction.run {await starts.increment();return false}}
        await fixtureJoinSignal.wait()
        second.cancel();await latch.release();expect(await first.value,"shared operation completes");expect(await second.value,"cancelled waiter does not cancel shared operation");expect(await starts.count==1,"concurrent scans coalesced")
        expect(await transaction.run {true},"completed transaction releases slot")
        print("OWNED_READINESS_SOURCE_RUNTIME_PASS no_device_execution=true")
    }
}

// Actual state/monitor code above; only framework callbacks are synthetic.
extension Cases {
    static func wifiObservationCases() async {
        let observer = LocalVPNWiFiObservation()
        expect(!observer.snapshot().satisfied && !observer.snapshot().observed, "unstarted local Wi-Fi fails closed")
        observer.start()
        let first = NWPathMonitor.instances.last!
        expect(first.required == .wifi && first.starts == 1, "actual Wi-Fi-specific constructor and single start")
        first.currentPath = .init(status: .satisfied, wifi: true)
        expect(!observer.snapshot().satisfied, "currentPath alone before first callback cannot admit")
        first.emit(.satisfied, wifi: true)
        expect(observer.snapshot().satisfied, "current generation callback admits Wi-Fi observation only")
        first.currentPath = .init(status: .unsatisfied, wifi: false)
        expect(!observer.snapshot().satisfied, "no retained true after current path changes")
        first.emit(.satisfied, wifi: false)
        expect(!observer.snapshot().satisfied, "satisfied cellular or other path cannot satisfy local Wi-Fi")
        first.emit(.requiresConnection, wifi: true)
        expect(!observer.snapshot().satisfied, "requiresConnection Wi-Fi is not satisfied")
        first.emit(.satisfied, wifi: true)
        let old = first.pathUpdateHandler!
        let oldGeneration = observer.snapshot().generation
        observer.start()
        expect(NWPathMonitor.instances.last === first && first.starts == 1, "duplicate start does not leak monitor")
        observer.stop()
        old(.init(status: .satisfied, wifi: true))
        expect(!observer.snapshot().observed && first.cancellations == 1, "stop rejects queued old callback")
        observer.start()
        let second = NWPathMonitor.instances.last!
        old(.init(status: .satisfied, wifi: true))
        expect(second !== first && observer.snapshot().generation != oldGeneration && !observer.snapshot().observed, "restart allocates fresh monitor and fences old generation")
        second.emit(.satisfied, wifi: true)
        expect(observer.snapshot().satisfied, "fresh restarted callback becomes observable")
        observer.stop()

        NWPathMonitor.callbackDuringStart = true
        let synchronous = LocalVPNWiFiObservation()
        synchronous.start()
        expect(synchronous.snapshot().satisfied, "synchronous inert callback cannot deadlock start admission")
        synchronous.stop()
        NWPathMonitor.callbackDuringStart = false
        let concurrent = LocalVPNWiFiObservation()
        let firstConcurrentIndex = NWPathMonitor.instances.count
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<64 { group.addTask { concurrent.start(); concurrent.stop() } }
        }
        concurrent.stop()
        let concurrentMonitors = NWPathMonitor.instances.dropFirst(firstConcurrentIndex)
        expect(!concurrentMonitors.isEmpty && concurrentMonitors.allSatisfy { $0.starts == 1 && $0.cancellations == 1 && !$0.startedAfterCancellation }, "concurrent start stop never revives or leaks a cancelled monitor")

        let service = Network(Endpoint(), bootstrap: false)
        let serviceMonitorCount = NWPathMonitor.instances.count
        let admittedStarts = await withTaskGroup(of: Bool.self, returning: Int.self) { group in
            for _ in 0..<64 { group.addTask { await service.start() } }
            var total = 0
            for await admitted in group { if admitted { total += 1 } }
            return total
        }
        expect(admittedStarts == 1 && service.fixtureDefaultStarts == 1 && NWPathMonitor.instances.count == serviceMonitorCount + 1, "actual service start admission is atomic")
        let serviceStarted = await service.fixtureState()
        expect(serviceStarted.0 && serviceStarted.2, "actual service task publication belongs to admitted lifecycle")
        _ = await service.stop()
        let serviceStopped = await service.fixtureState()
        expect(!serviceStopped.0 && !serviceStopped.2 && !service.localVPNWiFiSnapshot.observed, "actual service stop clears owner and companion observation")
        _ = await service.start()
        expect(NWPathMonitor.instances.count == serviceMonitorCount + 2 && !service.localVPNWiFiSnapshot.observed, "actual service restart creates fresh companion without prior true state")
        _ = await service.stop()

        let lateService = Network(Endpoint(), bootstrap: false)
        await fixtureStartPublicationGate.arm()
        let firstServiceStart = Task { await lateService.start() }
        await fixtureStartPublicationGate.waitForEntry()
        _ = await lateService.stop()
        _ = await lateService.start()
        let newerService = await lateService.fixtureState()
        await fixtureStartPublicationGate.release()
        _ = await firstServiceStart.value
        let afterOldPublication = await lateService.fixtureState()
        expect(afterOldPublication.0 && afterOldPublication.2 && afterOldPublication.1 == newerService.1,
               "old service task publication cannot replace newer lifecycle task")
        _ = await lateService.stop()

        let mismatch = Core()
        mismatch.network.isWifiSatisfied = false
        mismatch.decision = .init(transport: .unavailable, reason: "synthetic", unavailableCause: .missingRequiredVPNInterface)
        let noVPN = await mismatch.ownedNetworkReadinessProbe(withNetworkCheck: true)
        expect(noVPN.transient == .vpnInterfacePending && mismatch.fetches == 0, "default non-Wi-Fi plus local Wi-Fi still requires VPN before native")
        mismatch.decision = .init()
        expect(ready(await mismatch.ownedNetworkReadinessProbe(withNetworkCheck: true)) && mismatch.fetches == 0, "Wi-Fi route mismatch admits network checks only")
        mismatch.reachable = false
        expect(await mismatch.ownedNetworkReadinessProbe(withNetworkCheck: true).transient == .peerProbePending && mismatch.fetches == 0, "local Wi-Fi never bypasses peer probe")
        let ordinaryMismatch = Core()
        ordinaryMismatch.network.isWifiSatisfied = false
        if case .success(true) = await ordinaryMismatch.isReady(withNetworkCheck: true, withDDIMountCheck: false) {} else { preconditionFailure("ordinary local readiness incorrectly uses default path") }
        expect(ordinaryMismatch.fetches == 1, "ordinary local Wi-Fi mismatch admits exactly one native readiness call")
        let wifiLostDuringProbe = Core()
        wifiLostDuringProbe.reachable = false
        wifiLostDuringProbe.duringProbe = { wifiLostDuringProbe.network.setLocalWiFi(false) }
        let wifiLost = await wifiLostDuringProbe.ownedNetworkReadinessProbe(withNetworkCheck: true)
        if case .failure(.noConnection) = wifiLost.result {} else { preconditionFailure("false TCP result reused after Wi-Fi loss") }
        expect(wifiLost.transient == nil && wifiLostDuringProbe.fetches == 0, "Wi-Fi loss during probe cannot authorize VPN recovery")
        let monitorStoppedDuringProbe = Core()
        monitorStoppedDuringProbe.reachable = false
        monitorStoppedDuringProbe.duringProbe = { monitorStoppedDuringProbe.network.stopLocalWiFiForFixture() }
        expect(!ready(await monitorStoppedDuringProbe.ownedNetworkReadinessProbe(withNetworkCheck: true)) && monitorStoppedDuringProbe.fetches == 0, "monitor generation loss during probe blocks old result")
        let remote = Core()
        remote.network.isWifiSatisfied = false
        await remote.network.connectionManager.setMode(.remoteServer)
        if case .failure(.noConnection) = await remote.isReady(withNetworkCheck: true, withDDIMountCheck: false) {} else { preconditionFailure("remote default-route guard changed") }
        expect(remote.fetches == 0, "remote mode does not inherit local Wi-Fi admission")
        let remoteEpoch = Core()
        await remoteEpoch.network.connectionManager.setMode(.remoteServer)
        await remoteEpoch.endpoint.setOnRead { remoteEpoch.network.stopLocalWiFiForFixture() }
        expect(ready(await remoteEpoch.ownedNetworkReadinessProbe(withNetworkCheck: true)), "remote readiness ignores companion Wi-Fi generation")
        let cellular = Core()
        cellular.stopWiFiDuringFetch = true
        if case .success(true) = await cellular.isReady(withNetworkCheck: false, withDDIMountCheck: false) {} else { preconditionFailure("explicit network-check bypass changed") }
        expect(cellular.fetches == 1, "explicit cellular network-check bypass remains unchanged")
        let changed = Core()
        changed.mutateConfigDuringFetch = true
        if case .failure(.invalidVPN) = await changed.isReady(withNetworkCheck: true, withDDIMountCheck: false) {} else { preconditionFailure("local configuration changed across native call") }
        expect(changed.fetches == 1, "native configuration change awaited then rejected without replay")
        let stopped = Core()
        stopped.stopWiFiDuringFetch = true
        if case .failure(.invalidVPN) = await stopped.isReady(withNetworkCheck: true, withDDIMountCheck: false) {} else { preconditionFailure("local monitor stopped across native call") }
        expect(stopped.fetches == 1, "native monitor stop awaited then rejected without replay")
        print("LOCAL_VPN_WIFI_OBSERVATION_SOURCE_RUNTIME_PASS no_device_execution=true")
    }
}
