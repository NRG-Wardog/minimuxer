//
//  self.swift
//  Minimuxer
//
//  Created by Magesh K on 4/7/26.
//  Copyright © 2026 SideStore. All rights reserved.
//

import Foundation
import Combine
import ZIPFoundation
internal import DeviceGatewayAPI
internal import MinimuxerCommon

private enum MinimuxerStatus{
    case started, inprogress, stopped
}

final internal class MinimuxerImpl: MinimuxerAPI {
    public let statusSubject = PassthroughSubject<Result<Bool, MinimuxerError>, Never>()
    public var statusPublisher: AnyPublisher<Result<Bool, MinimuxerError>, Never> {
        statusSubject.eraseToAnyPublisher()
    }

    let deviceProvider: DeviceProvider
    var gateway: any DeviceGatewayAPI {
        deviceProvider.gateway
    }
    let network: NetworkObserverService
    let emproxy: any EMProxyAPI
    let wirelessPair: any WirelessPairAPI
    let mounter: Mounter
    let proxyServer: UsbmuxdProxyServer
    let endpoint: DeviceEndpoint
    let connectionManager: DeviceConnectionManager
    let heartbeat: HeartbeatService
    
    var activeProtocol: PairingProtocol {
        gateway.pairingFileType
    }

    init(
        deviceProvider: DeviceProvider,
        network: NetworkObserverService,
        emproxy: any EMProxyAPI,
        wirelessPair: any WirelessPairAPI,
        mounter: Mounter,
        proxyServer: UsbmuxdProxyServer,
        endpoint: DeviceEndpoint,
        connectionManager: DeviceConnectionManager,
        heartbeat: HeartbeatService
    ) {
        self.deviceProvider = deviceProvider
        self.network = network
        self.emproxy = emproxy
        self.wirelessPair = wirelessPair
        self.mounter = mounter
        self.proxyServer = proxyServer
        self.endpoint = endpoint
        self.connectionManager = connectionManager
        self.heartbeat = heartbeat

        self.network.onNetworkChanged = { [weak self] in
            guard let self = self else { return }
            let readyResult = await self.isReady()
            debugLog("[minimuxer] [net] publishing status update to subscribers")
            self.statusSubject.send(readyResult)
        }
    }

    private actor State {
        var status: MinimuxerStatus = .stopped
        var mountTask: Task<Bool, Error>? = nil
        var lastDocsPath: String? = nil
        var preferredProtocol: PairingProtocol? = nil
        
        func with<T>(_ body: (isolated State) throws -> T) rethrows -> T {
            try body(self)
        }
    }
    private let state = State()
    
    var pairingFileType: PairingProtocol { self.gateway.pairingFileType }
    
    var isLoggingEnabled: Bool { MinimuxerLogging.isLoggingEnabled }
    
    var isPairingFileLoaded: Bool {
        return pairingFileType != .unknown
    }


    func describeError(_ error: MinimuxerError) -> String {
        return error.description
    }
    
    func getConnectionMode() async -> DeviceConnectionMode {
        await self.connectionManager.getPreferredConnectionMode()
    }
    
    func bindConnectionConfig(_ binding: ConnectionConfigBinding) async {
        await self.connectionManager.bindConnectionConfig(binding)
        await self.network.refreshEndpoint()
    }
    
    @discardableResult
    private func configureRefreshTransport() async -> RefreshTransportDecision {
        let modernOS: Bool
        if #available(iOS 26.4, *) { modernOS = true } else { modernOS = false }
        let mode = await getConnectionMode()
        // One scanner snapshot for both route predicates and the finite cause.
        // An up addressless utun is intentionally not a usable interface.
        let interfaces = NetworkIfaceScanner.scan(quiet: true)
        let utun = interfaces.contains { $0.name.lowercased().hasPrefix("utun") }
        let ipsec = interfaces.contains { $0.name.lowercased().hasPrefix("ipsec") }
        let pairing = gateway.pairingFileType
        let decision = RefreshTransportPolicy.select(
            modernOS: modernOS, mode: mode, pairing: pairing,
            utun: utun, ipsec: ipsec, coreDeviceSupported: gateway.supportsCoreDeviceTransport)
        gateway.configureCoreDeviceTransport(decision.transport == .coreDevice)
        // Interface presence cannot establish the identity of the App Store VPN.
        debugLog("[SIDESTORE_COREDEVICE] TRANSPORT_SELECTION os_version=\(ProcessInfo.processInfo.operatingSystemVersionString) pairing_mode=\(pairing) localdevvpn_detected=unverified utun_detected=\(utun) ipsec_interface_detected=\(ipsec) selected_transport=\(decision.transport.rawValue) reason=\(decision.reason)")
        return decision
    }

    func beginTransportBatch() async {
        await deviceProvider.beginTransportBatch()
        await configureRefreshTransport()
    }

    func endTransportBatch() async { await deviceProvider.endTransportBatch() }

    func isReady(withNetworkCheck: Bool, withDDIMountCheck: Bool) async -> Result<Bool, MinimuxerError> {
        await readinessObservation(withNetworkCheck: withNetworkCheck, withDDIMountCheck: withDDIMountCheck, owned: false).result
    }

    func ownedNetworkReadinessProbe(withNetworkCheck: Bool) async -> MinimuxerOwnedReadinessObservation {
        guard deviceProvider.hasActiveOwnedBatch, !Task.isCancelled else { return .init(result: .success(false)) }
        let configuration = await network.connectionManager.configurationIdentity()
        let wifiGeneration = network.localVPNWiFiSnapshot.generation
        let result = await readinessObservation(withNetworkCheck: withNetworkCheck, withDDIMountCheck: false, owned: true, configuration: configuration)
        guard deviceProvider.hasActiveOwnedBatch, !Task.isCancelled,
              await network.connectionManager.configurationIdentity() == configuration,
              (!withNetworkCheck || configuration.mode != .localVPN ||
               network.localVPNWiFiSnapshot.generation == wifiGeneration) else {
            return .init(result: .success(false))
        }
        return result
    }

    private func readinessObservation(withNetworkCheck: Bool, withDDIMountCheck: Bool,
                                      owned: Bool, configuration: DeviceConnectionManager.ConfigurationIdentity? = nil) async -> MinimuxerOwnedReadinessObservation {
        if !isPairingFileLoaded {
            debugLog("[minimuxer] minimuxer not ready: pairing file not loaded")
            return .init(result: .failure(.pairingNotLoaded("No valid pairing file has been loaded")))
        }

        let currentStatus = await state.with { $0.status }
        if currentStatus != .started {
            debugLog("[minimuxer] minimuxer not ready: minimuxer has not been started")
            return .init(result: .failure(.notStarted("Minimuxer has not been started")))
        }

        let ownedDecision = owned ? await configureRefreshTransport() : nil
        let ownedMode = owned ? await getConnectionMode() : nil
        let transientAllowed = owned && deviceProvider.hasActiveOwnedBatch &&
            ownedMode == .localVPN && pairingFileType != .unknown &&
            (ownedDecision?.transport != .unavailable || ownedDecision?.unavailableCause == .missingRequiredVPNInterface)

        // Preserve default-route semantics for other modes and public clients.
        // Local VPN uses the same Wi-Fi-specific predicate as host preflight.
        let readinessConfiguration = await network.connectionManager.configurationIdentity()
        let connectionMode = readinessConfiguration.mode
        let localWiFi = network.localVPNWiFiSnapshot
        func localObservationFailure() async -> MinimuxerError? {
            guard withNetworkCheck && connectionMode == .localVPN else { return nil }
            let currentConfiguration = await network.connectionManager.configurationIdentity()
            let currentWiFi = network.localVPNWiFiSnapshot
            guard !Task.isCancelled, currentConfiguration == readinessConfiguration,
                  currentWiFi.generation == localWiFi.generation else {
                return .invalidVPN("Local VPN readiness configuration changed during observation.")
            }
            if withNetworkCheck && !currentWiFi.satisfied {
                return .noConnection("No wifi interface satisfied")
            }
            return nil
        }
        let wifiSatisfied = connectionMode == .localVPN ? localWiFi.satisfied : network.isWifiSatisfied
        if withNetworkCheck && connectionMode == .localVPN && owned {
            network.logReadinessWiFiObservation(localWiFi)
        }
        if withNetworkCheck && !wifiSatisfied {
            debugLog("[minimuxer] minimuxer not ready: no network connection")
            return .init(result: .failure(.noConnection("No wifi interface satisfied")), transient: transientAllowed ? .wifiPending : nil)
        }

        // check connection mode
        let net = self.network

        let decision = await configureRefreshTransport()
        if let failure = await localObservationFailure() { return .init(result: .failure(failure)) }
        if decision.transport == .unavailable {
            // V3_LOCALVPN_INTERFACE_RECOVERY_V1: only the same policy snapshot
            // may produce noVPN. Configuration, pairing and backend failures
            // retain invalidVPN and cannot authorize automatic activation.
            if decision.unavailableCause == .missingRequiredVPNInterface {
                return .init(result: .failure(.noVPN(decision.reason)), transient: transientAllowed ? .vpnInterfacePending : nil)
            }
            return .init(result: .failure(.invalidVPN(decision.reason)))
        }
        if decision.transport == .coreDevice {
            verboseLog("[SIDESTORE_COREDEVICE] LOCALVPN_UTUN_ACCEPTED transport=lockdown-coredevice")
            // Network-change UI checks must not start CoreDevice/signing work.
            if !gateway.hasActiveTransportBatch { return .init(result: .success(false)) }
        }

        // check if pairing file is loaded
        let pairingType = pairingFileType
        if pairingType == .unknown {
            debugLog("[minimuxer] minimuxer not ready: no valid pairing file loaded")
            return .init(result: .failure(.pairingNotLoaded("No valid pairing file has been loaded in Minimuxer")))
        }

        // Only the caller-owned local VPN batch performs a fresh endpoint scan.
        // UI readiness checks keep their existing non-initializing behavior.
        if owned && connectionMode == .localVPN {
            guard deviceProvider.hasActiveOwnedBatch, !Task.isCancelled,
                  await network.refreshEndpointValidated() else { return .init(result: .success(false)) }
            guard deviceProvider.hasActiveOwnedBatch, !Task.isCancelled,
                  await network.connectionManager.configurationIdentity() == configuration else { return .init(result: .success(false)) }
        }

        // then check if device is ready
        let deviceIp: String
        do {
            deviceIp = try await self.endpoint.ip()
        } catch {
            if let failure = await localObservationFailure() { return .init(result: .failure(failure)) }
            switch connectionMode {
                case .localVPN:
                    debugLog("[minimuxer] minimuxer not ready: tunnel peer IP not available despite tunnel iface being present")
                    return .init(result: .failure(.noDevice("VPN tunnel iface is up but tunnel peer IP is not yet reachable — VPN may not be routing device traffic correctly. Cause: \(error.localizedDescription)")), transient: transientAllowed ? .peerAddressPending : nil)
                case .remoteServer:
                    debugLog("[minimuxer] minimuxer not ready: remote endpoint IP is not configured or reachable")
                    return .init(result: .failure(.noDevice("Remote endpoint IP is not configured or reachable. Cause: \(error.localizedDescription)")))
                case .notConfigured:
                    return .init(result: .failure(connectionNotConfiguredError()))
            }
        }
        
        if let failure = await localObservationFailure() { return .init(result: .failure(failure)) }
        let peerReachable = testDeviceConnection(ifaddr: deviceIp)
        if let failure = await localObservationFailure() { return .init(result: .failure(failure)) }
        if !peerReachable {
            switch connectionMode {
                case .localVPN:
                    debugLog("[minimuxer] minimuxer not ready: failed to connect to tunnel peer IP")
                    return .init(result: .failure(.invalidVPN("VPN tunnel iface is up and tunnel peer IP \(deviceIp) is known, but TCP port poll failed — device may be unreachable on this interface")), transient: transientAllowed ? .peerProbePending : nil)
                case .remoteServer:
                    debugLog("[minimuxer] minimuxer not ready: failed to connect to remote endpoint IP \(deviceIp)")
                    return .init(result: .failure(.notReachable("Remote endpoint \(deviceIp) is configured, but TCP port poll failed — target device is unreachable")))
                case .notConfigured:
                    return .init(result: .failure(connectionNotConfiguredError()))
            }
        }

        if let failure = await localObservationFailure() { return .init(result: .failure(failure)) }
        if owned {
            guard deviceProvider.hasActiveOwnedBatch, !Task.isCancelled,
                  await network.connectionManager.configurationIdentity() == configuration else { return .init(result: .success(false)) }
            // Only network prerequisites have passed. The pipeline must call
            // ordinary isReady exactly once after grace, outside its deadline.
            // No UDID, CoreDevice initialization, DDI or signing work is retried.
            return .init(result: .success(true))
        }
        let deviceUDID: String
        do {
            deviceUDID = try await fetchUDID()
        } catch {
            return .init(result: .failure(error))
        }

        // Await native initialization to completion; never detach or replay it
        // if a local observation/configuration changes while it is in flight.
        if let failure = await localObservationFailure() { return .init(result: .failure(failure)) }
        verboseLog(
            "minimuxer status (.\(activeProtocol)): " +
            "deviceUDID_present=\(!deviceUDID.isEmpty) " +
            "started=\(self.proxyServer.isListening) "
        )

        if self.gateway.requiresUsbmuxd && !self.proxyServer.isListening {
            return .init(result: .failure(.muxerNotListening("Usbmuxd fake server is not listening")))
        }

        if withDDIMountCheck {
            do {
                let isMounted = try await isDDIMounted()
                verboseLog("minimuxer status (.\(activeProtocol)): dmg=\(isMounted) started=\(self.proxyServer.isListening)")
                return .init(result: .success(isMounted))
            } catch {
                return .init(result: .failure(error))
            }
        }

        return .init(result: .success(true))
    } 

    private func runWithChecks<T: Sendable>(_ context: String, catchAll: @escaping (String) -> MinimuxerError, action: @escaping @Sendable () async throws -> T) async throws(MinimuxerError) -> T {
        do {
            return try await matchingPriority {
                try await action()
            }
        } catch let err as DeviceGatewayError {
            if context.contains("fetching device UDID") && !err.isVPNDrop {
                if err.code == .invalidPairingFile {
                    throw MinimuxerError.invalidPairing(protocol: activeProtocol, reason: err.reason)
                }
                if err.code == .connectionFailed {
                    if err.reason.lowercased().contains("heartbeat") {
                        throw MinimuxerError.connect(err.reason)
                    }
                    if self.gateway.coreDeviceTransportEnabled || err.reason.contains("CoreDevice") {
                        throw MinimuxerError.createCoreDevice(err.reason)
                    }
                    throw MinimuxerError.noDevice(err.reason)
                }
                if err.code == .serviceError {
                    if err.reason.contains("UniqueDeviceID") {
                        throw MinimuxerError.getLockdownValue(err.reason)
                    }
                    if err.reason.contains("stage=rsd_service") || err.reason.contains("stage=rsdService") || (err.reason.contains("RSD") && err.reason.contains("service")) {
                        throw MinimuxerError.noService(err.reason)
                    }
                    if err.reason.lowercased().contains("lockdown") {
                        throw MinimuxerError.createLockdown(err.reason)
                    }
                    throw MinimuxerError.noService(err.reason)
                }
                if err.code == .notInitialized {
                    throw MinimuxerError.notStarted(err.reason)
                }
                throw MinimuxerError.noDevice(err.reason)
            }
            throw err.asMinimuxerError(protocol: activeProtocol, catchAll: catchAll)
        } catch {
            throw (error as? MinimuxerError) ?? catchAll("\(error)")
        }
    }

    func setLogging(_ enabled: Bool) {
        MinimuxerLogging.setLogging(enabled)
        self.gateway.setLogging(enabled)
    }

    public var deviceProbeTimeout: Int {
        self.connectionManager.deviceProbeTimeout
    }

    func setDeviceProbeTimeout(_ timeoutMs: Int) {
        self.connectionManager.deviceProbeTimeout = timeoutMs
    }
    
    private func retargetUsbmuxdAddr() {
        verboseLog("[minimuxer] unsetenv(USBMUXD_SOCKET_ADDRESS)")
        unsetenv(MinimuxerConstants.usbmuxdEnvKey)
        verboseLog("[minimuxer] setenv(USBMUXD_SOCKET_ADDRESS, \(MinimuxerConstants.usbmuxdSocket))")
        setenv(MinimuxerConstants.usbmuxdEnvKey, MinimuxerConstants.usbmuxdSocket, 1)
        let value = String(cString: getenv(MinimuxerConstants.usbmuxdEnvKey))
        verboseLog("[minimuxer] getenv(USBMUXD_SOCKET_ADDRESS) = \(value)")
    }
    
    private func connectionNotConfiguredError() -> MinimuxerError{
        let modes: [DeviceConnectionMode] = [.localVPN, .remoteServer]
        debugLog("[minimuxer] minimuxer not ready: connection mode not configured. Supported modes: \(modes)")
        return MinimuxerError.connectionModeNotConfigured("Connection mode not configured. Supported modes: \(modes)")
    }
    
    
    private func restartMuxerServer() async throws(MinimuxerError) {
        guard self.gateway.requiresUsbmuxd else { return }
        guard let pairingDict = self.gateway.pairingDataDict else {
            debugLog("[minimuxer] ERROR: Pairing DICT missing...ignoring restart MuxerServer")
            throw MinimuxerError.pairingNotLoaded("Pairing dictionary is missing in gateway")
        }
        verboseLog("[minimuxer] loaded pairing file keys: \(pairingDict.keys)")

        guard let deviceUDID = pairingDict["UDID"] as? String else {
            debugLog("[minimuxer] ERROR: Pairing file missing UDID")
            throw MinimuxerError.invalidPairing(protocol: activeProtocol, reason: "Pairing file is missing UDID value")
        }

        // restart muxer
        await self.proxyServer.stop()
        do {
            try await self.proxyServer.start(udid: deviceUDID)
        } catch {
            throw (error as? MinimuxerError) ?? MinimuxerError.connect("\(error)")
        }
    }
    
    
    
    func start(pairingFile: String, mountPath: String, preferred: PairingProtocol?) async throws(MinimuxerError) {
        let connectionMode = await getConnectionMode()
        if DeviceConnectionMode.notConfigured == connectionMode {
            throw connectionNotConfiguredError()
        }
        await self.network.start()

        // actor serialization scope
        await state.with{
            $0.status = .inprogress     // mark inprogress
            $0.lastDocsPath = mountPath // record the mountPath
            $0.preferredProtocol = preferred
        }
        // let idevice initialize its state
        try await runWithChecks("while starting gateway", catchAll: { .invalidPairing(protocol: self.activeProtocol, reason: $0) }) {
            try await self.gateway.start(pairingFileContent: pairingFile, preferred: preferred)
        }
        await configureRefreshTransport()
        if self.gateway.requiresUsbmuxd {
            // retarget usbmuxd to our fake usbmuxd server (over network)
            retargetUsbmuxdAddr()
            // start our fake usbmuxd server for clients if required
            try await restartMuxerServer()
        }
        
        // mark ready!
        await state.with{
            $0.status = .started
        }
    }

    func stop() async throws(MinimuxerError) {
        // actor serialization scope
        let oldTask = await state.with { state -> Task<Bool, Error>? in
            state.status = .inprogress  // mark inprogress
            let task = state.mountTask
            task?.cancel()              // cancel the task
            state.mountTask = nil
            return task
        }
        _ = await oldTask?.result       // await cancelled mount task completion
        if self.gateway.requiresUsbmuxd {
            await self.proxyServer.stop()
        }
        try await runWithChecks("while stopping gateway", catchAll: MinimuxerError.close) {
            try await self.gateway.stop()
        }
        // mark ready!
        await state.with {
            $0.status = .stopped
        }
    }
    
    private func restartWith(pairingFile: String, op: String) async throws(MinimuxerError) {
        let (mountPath, preferred) = await state.with { ($0.lastDocsPath, $0.preferredProtocol) }
        guard let mountPath else {
            let activeProtocol = self.gateway.pairingFileType
            throw MinimuxerError.mount(protocol: activeProtocol, reason: "start() should be invoked before requesting \(op). cause: lastDocsPath is nil")
        }
        try await stop()
        try await start(pairingFile: pairingFile, mountPath: mountPath, preferred: preferred)
    }

    func restart() async throws(MinimuxerError) {
        verboseLog("[minimuxer] Restarting services...")
        let activeProtocol = self.gateway.pairingFileType
        guard let pairingData = self.gateway.pairingFileData,
              let pairingFile = String(data: pairingData, encoding: .utf8) else
        {
            debugLog("[minimuxer] restart: no existing pairing file — cannot restart")
            throw MinimuxerError.invalidPairing(protocol: activeProtocol, reason: "No existing pairing file found in gateway during restart")
        }
        try await restartWith(pairingFile: pairingFile, op: "restart")
        await self.network.refreshEndpoint()
    }

    func reinitializePairingData(pairingFile: String) async throws(MinimuxerError) {
        verboseLog("[minimuxer] Reinitializing with new pairing file...")
        try await restartWith(pairingFile: pairingFile, op: "reinitializePairingData")
    }
  
    func testDeviceConnection(ifaddr: String, timeout: Int) -> Bool {
        return NetworkUtils.testTCP(ip: ifaddr, port: self.gateway.servicePort, timeoutMs: timeout)
    }

    private func ensureDDIMounted() async throws(MinimuxerError) {
        let isMounted = (try? await self.gateway.isDDIMounted()) ?? false
        if isMounted {
            return
        }
        guard let mountPath = await state.lastDocsPath else
        {
            let activeProtocol = self.gateway.pairingFileType
            throw MinimuxerError.mount(protocol: activeProtocol, reason: "DDI mount path not set")
        }
        verboseLog("[minimuxer] DDI not mounted, mounting now before launching debug session...")
        try await self.mountDDI(docsPath: mountPath)
    }

    
    @discardableResult
    func mountDDI(docsPath: String) async throws(MinimuxerError) -> Bool {
        try await runWithChecks("while mounting DDI", catchAll: { .mount(protocol: self.activeProtocol, reason: $0) }) {
            let oldTask = await self.state.with { state -> Task<Bool, Error>? in
                state.lastDocsPath = docsPath
                let task = state.mountTask
                task?.cancel()
                state.mountTask = nil
                return task
            }
            _ = await oldTask?.result
            let mounter = self.mounter
            let task = Task.detached(priority: .medium) {
                try await mounter.mount(docsPath: docsPath)
            }
            await self.state.with {
                $0.mountTask = task
            }
            return try await task.value
        }
    }

    func isDDIMounted() async throws(MinimuxerError) -> Bool {
        try await runWithChecks("while checking DDI mount status", catchAll: { .mount(protocol: self.activeProtocol, reason: $0) }) {
            try await self.gateway.isDDIMounted()
        }
    }

    func fetchUDID() async throws(MinimuxerError) -> String {
        try await runWithChecks("while fetching device UDID", catchAll: MinimuxerError.fetchUDID) {
            try await self.gateway.fetchUDID()
        }
    }

    func sendIpaAfc(bundleId: String, ipaBytes: Data) async throws(MinimuxerError) {
        try await runWithChecks("while sending IPA via AFC", catchAll: MinimuxerError.rwAfc) {
            try await self.gateway.sendIpaAfc(bundleId: bundleId, ipaBytes: ipaBytes)
        }
    }

    func sendAppBundleAfc(bundleId: String, appURL: URL) async throws(MinimuxerError) {
        try await runWithChecks("while sending App Bundle via AFC", catchAll: MinimuxerError.rwAfc) {
            try await self.gateway.sendAppBundleAfc(bundleId: bundleId, appURL: appURL)
        }
    }

    func installIpa(bundleId: String) async throws(MinimuxerError) {
        try await runWithChecks("while installing IPA", catchAll: MinimuxerError.installApp) {
            try await self.gateway.installIpa(bundleId: bundleId)
        }
    }

    func installAppBundle(bundleId: String, appName: String) async throws(MinimuxerError) {
        try await runWithChecks("while installing App Bundle", catchAll: MinimuxerError.installApp) {
            try await self.gateway.installAppBundle(bundleId: bundleId, appName: appName)
        }
    }

    func removeApp(bundleId: String) async throws(MinimuxerError) {
        try await runWithChecks("while removing App", catchAll: MinimuxerError.uninstallApp) {
            try await self.gateway.removeApp(bundleId: bundleId)
        }
    }

    func wipeContainer(identifier: String) async throws(MinimuxerError) {
        try await runWithChecks("while wiping container", catchAll: MinimuxerError.uninstallApp) {
            try await self.gateway.wipeContainer(identifier: identifier)
        }
    }

    func debugApp(appId: String) async throws(MinimuxerError) {
        try await runWithChecks("while debugging App", catchAll: MinimuxerError.createDebug) {
            try await self.ensureDDIMounted()
            try await self.gateway.debugApp(appId: appId)
        }
    }

    func attachDebugger(pid: UInt32) async throws(MinimuxerError) {
        try await runWithChecks("while debugging process", catchAll: MinimuxerError.createDebug) {
            try await self.ensureDDIMounted()
            try await self.gateway.debugProcess(pid: pid)
        }
    }

    func installProvisioningProfile(profile: Data) async throws(MinimuxerError) {
        try await runWithChecks("while installing profile", catchAll: MinimuxerError.profileInstall) {
            try await self.gateway.installProvisioningProfile(profile: profile)
        }
    }

    func removeProvisioningProfile(id: String) async throws(MinimuxerError) {
        try await runWithChecks("while removing profile", catchAll: MinimuxerError.profileRemove) {
            try await self.gateway.removeProvisioningProfile(id: id)
        }
    }

    // Read-only post-install observation. Capture the gateway before suspension;
    // the caller retains its existing transport batch until this returns.
    func readInstalledProvisioningProfiles() async throws(MinimuxerError) -> [Data] {
        let capturedGateway = gateway
        return try await runWithChecks("while reading installed profiles", catchAll: MinimuxerError.createMisagent) {
            try Task.checkCancellation()
            let profiles = try await capturedGateway.readInstalledProvisioningProfiles()
            try Task.checkCancellation()
            return profiles
        }
    }

    func dumpProfiles(docsPath: String, mode: ProfileDumpMode = .zip) async throws(MinimuxerError) -> String {
        try await runWithChecks("while dumping profiles", catchAll: MinimuxerError.createMisagent) {
            switch mode {
                case .raw:
                    verboseLog("[minimuxer] dumpProfiles(mode: .raw) dumping profiles")
                    return try await self.gateway.dumpProfiles(docsPath: docsPath)
                case .zip:
                    verboseLog("[minimuxer] dumpProfiles(mode: .zip) staging to temporary directory")
                    let tempDir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
                    defer {
                        verboseLog("[minimuxer] dumpProfiles(mode: .zip) cleaning up temporary directory")
                        try? FileManager.default.removeItem(at: tempDir)
                    }

                    let dumpedPath = try await self.gateway.dumpProfiles(docsPath: tempDir.path)
                    let zipURL = URL(fileURLWithPath: docsPath).appendingPathComponent("Profiles-\(ISO8601DateFormatter().string(from: Date())).zip")
                    verboseLog("[minimuxer] dumpProfiles(mode: .zip) compressing profiles")
                    try FileManager.default.zipItem(at: URL(fileURLWithPath: dumpedPath), to: zipURL, shouldKeepParent: false)
                    verboseLog("[minimuxer] dumpProfiles(mode: .zip) archive created")
                    return zipURL.path
            }
        }
    }

    func afcListDirectory(bundleId: String, path: String) async throws(MinimuxerError) -> [String] {
        try await runWithChecks("while listing AFC directory", catchAll: MinimuxerError.createAfc) {
            try await self.gateway.afcListDirectory(bundleId: bundleId, path: path)
        }
    }

    func afcReadFile(bundleId: String, path: String) async throws(MinimuxerError) -> Data {
        try await runWithChecks("while reading AFC file", catchAll: MinimuxerError.rwAfc) {
            try await self.gateway.afcReadFile(bundleId: bundleId, path: path)
        }
    }

    func afcGetFileInfo(bundleId: String, path: String) async throws(MinimuxerError) -> (isDirectory: Bool, fileSize: Int64) {
        try await runWithChecks("while getting AFC file info", catchAll: MinimuxerError.createAfc) {
            try await self.gateway.afcGetFileInfo(bundleId: bundleId, path: path)
        }
    }
}
