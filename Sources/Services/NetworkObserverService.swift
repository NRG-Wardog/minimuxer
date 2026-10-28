//
//  NetworkObserverService.swift
//  Minimuxer
//
//  Created by Magesh K on 02/03/26.
//

import Network
import Foundation
import Combine

// V3_LOCAL_VPN_WIFI_OBSERVATION_BEGIN
// Local VPN admission asks whether a Wi-Fi-specific path is available, not
// whether the default route currently uses Wi-Fi. No callback starts transport.
final class LocalVPNWiFiObservation: @unchecked Sendable {
    struct Snapshot {
        let generation: UInt64
        let observed: Bool
        let status: String
        let usesWiFi: Bool
        var satisfied: Bool { observed && status == "satisfied" && usesWiFi }
    }
    private let lock = NSRecursiveLock()
    private let queue = DispatchQueue(label: "net.local-vpn-wifi")
    private var monitor: NWPathMonitor?
    private var generation: UInt64 = 0
    private var received = false

    static func statusName(_ status: NWPath.Status) -> String {
        switch status {
        case .satisfied: return "satisfied"
        case .unsatisfied: return "unsatisfied"
        case .requiresConnection: return "requiresConnection"
        @unknown default: return "unknown"
        }
    }

    func start() {
        lock.lock()
        defer { lock.unlock() }
        guard monitor == nil else { return }
        generation &+= 1
        received = false
        let token = generation
        let next = NWPathMonitor(requiredInterfaceType: .wifi)
        monitor = next
        next.pathUpdateHandler = { [weak self] _ in self?.receivedUpdate(generation: token) }
        // Network.framework delivers callbacks on queue, never inline here.
        next.start(queue: queue)
    }

    private func receivedUpdate(generation token: UInt64) {
        lock.lock()
        defer { lock.unlock() }
        guard monitor != nil, generation == token else { return }
        received = true
    }

    func stop() {
        lock.lock()
        defer { lock.unlock() }
        generation &+= 1
        received = false
        let previous = monitor
        monitor = nil
        previous?.pathUpdateHandler = nil
        previous?.cancel()
    }

    func snapshot() -> Snapshot {
        lock.lock()
        defer { lock.unlock() }
        guard let monitor, received else {
            return Snapshot(generation: generation, observed: false, status: "unknown", usesWiFi: false)
        }
        // Never retain a prior true observation after the monitored path changes.
        let path = monitor.currentPath
        return Snapshot(generation: generation, observed: true,
                        status: Self.statusName(path.status), usesWiFi: path.usesInterfaceType(.wifi))
    }

    deinit { stop() }
}
// V3_LOCAL_VPN_WIFI_OBSERVATION_END

final internal class NetworkObserverService: NetworkObserverAPI, @unchecked Sendable {

    var onNetworkChanged: (() async -> Void)?

    public let pathSubject = PassthroughSubject<NWPath, Never>()
    public var pathPublisher: AnyPublisher<NWPath, Never> {
        pathSubject.eraseToAnyPublisher()
    }

    let connectionManager: DeviceConnectionManager
    let endpoint: DeviceEndpoint
    let proxyServer: UsbmuxdProxyServer

    private let monitor = NWPathMonitor()
    private let localVPNWiFi = LocalVPNWiFiObservation()
    private let queue = DispatchQueue(label: "net.monitor")
    private let state = State()
    private let endpointRefresh = EndpointRefreshTransaction()
    private var publishedConfiguration: DeviceConnectionManager.ConfigurationIdentity?
    private var publishedLifecycle: UInt64?

    init(
        connectionManager: DeviceConnectionManager,
        endpoint: DeviceEndpoint,
        proxyServer: UsbmuxdProxyServer
    ) {
        self.connectionManager = connectionManager
        self.endpoint = endpoint
        self.proxyServer = proxyServer
    }
    
    private actor State {
        var started = false
        var lifecycle: UInt64 = 0
        var observationTask: Task<Void, Never>? = nil
        
        func with<T>(_ body: (isolated State) throws -> T) rethrows -> T {
            try body(self)
        }
    }

    @discardableResult
    func start() async -> Bool {
        let admittedLifecycle = await state.with { value -> UInt64? in
            guard !value.started else { return nil }
            value.lifecycle &+= 1
            value.started = true
            localVPNWiFi.start()
            return value.lifecycle
        }
        guard let admittedLifecycle else {
            verboseLog("[minimuxer] [net] monitor already started")
            return false
        }

        verboseLog("[minimuxer] [net] monitor started")

        let paths = AsyncStream<NWPath> { [weak self] continuation in
            guard let self = self else {
                continuation.finish()
                return
            }
            self.monitor.pathUpdateHandler = { path in
                self.pathSubject.send(path)
                continuation.yield(path)
            }
        }

        self.monitor.start(queue: self.queue)

        let task = Task.detached { [weak self] in
            for await path in paths {
                verboseLog("[minimuxer] [net] path changed, status: \(path.status)")
                await self?.handleNetworkChange()
            }
        }
        await state.with { value in
            guard value.started, value.lifecycle == admittedLifecycle else { task.cancel(); return }
            value.observationTask = task
        }

        return true
    }
    
    private func handleNetworkChange() async {
        await refreshEndpoint()
        
        // Always re-evaluate and publish network change events as is
        debugLog("[minimuxer] [net] dispatching status update to subscribers")
        await onNetworkChanged?()
    }
    
    func refreshEndpoint() async {
        _ = await refreshEndpointValidated()
    }

    func refreshEndpointValidated() async -> Bool {
        await endpointRefresh.run { [self] in await refreshEndpointTransaction() }
    }

    private func refreshEndpointTransaction() async -> Bool {
        let lifecycle = await state.with { $0.lifecycle }
        let manager = self.connectionManager
        verboseLog("[minimuxer] [net] refreshing interfaces list and peers")
        let configuration = await manager.configurationIdentity()
        let ifacesChanged = await manager.refresh()
        guard await manager.configurationIdentity() == configuration,
              await state.with({ $0.lifecycle }) == lifecycle else { return false }
        
        if !ifacesChanged && publishedConfiguration == configuration && publishedLifecycle == lifecycle { return true }
        
        let connectionMode = await manager.getPreferredConnectionMode()
        switch connectionMode {
            case .notConfigured:
                debugLog("[minimuxer] [net] connection mode not configured. skipping endpoint update...")
                return true
                
            case .localVPN:
                verboseLog("[minimuxer] [net] retrive the first uTun vpn interface info")
                if let info = await manager.vpnIface {
                    verboseLog("""
                    [minimuxer] [net] vpn interface detected
                      • name: \(info.name)
                      • addresses: \(info.interfaceAddresses.description)
                      • linkType: \(info.linkType)
                      • linkLayerDestinationIP: \(info.linkLayerDestinationIP?.description ?? "nil")
                      • destinationIPs: [\(info.destinationIPs.map { $0.description }.joined(separator: ", "))]
                      • destinationGatewayIPs: [\(info.destinationGatewayIPs.map { $0.description }.joined(separator: ", "))]
                    
                    """)

                    let overrideIp = await manager.overridePeerIp
                    let overrideReachable = await manager.isOverridePeerIpReachable
                    let derivedIp = await manager.derivedPeerIp
                    let derivedReachable = await manager.isDerivedPeerIpReachable
                    let effectiveIp = overrideReachable ? overrideIp : (derivedReachable ? derivedIp : nil)
                    let effectivePeer = overrideReachable ? "overridePeer" : "derivedPeerIp"
                    debugLog("[SIDESTORE_COREDEVICE] ENDPOINT_SELECT selected_source=\(effectivePeer) reachable=\(effectiveIp != nil)")

                    if let peer = effectiveIp {
                        verboseLog("[minimuxer] [net] update device IP with effective tunnel peer: '\(effectivePeer)'")
                        guard await publishEndpoint(peer, configuration: configuration, lifecycle: lifecycle) else { return false }
                    } else {
                        verboseLog("[minimuxer] [net] peer not available for \(info.name)")
                        guard await publishEndpoint(nil, configuration: configuration, lifecycle: lifecycle) else { return false }
                    }

                } else {
                    verboseLog("[minimuxer] [net] no local VPN interface detected")
                    guard await publishEndpoint(nil, configuration: configuration, lifecycle: lifecycle) else { return false }
                }
            
            case .remoteServer:
                let isReachable = await manager.isRemoteServerIpReachable
                if let remoteIp = await manager.remoteServerIp {
                    verboseLog("""
                    [minimuxer] [net] remote server endpoint detected \(isReachable ? "and reachable" : "but unreachable")
                      • remoteServerIp: \(remoteIp)
                    
                    """)
                    if isReachable {
                        guard await publishEndpoint(remoteIp, configuration: configuration, lifecycle: lifecycle) else { return false }
                    } else {
                        guard await publishEndpoint(nil, configuration: configuration, lifecycle: lifecycle) else { return false }
                    }
                } else {
                    verboseLog("[minimuxer] [net] remote server endpoint unreachable")
                    guard await publishEndpoint(nil, configuration: configuration, lifecycle: lifecycle) else { return false }
                }
            }
        guard await manager.configurationIdentity() == configuration,
              await state.with({ $0.lifecycle }) == lifecycle else { return false }
        publishedConfiguration = configuration
        publishedLifecycle = lifecycle
        return true
    }
    
    private func publishEndpoint(_ peer: String?, configuration: DeviceConnectionManager.ConfigurationIdentity, lifecycle: UInt64) async -> Bool {
        guard await connectionManager.configurationIdentity() == configuration,
              await state.with({ $0.lifecycle }) == lifecycle else { return false }
        if let peer { await endpoint.update(peer) } else { await endpoint.clear() }
        guard await connectionManager.configurationIdentity() == configuration,
              await state.with({ $0.lifecycle }) == lifecycle else {
            await endpoint.clear()
            proxyServer.notifyDeviceDetached()
            return false
        }
        // Serialize the final synchronous notification against stop's epoch bump.
        let published = await state.with { value in
            guard value.lifecycle == lifecycle else { return false }
            if let peer { self.proxyServer.notifyDeviceAttached(tunnelPeerIp: peer) }
            else { self.proxyServer.notifyDeviceDetached() }
            return true
        }
        if !published { await endpoint.clear() }
        return published
    }

    @discardableResult
    func stop() async -> Bool {
        let stopped = await state.with { value -> (Bool, Task<Void, Never>?) in
            value.lifecycle &+= 1 // Invalidate in-flight publication, not its other waiters.
            localVPNWiFi.stop()
            let wasStarted = value.started
            value.started = false
            let task = value.observationTask
            value.observationTask = nil
            return (wasStarted, task)
        }
        guard stopped.0 else {
            verboseLog("[minimuxer] [net] monitor already stopped")
            return false
        }

        self.monitor.cancel()
        stopped.1?.cancel()
        
        verboseLog("[minimuxer] [net] monitor stopped")
        return true
    }
    
    var localVPNWiFiSnapshot: LocalVPNWiFiObservation.Snapshot { localVPNWiFi.snapshot() }

    func logReadinessWiFiObservation(_ local: LocalVPNWiFiObservation.Snapshot) {
        let path = monitor.currentPath
        debugLog("[V3_WIFI_READINESS] default_status=\(LocalVPNWiFiObservation.statusName(path.status)) default_wifi=\(path.usesInterfaceType(.wifi)) local_status=\(local.status) local_wifi=\(local.usesWiFi) local_observed=\(local.observed)")
    }

    var isWifiSatisfied: Bool {
        let path = monitor.currentPath
        return path.status == .satisfied && path.usesInterfaceType(.wifi)
    }
    
    var isWiredSatisfied: Bool {
        let path = monitor.currentPath
        return path.status == .satisfied && path.usesInterfaceType(.wiredEthernet)
    }
    
    var isUsbSatisfied: Bool {
        return NetworkIfaceScanner.scan(quiet: true).contains { info in
            let name = info.name.lowercased()
            return name.hasPrefix("en") && name != "en0" && (info.interfaceAddresses.v4.first?.host.hasPrefix("169.254.") == true)
        }
    }
    
    var isBridgeSatisfied: Bool {
        let path = monitor.currentPath
        if path.status == .satisfied && path.usesInterfaceType(.other) {
            return true
        }
        
        return NetworkIfaceScanner.scan(quiet: true).contains { info in
            info.name.lowercased().contains("bridge") ||
            info.name.lowercased().contains("ap")
        }
    }

    // True when at least one `utun*` interface is active (userspace VPN — ex: wireguard).
    var isUTunAvailable: Bool {
        return NetworkIfaceScanner.scan(quiet: true).contains { $0.name.lowercased().hasPrefix("utun") }
    }

    // True when at least one `ipsec*` interface is active (IKEv2/IPSec kernel VPN).
    var isIKEv2IPSecAvailable: Bool {
        return NetworkIfaceScanner.scan(quiet: true).contains { $0.name.lowercased().hasPrefix("ipsec") }
    }

    var activeInterfaces: [LocalInterfaceInfo] {
        return NetworkIfaceScanner.scan(quiet: true).map { info in
            let isLinkLocal = info.interfaceAddresses.v4.first?.host.hasPrefix("169.254.") == true
            let type = LocalInterfaceType(name: info.name, isLinkLocal: isLinkLocal)
            let v4 = info.interfaceAddresses.v4.first
            let v6 = info.interfaceAddresses.v6.first
            
            return LocalInterfaceInfo(
                name: info.name,
                ip: v4?.host ?? (v6 ?? ""),
                ipv6: v6,
                subnet: v4?.mask ?? "",
                type: type
            )
        }.sorted {
            if $0.type != $1.type {
                return $0.type < $1.type
            }
            return $0.name.lowercased().localizedCompare($1.name.lowercased()) == .orderedAscending
        }
    }
}
