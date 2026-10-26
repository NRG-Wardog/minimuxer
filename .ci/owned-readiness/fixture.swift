import Foundation
func debugLog(_ value:String) {}
func verboseLog(_ value:String) {}
public enum MinimuxerError: Error { case pairingNotLoaded(String),notStarted(String),noConnection(String),noVPN(String),invalidVPN(String),noDevice(String),notReachable(String),muxerNotListening(String) }
enum DeviceConnectionMode: String,Sendable { case localVPN,remoteServer,notConfigured }
enum Pairing { case unknown,lockdown }
enum Transport { case coreDevice,unavailable,lockdown }
enum Cause { case missingRequiredVPNInterface,unsupportedBackend }
struct Decision { var transport:Transport = .coreDevice; var reason="synthetic";var unavailableCause:Cause? }
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
final class Monitor {func cancel(){}}
final class Network: @unchecked Sendable {
// NETWORK_STATE
    private let state=State();private let monitor=Monitor()
    let connectionManager=DeviceConnectionManager();let endpoint:Endpoint;let proxyServer=Proxy();let endpointRefresh=EndpointRefreshTransaction();var publishedConfiguration:DeviceConnectionManager.ConfigurationIdentity?;var publishedLifecycle:UInt64?;var isWifiSatisfied=true
    init(_ endpoint:Endpoint){self.endpoint=endpoint}
// NETWORK
// STOP
    func fixtureStart() async {await state.with {$0.lifecycle &+= 1;$0.started=true}}
}
actor State {enum Status {case started,stopped};var status=Status.started;func with<T>(_ block:(isolated State)->T)->T{block(self)}}
final class Core {
    var isPairingFileLoaded=true;let state=State();let gateway=Gateway();let deviceProvider=Provider();var pairingFileType=Pairing.lockdown;let endpoint=Endpoint();lazy var network=Network(endpoint);let proxyServer=Proxy();var activeProtocol="fixture";var decision=Decision();var reachable=true;var udidFailure=false;var fetches=0;var mutateConfigDuringFetch=false
    func getConnectionMode() async ->DeviceConnectionMode{await network.connectionManager.getPreferredConnectionMode()}
    func configureRefreshTransport() async ->Decision{decision}
    func connectionNotConfiguredError()->MinimuxerError{.noDevice("not configured")}
    func testDeviceConnection(ifaddr:String)->Bool{reachable}
    func fetchUDID() async throws(MinimuxerError)->String {fetches+=1;if mutateConfigDuringFetch{await network.connectionManager.bump()};if udidFailure{throw .noDevice("arbitrary native failure")};return "synthetic"}
    func isDDIMounted() async throws(MinimuxerError)->Bool{true}
// CORE
}
actor Counter {var count=0;func increment(){count+=1}}
actor Latch {var open=false;var waiters:[CheckedContinuation<Void,Never>]=[];func wait() async {if open{return};await withCheckedContinuation{waiters.append($0)}};func release(){open=true;for w in waiters{w.resume()};waiters=[]}}
@main struct Cases {
    static func expect(_ value:Bool,_ name:String){precondition(value,name);print("PASS "+name)}
    static func ready(_ o:MinimuxerOwnedReadinessObservation)->Bool{if case .success(true)=o.result{return true};return false}
    static func main() async {
        let c=Core();expect(ready(await c.ownedNetworkReadinessProbe(withNetworkCheck:true)),"owned ready requires fresh scan");expect(await c.network.connectionManager.refreshCount==1,"one scan")
        let noBatch=Core();noBatch.gateway.hasActiveTransportBatch=false;noBatch.deviceProvider.activeBatches=0;let no=await noBatch.ownedNetworkReadinessProbe(withNetworkCheck:true);expect(!ready(no) && no.transient==nil && noBatch.fetches==0,"no batch cannot initialize")
        let ui=Core();ui.gateway.hasActiveTransportBatch=false;_ = await ui.isReady(withNetworkCheck:true,withDDIMountCheck:false);expect(await ui.network.connectionManager.refreshCount==0 && ui.fetches==0,"UI checks remain noninitializing")
        let wifi=Core();wifi.network.isWifiSatisfied=false;expect(await wifi.ownedNetworkReadinessProbe(withNetworkCheck:true).transient == .wifiPending,"typed wifi guard")
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
