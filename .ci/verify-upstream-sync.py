"""Check source invariants; optionally compile only source-owned Swift fake tests.

This is not an iOS build, native backend test, or on-device authentication proof.
Usage: python3 .ci/verify-upstream-sync.py [--swiftc /verified/path/to/swiftc]
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
def require(condition, message):
    if not condition:
        raise ValueError(message)
def read(path):
    return (ROOT / path).read_text()
def section(text, start, stop):
    return text[text.index(start):text.index(stop, text.index(start))]

def strip_dependency_imports(text):
    return re.sub(r'^(?:(?:public|internal) )?import (?:MinimuxerCommon|DeviceGatewayAPI)\n', '', text, flags=re.M)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--swiftc')
    args = parser.parse_args()
    for file in ROOT.rglob('*.swift'):
        require(re.search(r'^(<<<<<<<|=======|>>>>>>>)', file.read_text(), re.M) is None, f'Conflict markers: {file}')
    package = read('DeviceGateway/Package.swift')
    idevice = section(package, 'name: "IDevice"', '//        .binaryTarget')
    require('path: "LocalBinary/IDevice.xcframework"' in idevice and 'url:' not in idevice, 'Native provenance path changed')
    ffi = read('DeviceGateway/idevice/IdeviceGateway.swift')
    require('withFFIDispatch {' not in ffi, 'Native dispatch escaped the serialized queue')
    require('let upperBoundLevel = IdeviceLogLevel(rawValue: enabled ? 1 : 0)' in ffi and 'IdeviceLogLevel(rawValue: 5)' not in ffi, 'Native trace verbosity would expose additional payload diagnostics')
    wrappers = ffi[ffi.index('// Async FFI Dispatcher Extensions'):]
    require(wrappers.count('withFFIDispatch(on: self.ffiQueue)') == wrappers.count('defer { if self.batchCount == 0 { self.releaseTransport() } }'), 'Operation release scopes drifted')
    for function in ['tunnel_create_usb', 'tunnel_heartbeat_is_active', 'lockdownd_connect_rsd', 'idevice_plist_array_free', 'idevice_set_transport_log_callback', 'pairable_host_prepare', 'pairable_host_accept_fd', 'pairable_host_free', 'rppairing_peer_device_free', 'tunnel_create_rppairing_with_options']:
        require(function + '(' in ffi, f'Required native function missing: {function}')
    require('self.pairingFileType == .lockdown && !self.usesCoreDevice' in ffi, 'RSD must not start a second ordinary Lockdown session')
    live_udid = section(ffi, '    private func syncFetchUDID()', '    private func syncGetLockdownValue(')
    require('idevice_usbmuxd_device_get_udid' not in live_udid, 'UDID was substituted from fake usbmuxd metadata')
    require('getRustPlistString(plistVal), !udid.isEmpty' in live_udid and 'lockdownd_get_value(client, "UniqueDeviceID"' in live_udid, 'CoreDevice live UDID proof missing')
    require('stagedBundleIdentities' in ffi and 'signedIdentifier' in ffi, 'Signed bundle identity protection missing')
    core = read('Sources/MinimuxerImpl.swift')
    require('if !gateway.hasActiveTransportBatch { return .init(result: .success(false)) }' in core, 'Background readiness could trigger CoreDevice')
    require('await deviceProvider.beginTransportBatch()' in core and 'await deviceProvider.endTransportBatch()' in core, 'Gateway batch pairing bypassed provider')
    require('deviceUDID=\\(' not in core, 'Readiness exposes device identity')
    configure = section(core, '    private func configureRefreshTransport()', '    func beginTransportBatch()')
    require(configure.count('NetworkIfaceScanner.scan(quiet: true)') == 1 and 'network.isUTunAvailable' not in configure and 'network.isIKEv2IPSecAvailable' not in configure, 'Transport cause must use one interface snapshot')
    require('pairing: pairing' in configure and 'let pairing = gateway.pairingFileType' in configure, 'Pairing observation was not captured with transport decision')
    readiness = section(core, '    func isReady(withNetworkCheck:', '    private func runWithChecks')
    unavailable = section(readiness, '        if decision.transport == .unavailable {', '        if decision.transport == .coreDevice {')
    require('if decision.unavailableCause == .missingRequiredVPNInterface {' in unavailable and 'return .init(result: .failure(.noVPN(decision.reason)), transient: transientAllowed ? .vpnInterfacePending : nil)' in unavailable, 'Typed local interface cause was not preserved as noVPN')
    require('return .init(result: .failure(.invalidVPN(decision.reason)))' in unavailable and unavailable.count('.noVPN(') == 1, 'Other unavailable cases lost existing invalidVPN family')
    require('getConnectionMode' not in unavailable and 'NetworkIfaceScanner' not in unavailable, 'Readiness error classification resampled mutable state')

    require('if gateway.coreDeviceTransportEnabled { return }' in read('Sources/Services/HeartbeatService.swift'), 'Background CoreDevice heartbeat restored')
    require('overrideReachable ? overrideIp : (derivedReachable ? derivedIp : nil)' in read('Sources/Services/NetworkObserverService.swift'), 'Reachable endpoint fallback lost')
    api = read('DeviceGateway/DeviceGatewayAPI.swift')
    require('func fetchUDID() async throws -> String\n' in api and 'func getLockdownValue(key: String) async throws -> String\n' in api, 'Nonoptional upstream API missing')
    facade = read('Sources/MinimuxerApi.swift')
    production_set = section(facade, '    @discardableResult\n    public func set(', '    private static func makeGateway(')
    require('let newBackend = params.backend ?? Self.currentBackend' in production_set and 'let newPort = params.remotePairingPort ?? Self.currentRemotePairingPort' in production_set, 'Partial configuration was not resolved before applying')
    require(production_set.count('self.deviceProvider.setConfiguration(gateway: replacement, remotePairingPort: newPort)') == 1 and '.setPort(' not in production_set and '.setGateway(' not in production_set, 'Configuration bypasses atomic provider boundary')
    provider = read('Sources/DeviceProvider.swift')
    require('internal import MinimuxerCommon\n' in provider, 'Internal helper dependency import must have explicit visibility')
    require('public import MinimuxerCommon\n' in facade and 'public import DeviceGatewayAPI\n' in facade, 'Public facade dependency visibility changed')
    for access in ['', 'public ', 'internal ']:
        for module in ['MinimuxerCommon', 'DeviceGatewayAPI']:
            require(strip_dependency_imports(access + 'import ' + module + '\n') == '', 'Fake harness retained a real dependency import')
    require(strip_dependency_imports('import Foundation\n') == 'import Foundation\n', 'Fake harness strips unrelated imports')
    require('newGateway ?? pendingConfiguration?.gateway ?? cachedGateway' in provider, 'Port-only updates ignore pending backend')
    require('guard activeBatches == 0, let pendingConfiguration else { return }' in provider, 'Port can mutate an active lease')
    require(provider.count('.setPort(') == 1 and 'guard activeBatches > endingBatches else { return nil }' in provider, 'Unpaired end or port mutation bypasses lease accounting')
    report = {'status': 'static_source_invariants_pass', 'native_or_device_execution': False, 'swift_smoke': 'not_run_no_compiler_requested'}
    if args.swiftc:
        prelude = '''import Foundation
public enum MinimuxerConstants { public static let remotePairingPort: UInt16 = 49151; public static let lockdowndPort: UInt16 = 62078 }
public enum DeviceConnectionMode: String, Codable, Sendable { case localVPN, remoteServer, notConfigured }
public protocol DeviceGatewayAPI: AnyObject, Sendable { func beginTransportBatch() async; func endTransportBatch() async; func setPort(_ port: UInt16, for protocolType: PairingProtocol) }
public protocol MinimuxerFacade: AnyObject, Sendable {}
'''
        paths = ['Common/PairingProtocol.swift', 'Common/ConcurrencyUtils.swift', 'Common/PairingFile.swift', 'Sources/RefreshTransportPolicy.swift', 'Sources/DeviceProvider.swift', '.ci/upstream-sync-smoke.swift']
        prelude += section(facade, 'public struct MinimuxerParams:', 'public protocol MinimuxerFacade:')
        prelude += section(facade, 'public enum GatewayBackend:', 'public final class Minimuxer:')
        text = prelude + '\n'.join(strip_dependency_imports(read(path)) for path in paths)
        require(text.count('// PRODUCTION_SET_METHOD') == 1, 'Missing exact production set injection point')
        text = text.replace('// PRODUCTION_SET_METHOD', production_set)
        with tempfile.TemporaryDirectory(prefix='minimuxer-source-smoke-') as tmp:
            source = Path(tmp) / 'smoke.swift'
            binary = Path(tmp) / 'smoke'
            source.write_text(text)
            subprocess.run([args.swiftc, '-parse-as-library', str(source), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True)
        report['swift_smoke'] = 'source_owned_fake_tests_pass'
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
