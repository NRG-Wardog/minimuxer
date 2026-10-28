"""Source-owned cold VPN controls. Executes extracted production, not native/device networking."""
import hashlib,json,os,platform,shutil,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def section(text,start,end):
    assert text.count(start)==1
    return text.split(start,1)[1].split(end,1)[0]
JOIN_ANCHOR = 'if let running { return await running.1.value }'
JOIN_INSTRUMENTED = 'if let running { fixtureJoinSignal.signal(); return await running.1.value }'
def observe_join(source):
    # Fixture-only synchronous notification after the actual existing-task capture.
    # No production declarations, decisions, await points or returns are replaced.
    assert source.count(JOIN_ANCHOR) == 1 and JOIN_INSTRUMENTED not in source
    instrumented = source.replace(JOIN_ANCHOR, JOIN_INSTRUMENTED, 1)
    assert instrumented.count(JOIN_INSTRUMENTED) == 1
    assert instrumented.replace(JOIN_INSTRUMENTED, JOIN_ANCHOR, 1) == source
    return instrumented

START_PUBLICATION_ANCHOR = '        await state.with { value in\n            guard value.started, value.lifecycle == admittedLifecycle'
START_PUBLICATION_HOOK = '        await fixtureStartPublicationGate.pauseIfArmed()\n'
def observe_start_publication(source):
    # One scheduling-only fixture await immediately before an existing actor await.
    # The actual lifecycle comparison, cancellation and task assignment are intact.
    assert source.count(START_PUBLICATION_ANCHOR) == 1
    assert START_PUBLICATION_HOOK not in source
    transformed = source.replace(START_PUBLICATION_ANCHOR, START_PUBLICATION_HOOK + START_PUBLICATION_ANCHOR, 1)
    assert transformed.replace(START_PUBLICATION_HOOK, '', 1) == source
    return transformed

def generate():
    api=(ROOT/'Sources/MinimuxerApi.swift').read_text()
    core=(ROOT/'Sources/MinimuxerImpl.swift').read_text()
    net=(ROOT/'Sources/Services/NetworkObserverService.swift').read_text()
    actor=observe_join((ROOT/'Sources/Services/EndpointRefreshTransaction.swift').read_text())
    wifi=section(net,'// V3_LOCAL_VPN_WIFI_OBSERVATION_BEGIN','// V3_LOCAL_VPN_WIFI_OBSERVATION_END')
    wifi_accessors='    var localVPNWiFiSnapshot:'+section(net,'    var localVPNWiFiSnapshot:','    var isWifiSatisfied:')
    types=section(api,'// V3_OWNED_READINESS_TYPES_BEGIN','// V3_OWNED_READINESS_TYPES_END')
    methods='    func isReady(withNetworkCheck:'+section(core,'    func isReady(withNetworkCheck:','    private func runWithChecks')
    transaction='    func refreshEndpoint()'+section(net,'    func refreshEndpoint()','    @discardableResult\n    func stop()')
    manager=(ROOT/'Sources/Services/DeviceConnectionManager.swift').read_text()
    identity=section(manager,'actor DeviceConnectionManager {','    let deviceProvider: DeviceProvider')
    provider=(ROOT/'Sources/DeviceProvider.swift').read_text()
    ownership='    var hasActiveOwnedBatch: Bool {'+section(provider,'    var hasActiveOwnedBatch: Bool {','    func beginTransportBatch()')
    network_state='    private actor State {'+section(net,'    private actor State {','    @discardableResult\n    func start()')
    start='    @discardableResult\n    func start()'+section(net,'    @discardableResult\n    func start()','    private func handleNetworkChange()')
    stop='    @discardableResult\n    func stop()'+section(net,'    @discardableResult\n    func stop()','    var localVPNWiFiSnapshot:')
    fixture=(ROOT/'.ci/owned-readiness/fixture.swift').read_text()
    return fixture.replace('// TYPES',types).replace('// COALESCER',actor).replace('// CORE',methods).replace('// NETWORK\n',transaction+'\n').replace('// CONFIG_IDENTITY',identity).replace('// PROVIDER_OWNERSHIP',ownership).replace('// NETWORK_STATE',network_state).replace('// STOP',stop).replace('// WIFI_HELPER',wifi).replace('// WIFI_ACCESSORS',wifi_accessors).replace('// START',observe_start_publication(start))
class OwnedReadinessTests(unittest.TestCase):
    def test_join_observation_is_one_reversible_fixture_only_insertion(self):
        original=(ROOT/'Sources/Services/EndpointRefreshTransaction.swift').read_text()
        transformed=observe_join(original)
        self.assertEqual(transformed.replace(JOIN_INSTRUMENTED,JOIN_ANCHOR,1),original)
        for mutant in (original+JOIN_ANCHOR,original.replace(JOIN_ANCHOR,'return false')):
            with self.assertRaises(AssertionError):observe_join(mutant)
        self.assertNotIn('fixtureJoinSignal',original)
        fixture=(ROOT/'.ci/owned-readiness/fixture.swift').read_text()
        self.assertIn('await fixtureJoinSignal.wait()',fixture)
        self.assertNotIn('0..<100',fixture)

    def test_typed_guards_no_text_retry(self):
        s=(ROOT/'Sources/MinimuxerImpl.swift').read_text()
        self.assertEqual(s.count('transient: transientAllowed ?'),4)
        self.assertNotIn('localizedDescription.contains',s)
        self.assertIn('owned: false).result',s)
        self.assertIn('guard deviceProvider.hasActiveOwnedBatch',s)
        gate=section(s,'// Only network prerequisites have passed.','        let deviceUDID: String')
        self.assertIn('return .init(result: .success(true))',gate)
        self.assertIn('await network.refreshEndpointValidated()',s)
        self.assertIn('configurationIdentity() == configuration',s)
    def test_whole_transaction_and_configuration_fence(self):
        n=(ROOT/'Sources/Services/NetworkObserverService.swift').read_text()
        self.assertIn('await endpointRefresh.run { [self] in await refreshEndpointTransaction() }',n)
        self.assertIn('publishedConfiguration == configuration',n)
        m=(ROOT/'Sources/Services/DeviceConnectionManager.swift').read_text()
        self.assertIn('configurationGeneration &+= 1',m)
        self.assertGreaterEqual(m.count('guard configurationIdentity() == configuration else { return false }'),4)
        self.assertNotIn('.cancel()', (ROOT/'Sources/Services/EndpointRefreshTransaction.swift').read_text())
    def test_start_publication_hook_is_one_reversible_scheduling_point(self):
        n=(ROOT/'Sources/Services/NetworkObserverService.swift').read_text()
        transformed=observe_start_publication(n)
        self.assertEqual(transformed.replace(START_PUBLICATION_HOOK,'',1),n)
        self.assertNotIn('fixtureStartPublicationGate',n)
        for mutant in (n+START_PUBLICATION_ANCHOR,n.replace(START_PUBLICATION_ANCHOR,'changed')):
            with self.assertRaises(AssertionError):observe_start_publication(mutant)

    def test_local_wifi_contract_is_scoped_and_callback_only(self):
        n=(ROOT/'Sources/Services/NetworkObserverService.swift').read_text()
        helper=section(n,'// V3_LOCAL_VPN_WIFI_OBSERVATION_BEGIN','// V3_LOCAL_VPN_WIFI_OBSERVATION_END')
        self.assertIn('NWPathMonitor(requiredInterfaceType: .wifi)',helper)
        self.assertIn('guard let monitor, received else',helper)
        self.assertIn('let path = monitor.currentPath',helper)
        self.assertIn('generation == token',helper)
        self.assertNotIn('onNetworkChanged',helper)
        self.assertNotIn('fetchUDID',helper)
        self.assertNotIn('refreshEndpoint',helper)
        public=section(n,'    var isWifiSatisfied: Bool {','    var isWiredSatisfied: Bool {')
        self.assertIn('monitor.currentPath',public)
        self.assertNotIn('localVPNWiFi',public)
        core=(ROOT/'Sources/MinimuxerImpl.swift').read_text()
        self.assertIn('connectionMode == .localVPN ? localWiFi.satisfied : network.isWifiSatisfied',core)
        self.assertIn('let currentWiFi = network.localVPNWiFiSnapshot',core)
        self.assertIn('currentWiFi.generation == localWiFi.generation',core)
        probe=core.split('let peerReachable = testDeviceConnection(ifaddr: deviceIp)',1)[1]
        self.assertLess(probe.index('localObservationFailure()'),probe.index('if !peerReachable'))
        diagnostic=section(n,'    func logReadinessWiFiObservation(', '    var isWifiSatisfied:')
        for forbidden in ('SSID','interfaceAddresses','localizedDescription','remotePeer','overridePeer'):
            self.assertNotIn(forbidden,diagnostic)

    def test_actual_source_owned_runtime(self):
        source=generate()
        swift=shutil.which('swiftc')
        if not swift:
            if os.environ.get('REQUIRE_SWIFT_OWNED_READINESS_TESTS')=='1':self.fail('Mandatory Swift compiler unavailable')
            self.skipTest('Swift unavailable: executable owned-readiness tests not run')
        with tempfile.TemporaryDirectory(prefix='owned-readiness-') as td:
            p=Path(td).resolve();(p/'main.swift').write_text(source)
            subprocess.run([swift,'-swift-version','5','-parse-as-library',str(p/'main.swift'),'-o',str(p/'cases')],check=True,timeout=120)
            subprocess.run([str(p/'cases')],check=True,timeout=30)
            if platform.system()=='Darwin':
                sdk=subprocess.check_output(['xcrun','--sdk','iphonesimulator','--show-sdk-path'],text=True).strip()
                architecture=platform.machine();self.assertIn(architecture,['arm64','x86_64'])
                helper=section((ROOT/'Sources/Services/NetworkObserverService.swift').read_text(),'// V3_LOCAL_VPN_WIFI_OBSERVATION_BEGIN','// V3_LOCAL_VPN_WIFI_OBSERVATION_END')
                (p/'real-network.swift').write_text('import Foundation\nimport Network\n'+helper)
                subprocess.run([swift,'-swift-version','5','-typecheck','-parse-as-library','-sdk',sdk,'-target',architecture+'-apple-ios14.0-simulator',str(p/'real-network.swift')],check=True,timeout=120)
                subprocess.run([swift,'-swift-version','5','-typecheck','-parse-as-library','-sdk',sdk,'-target',architecture+'-apple-ios14.0-simulator',str(p/'main.swift')],check=True,timeout=120)
if __name__=='__main__':unittest.main(verbosity=2)
