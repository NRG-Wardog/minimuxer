"""Source-owned cold VPN controls. Executes extracted production, not native/device networking."""
import hashlib,json,os,platform,shutil,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def section(text,start,end):
    assert text.count(start)==1
    return text.split(start,1)[1].split(end,1)[0]
def generate():
    api=(ROOT/'Sources/MinimuxerApi.swift').read_text()
    core=(ROOT/'Sources/MinimuxerImpl.swift').read_text()
    net=(ROOT/'Sources/Services/NetworkObserverService.swift').read_text()
    actor=(ROOT/'Sources/Services/EndpointRefreshTransaction.swift').read_text()
    types=section(api,'// V3_OWNED_READINESS_TYPES_BEGIN','// V3_OWNED_READINESS_TYPES_END')
    methods='    func isReady(withNetworkCheck:'+section(core,'    func isReady(withNetworkCheck:','    private func runWithChecks')
    transaction='    func refreshEndpoint()'+section(net,'    func refreshEndpoint()','    @discardableResult\n    func stop()')
    manager=(ROOT/'Sources/Services/DeviceConnectionManager.swift').read_text()
    identity=section(manager,'actor DeviceConnectionManager {','    let deviceProvider: DeviceProvider')
    provider=(ROOT/'Sources/DeviceProvider.swift').read_text()
    ownership='    var hasActiveOwnedBatch: Bool {'+section(provider,'    var hasActiveOwnedBatch: Bool {','    func beginTransportBatch()')
    network_state='    private actor State {'+section(net,'    private actor State {','    @discardableResult\n    func start()')
    stop='    @discardableResult\n    func stop()'+section(net,'    @discardableResult\n    func stop()','    var isWifiSatisfied:')
    fixture=(ROOT/'.ci/owned-readiness/fixture.swift').read_text()
    return fixture.replace('// TYPES',types).replace('// COALESCER',actor).replace('// CORE',methods).replace('// NETWORK\n',transaction+'\n').replace('// CONFIG_IDENTITY',identity).replace('// PROVIDER_OWNERSHIP',ownership).replace('// NETWORK_STATE',network_state).replace('// STOP',stop)
class OwnedReadinessTests(unittest.TestCase):
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
                subprocess.run([swift,'-swift-version','5','-typecheck','-parse-as-library','-sdk',sdk,'-target',architecture+'-apple-ios14.0-simulator',str(p/'main.swift')],check=True,timeout=120)
if __name__=='__main__':unittest.main(verbosity=2)
