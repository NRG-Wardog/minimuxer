"""Actual policy execution when Swift is available, plus boundary wiring controls.
No device access, profile exports, dependency downloads, or mutation replay.
"""
import os, pathlib, shutil, subprocess, tempfile, unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
def section(text, start, end):
    assert text.count(start) == 1
    return text.split(start, 1)[1].split(end, 1)[0]
class ReadbackTests(unittest.TestCase):
    def test_real_gateways_implement_no_export_readback(self):
        source=(ROOT/'DeviceGateway/idevice/IdeviceGateway.swift').read_text()
        body=section(source,'    private func syncReadInstalledProvisioningProfiles()', '    private func syncDumpProfiles(')
        for forbidden in ('debugLog(', 'verboseLog(', '.write(', 'FileManager', 'misagent_install(', 'ensureRPConnection(', 'performWithEitherService('):
            self.assertNotIn(forbidden, body)
        self.assertIn('misagent_read_profiles_rsd(',body)
        self.assertIn('misagent_read_profiles(',body)
        self.assertIn('guard batchCount > 0 else',body)
        self.assertIn('guard let adapter, let handshake else',body)
        alternate=(ROOT/'DeviceGateway/libimobiledevice/LibimobiledeviceGateway.swift').read_text()
        unsupported=section(alternate,'    public func readInstalledProvisioningProfiles()', '    public func dumpProfiles(')
        self.assertIn('throw LibimobiledeviceGatewayError(.unsupportedOperation',unsupported)
    def test_native_memory_and_transport_retained(self):
        source=(ROOT/'DeviceGateway/idevice/IdeviceGateway.swift').read_text()
        body=section(source,'    private func syncReadInstalledProvisioningProfiles()', '    private func syncDumpProfiles(')
        self.assertIn('defer { misagent_free_profiles(profiles, lengths, count) }',body)
        self.assertLess(body.index('validateLength(lengths[index]'),body.index('Data(bytes: bytes'))
        public=section(source,'    public func readInstalledProvisioningProfiles()', '    public func dumpProfiles(')
        self.assertIn('withFFIDispatch(on: self.ffiQueue)',public)
        self.assertIn('if self.batchCount == 0 { self.releaseTransport() }',public)
        self.assertEqual(public.count('Task.checkCancellation()'),2)
        self.assertNotIn('Task.detached',public)
    def test_capture_and_unsupported_are_fail_closed(self):
        source=(ROOT/'Sources/MinimuxerImpl.swift').read_text()
        body=section(source,'    func readInstalledProvisioningProfiles()', '    func dumpProfiles(')
        self.assertIn('let capturedGateway = gateway',body)
        self.assertIn('capturedGateway.readInstalledProvisioningProfiles()',body)
        for path in ['Sources/MinimuxerApi.swift','DeviceGateway/DeviceGatewayAPI.swift']:
            body=(ROOT/path).read_text()
            self.assertIn('installed_profile_readback',body)
            self.assertIn('throw ',body)
    def test_install_ack_uses_same_strict_policy(self):
        source=(ROOT/'DeviceGateway/libimobiledevice/LibimobiledeviceGateway.swift').read_text()
        body=section(source,'    func syncInstallProvisioningProfile(', '    func syncRemoveProvisioningProfile(')
        self.assertIn('try InstalledProfileReadback.requireSuccessStatus(resp)',body)
        self.assertNotIn('if let status',body)
    def test_actual_policy_native(self):
        swift=shutil.which('swiftc')
        if not swift:
            if os.environ.get('REQUIRE_NATIVE_PROFILE_READBACK') == '1': self.fail('required swiftc unavailable')
            self.skipTest('swiftc unavailable; mandatory native CI still required')
        source='\n'.join((ROOT/p).read_text() for p in ['DeviceGateway/DeviceGatewayError.swift','DeviceGateway/InstalledProfileReadback.swift','.ci/profile-readback/policy-fixture.swift'])
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp).resolve(); path=root/'main.swift'; path.write_text(source)
            subprocess.run([swift,str(path),'-o',str(root/'fixture')],check=True,timeout=120)
            subprocess.run([str(root/'fixture')],check=True,timeout=30)
    def test_actual_idevice_copy_and_free_native(self):
        swift=shutil.which('swiftc')
        if not swift:
            if os.environ.get('REQUIRE_NATIVE_PROFILE_READBACK') == '1': self.fail('required swiftc unavailable')
            self.skipTest('swiftc unavailable; mandatory native CI still required')
        production=(ROOT/'DeviceGateway/idevice/IdeviceGateway.swift').read_text()
        method='    private func syncReadInstalledProvisioningProfiles()'+section(production,'    private func syncReadInstalledProvisioningProfiles()', '    private func syncDumpProfiles(')
        fixture=(ROOT/'.ci/profile-readback/ffi-fixture.swift').read_text().replace('    // PRODUCTION_SYNC_METHOD',method)
        source='\n'.join((ROOT/p).read_text() for p in ['DeviceGateway/DeviceGatewayError.swift','DeviceGateway/InstalledProfileReadback.swift'])+'\n'+fixture
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp).resolve(); path=root/'main.swift'; path.write_text(source)
            subprocess.run([swift,str(path),'-o',str(root/'fixture')],check=True,timeout=120)
            subprocess.run([str(root/'fixture')],check=True,timeout=30)
if __name__=='__main__':unittest.main()
