from pathlib import Path
import ctypes as C, datetime as dt, hashlib, json, unittest, sys, os, subprocess, tempfile
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
ROOT=Path(__file__).resolve().parent
class Content(C.Structure): _fields_=[('bytes',C.c_void_p),('length',C.c_size_t)]
BUILD=tempfile.TemporaryDirectory(prefix='profile-cms-tests-')
CORE=ROOT.parent/'DeviceGateway/ProvisioningCMSCore'
openssl_root=os.environ.get('CMS_OPENSSL_ROOT')
if openssl_root:
 openssl_root=Path(openssl_root).resolve()
 version=subprocess.run([str(openssl_root/'bin/openssl'),'version'],check=True,capture_output=True,text=True).stdout.split()
 if len(version)<2 or version[1]!='3.5.9':raise RuntimeError('Qualification requires exact OpenSSL 3.5.9')
 openssl_flags=['-I',str(openssl_root/'include'),str(openssl_root/'lib/libcrypto.a')]
else:
 if os.environ.get('CMS_REQUIRE_QUALIFIED')=='1':raise RuntimeError('CMS_OPENSSL_ROOT is required for qualification')
 openssl_flags=['-lcrypto']
 print('Development-only system OpenSSL run; not native qualification.',file=sys.stderr)
for name,flags in [('production',[]),('test',['-DV3_CMS_TESTING'])]:
 command=[os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror','-fPIC','-shared',*flags,str(CORE/'profile_cms.c'),'-I',str(CORE/'include'),*openssl_flags,'-o',str(Path(BUILD.name)/('libprofile_'+name+'.so'))]
 subprocess.run(command,check=True,capture_output=True)
prod=C.CDLL(str(Path(BUILD.name)/'libprofile_production.so'));test=C.CDLL(str(Path(BUILD.name)/'libprofile_test.so'))
for lib in [prod,test]:
 lib.v3_profile_cms_verify_legacy_outer.argtypes=[C.c_void_p,C.c_size_t,C.POINTER(Content)]
 lib.v3_profile_cms_verify_legacy_outer.restype=C.c_int
 lib.v3_profile_cms_verify_pinned_inner.argtypes=[C.c_void_p,C.c_size_t,C.POINTER(Content)]
 lib.v3_profile_cms_verify_pinned_inner.restype=C.c_int
 lib.v3_profile_cms_content_free.argtypes=[C.POINTER(Content)]
test.v3_test_cms_authenticate.argtypes=[C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t,C.POINTER(Content)]
test.v3_test_cms_authenticate.restype=C.c_int
test.v3_test_inner_authenticate.argtypes=[C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t,C.POINTER(Content)]
test.v3_test_inner_authenticate.restype=C.c_int

def verify(data,anchor=None,inner=False,pin=None):
 result=Content();buf=C.create_string_buffer(data);lib=prod if anchor is None else test
 if anchor is None:
  fn=lib.v3_profile_cms_verify_pinned_inner if inner else lib.v3_profile_cms_verify_legacy_outer
  status=fn(buf,len(data),C.byref(result))
 else:
  root=C.create_string_buffer(anchor)
  if inner:
   pinbuf=C.create_string_buffer(pin or b'');status=lib.v3_test_inner_authenticate(buf,len(data),root,len(anchor),pinbuf,len(pin or b''),C.byref(result))
  else:status=lib.v3_test_cms_authenticate(buf,len(data),root,len(anchor),C.byref(result))
 payload=C.string_at(result.bytes,result.length) if result.bytes else None
 if status!=0:assert result.length==0 and result.bytes is None,'Failure leaked unverified payload'
 lib.v3_profile_cms_content_free(C.byref(result));assert not result.bytes and not result.length
 return status,payload

def cert(cn,key,issuer=None,issuer_key=None,ca=False,path=None,serial=None,validity=None):
 subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,cn)])
 before,after=validity or (dt.datetime(2020,1,1,tzinfo=dt.timezone.utc),dt.datetime(2021,1,1,tzinfo=dt.timezone.utc))
 b=x509.CertificateBuilder().subject_name(subject).issuer_name(issuer.subject if issuer else subject).public_key(key.public_key()).serial_number(serial or x509.random_serial_number()).not_valid_before(before).not_valid_after(after)
 b=b.add_extension(x509.BasicConstraints(ca=ca,path_length=path),critical=True).add_extension(x509.KeyUsage(digital_signature=not ca,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=ca,crl_sign=ca,encipher_only=False,decipher_only=False),critical=True).add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key((issuer_key or key).public_key()),critical=False)
 return b.sign(issuer_key or key,hashes.SHA256())

def sign(payload,leaf,key,chain,options=None,digest=None,second=None):
 b=pkcs7.PKCS7SignatureBuilder().set_data(payload).add_signer(leaf,key,digest or hashes.SHA256())
 for c in chain:b=b.add_certificate(c)
 if second:b=b.add_signer(*second,hashes.SHA256())
 return b.sign(serialization.Encoding.DER,options or [pkcs7.PKCS7Options.Binary])

class SyntheticCMS(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.rk=rsa.generate_private_key(public_exponent=65537,key_size=2048);cls.root=cert('Synthetic test root',cls.rk,ca=True,path=1)
  cls.ik=rsa.generate_private_key(public_exponent=65537,key_size=2048);cls.issuer=cert('Apple iPhone Certification Authority',cls.ik,cls.root,cls.rk,ca=True,path=0)
  cls.lk=rsa.generate_private_key(public_exponent=65537,key_size=2048);cls.leaf=cert('Apple iPhone OS Provisioning Profile Signing',cls.lk,cls.issuer,cls.ik)
  cls.anchor=cls.root.public_bytes(serialization.Encoding.DER);cls.payload=b'fixture-only authenticated content; never device information'
  cls.cms=sign(cls.payload,cls.leaf,cls.lk,[cls.issuer,cls.root])
 def test_valid_synthetic_math_requires_test_root(self):
  self.assertEqual(verify(self.cms,self.anchor),(0,self.payload));self.assertEqual(verify(self.cms)[0],3)
 def test_expired_signer_chain_intentionally_no_time(self):
  self.assertLess(self.leaf.not_valid_after_utc,dt.datetime.now(dt.timezone.utc));self.assertEqual(verify(self.cms,self.anchor)[0],0)
 def test_modified_content_rejected(self):
  self.assertIn(self.payload,self.cms);changed=self.cms.replace(self.payload,b'X'+self.payload[1:],1);self.assertEqual(verify(changed,self.anchor)[0],4)
 def test_modified_signature_rejected(self):
  changed=self.cms[:-1]+bytes([self.cms[-1]^1]);self.assertEqual(verify(changed,self.anchor)[0],4)
 def test_trailing_and_truncated_data_rejected(self):
  self.assertEqual(verify(self.cms+b'garbage',self.anchor)[0],1);self.assertNotEqual(verify(self.cms[:-1],self.anchor)[0],0)
 def test_detached_rejected(self):
  detached=sign(self.payload,self.leaf,self.lk,[self.issuer],options=[pkcs7.PKCS7Options.Binary,pkcs7.PKCS7Options.DetachedSignature]);self.assertEqual(verify(detached,self.anchor)[0],2)
 def test_wrong_root_rejected(self):
  self.assertEqual(verify(self.cms,self.issuer.public_bytes(serialization.Encoding.DER))[0],3)
 def test_wrong_leaf_name_rejected(self):
  leaf=cert('Wrong purpose signer',self.lk,self.issuer,self.ik);data=sign(self.payload,leaf,self.lk,[self.issuer]);self.assertEqual(verify(data,self.anchor)[0],3)
 def test_multiple_signers_rejected(self):
  other=cert('Apple iPhone OS Provisioning Profile Signing',self.lk,self.issuer,self.ik);data=sign(self.payload,self.leaf,self.lk,[self.issuer],second=(other,self.lk));self.assertEqual(verify(data,self.anchor)[0],2)
 def test_unknown_digest_rejected(self):
  data=sign(self.payload,self.leaf,self.lk,[self.issuer],digest=hashes.SHA224());self.assertEqual(verify(data,self.anchor)[0],2)
 def test_duplicate_same_sid_rejected(self):
  duplicate=sign(self.payload,self.leaf,self.lk,[self.issuer,self.leaf]);self.assertEqual(verify(duplicate,self.anchor)[0],2)
 def test_conflicting_same_sid_rejected_both_orders(self):
  key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
  conflicting=cert('Apple iPhone OS Provisioning Profile Signing',key,self.issuer,self.ik,serial=self.leaf.serial_number)
  for chain in [[self.issuer,conflicting],[conflicting,self.issuer]]:
   data=sign(self.payload,self.leaf,self.lk,chain);self.assertEqual(verify(data,self.anchor)[0],2)
 def test_reordered_valid_certificates_same_result(self):
  data=sign(self.payload,self.leaf,self.lk,[self.root,self.issuer]);self.assertEqual(verify(data,self.anchor),(0,self.payload))
 def test_signed_attributes_required(self):
  data=sign(self.payload,self.leaf,self.lk,[self.issuer],options=[pkcs7.PKCS7Options.Binary,pkcs7.PKCS7Options.NoAttributes]);self.assertEqual(verify(data,self.anchor)[0],2)
 def test_modified_signed_content_type_rejected(self):
  oid=bytes.fromhex('06092a864886f70d010701');at=self.cms.rfind(oid);self.assertGreater(at,0)
  changed=self.cms[:at]+oid[:-1]+b'\x03'+self.cms[at+len(oid):];self.assertEqual(verify(changed,self.anchor)[0],4)
 def test_bounds_rejected(self):
  self.assertEqual(verify(b'')[0],5);self.assertEqual(verify(b'x'*(1024*1024+1))[0],5)
 def test_production_exports_no_test_anchor_api(self):
  self.assertFalse(hasattr(prod,'v3_test_cms_authenticate'))


class PinnedInner(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  now=dt.datetime.now(dt.timezone.utc);cls.valid=(now-dt.timedelta(days=1),now+dt.timedelta(days=30))
  cls.rk=rsa.generate_private_key(public_exponent=65537,key_size=2048);cls.root=cert('Synthetic test root',cls.rk,ca=True,path=1,validity=cls.valid)
  cls.ik=rsa.generate_private_key(public_exponent=65537,key_size=2048);cls.issuer=cert('Synthetic test issuing CA',cls.ik,cls.root,cls.rk,ca=True,path=0,validity=cls.valid)
  cls.lk=rsa.generate_private_key(public_exponent=65537,key_size=2048);cls.leaf=cert('Synthetic pinned signer',cls.lk,cls.issuer,cls.ik,validity=cls.valid)
  cls.anchor=cls.root.public_bytes(serialization.Encoding.DER);cls.pin=cls.leaf.public_bytes(serialization.Encoding.DER)
  cls.payload=b'fixture-only nested DER authority';cls.cms=sign(cls.payload,cls.leaf,cls.lk,[cls.issuer])
 def test_exact_pinned_inner_math_and_chain(self):
  self.assertEqual(verify(self.cms,self.anchor,True,self.pin),(0,self.payload));self.assertEqual(verify(self.cms,inner=True)[0],6)
 def test_unknown_pin_rejected(self):
  other=cert('Synthetic pinned signer',self.lk,self.issuer,self.ik,validity=self.valid)
  self.assertEqual(verify(self.cms,self.anchor,True,other.public_bytes(serialization.Encoding.DER))[0],6)
 def test_expired_and_future_pinned_leaf_rejected(self):
  now=dt.datetime.now(dt.timezone.utc)
  for validity in [(now-dt.timedelta(days=30),now-dt.timedelta(days=1)),(now+dt.timedelta(days=1),now+dt.timedelta(days=30))]:
   leaf=cert('Synthetic pinned signer',self.lk,self.issuer,self.ik,validity=validity)
   data=sign(self.payload,leaf,self.lk,[self.issuer]);self.assertEqual(verify(data,self.anchor,True,leaf.public_bytes(serialization.Encoding.DER))[0],7)
 def test_wrong_digest_for_inner_rejected(self):
  data=sign(self.payload,self.leaf,self.lk,[self.issuer],digest=hashes.SHA224());self.assertEqual(verify(data,self.anchor,True,self.pin)[0],2)
 def test_inner_signature_tamper_rejected(self):
  data=self.cms[:-1]+bytes([self.cms[-1]^1]);self.assertEqual(verify(data,self.anchor,True,self.pin)[0],4)
 def test_inner_api_not_exposed_for_injected_roots(self):self.assertFalse(hasattr(prod,'v3_test_inner_authenticate'))


if __name__=='__main__':unittest.main(verbosity=2)
