#!/usr/bin/env python3
"""Standard-library-only actual C qualification with the existing pinned OpenSSL CLI."""
import argparse, ctypes as C, datetime as dt, json, os, pathlib, subprocess, tempfile
P=pathlib.Path
parser=argparse.ArgumentParser();parser.add_argument('--openssl-root',required=True);parser.add_argument('--output',required=True);parser.add_argument('--development',action='store_true');parser.add_argument('--openssl-cli');args=parser.parse_args()
root=P(args.openssl_root).resolve();openssl=P(args.openssl_cli).resolve() if args.openssl_cli else root/'bin/openssl';core=P(__file__).resolve().parents[1]/'DeviceGateway/ProvisioningCMSCore'
version=subprocess.run([str(openssl),'version'],check=True,capture_output=True,text=True).stdout.split()[1]
if not args.development and version!='3.5.9':raise SystemExit('Exact OpenSSL 3.5.9 required')
class Content(C.Structure):_fields_=[('bytes',C.c_void_p),('length',C.c_size_t)]
checks=[]
with tempfile.TemporaryDirectory(prefix='cms-native-') as temp:
 t=P(temp)
 # install_dev intentionally omits OPENSSLDIR/openssl.cnf. Synthetic requests
 # own their minimal config instead of inheriting ambient or global policy.
 request_config=t/'request.cnf'
 request_config.write_text('[req]\ndistinguished_name=dn\n[dn]\n')
 # Mandatory behavioral regression: CLI fixture generation cannot accidentally
 # recover an ambient default config if an explicit req -config is removed.
 cli_environment=dict(os.environ,OPENSSL_CONF=str(t/'absent-default.cnf'))
 def run(*argv):
  environment=cli_environment if argv[0]==openssl else None
  return subprocess.run([str(x) for x in argv],env=environment,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout
 libs={}
 version_source=t/'version.c'
 version_source.write_text('#include <openssl/crypto.h>\n#include <openssl/opensslv.h>\n'+('' if args.development else '_Static_assert(OPENSSL_VERSION_MAJOR == 3 && OPENSSL_VERSION_MINOR == 5 && OPENSSL_VERSION_PATCH == 9, "Exact headers required");\n')+'const char *v3_qualification_linked_version(void) { return OpenSSL_version(0); }\n')
 for mode in ['production','test']:
  lib=t/(mode+'.dylib');flags=['-DV3_CMS_TESTING'] if mode=='test' else []
  archive=next((root/d/'libcrypto.a' for d in ['lib','lib64'] if (root/d/'libcrypto.a').exists()),root/'lib/libcrypto.a')
  link=[str(archive)] if archive.exists() else ['-L',str(root/'lib'),'-lcrypto']
  if not args.development and not archive.exists():raise SystemExit('Pinned static libcrypto missing')
  run(os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror','-fPIC','-shared',*flags,core/'profile_cms.c',version_source,'-I',core/'include','-I',root/'include',*link,'-o',lib)
  libs[mode]=C.CDLL(str(lib))
  linked_version=libs[mode].v3_qualification_linked_version;linked_version.argtypes=[];linked_version.restype=C.c_char_p
  if linked_version().decode().split()[1]!=version:raise RuntimeError('CLI/library version mismatch')
  for name in ['v3_profile_cms_verify_legacy_outer','v3_profile_cms_verify_pinned_inner']:
   f=getattr(libs[mode],name);f.argtypes=[C.c_void_p,C.c_size_t,C.POINTER(Content)];f.restype=C.c_int
  libs[mode].v3_profile_cms_content_free.argtypes=[C.POINTER(Content)]
 test=libs['test'];test.v3_test_cms_authenticate.argtypes=[C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t,C.POINTER(Content)];test.v3_test_cms_authenticate.restype=C.c_int
 test.v3_test_inner_authenticate.argtypes=[C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t,C.POINTER(Content)];test.v3_test_inner_authenticate.restype=C.c_int
 def check(name,ok):
  if not ok:raise AssertionError(name)
  checks.append(name)
 check('production_has_no_injected_trust_exports',not hasattr(libs['production'],'v3_test_cms_authenticate') and not hasattr(libs['production'],'v3_test_inner_authenticate'))
 def verify(data,inner=False,anchor=None,pin=None):
  out=Content();buf=C.create_string_buffer(data);lib=libs['production'] if anchor is None else test
  if anchor is None:status=getattr(lib,'v3_profile_cms_verify_pinned_inner' if inner else 'v3_profile_cms_verify_legacy_outer')(buf,len(data),C.byref(out))
  elif inner:
   a=C.create_string_buffer(anchor);p=C.create_string_buffer(pin);status=test.v3_test_inner_authenticate(buf,len(data),a,len(anchor),p,len(pin),C.byref(out))
  else:
   a=C.create_string_buffer(anchor);status=test.v3_test_cms_authenticate(buf,len(data),a,len(anchor),C.byref(out))
  payload=C.string_at(out.bytes,out.length) if out.bytes else None
  if status:assert not out.bytes and not out.length
  lib.v3_profile_cms_content_free(C.byref(out));assert not out.bytes and not out.length
  return status,payload
 def req(name,cn):
  run(openssl,'req','-config',request_config,'-new','-newkey','rsa:2048','-nodes','-subj','/CN='+cn,'-keyout',t/(name+'.key'),'-out',t/(name+'.csr'))
 def issue(name,issuer,start,end,ca=False):
  db=t/(name+'.db');db.write_text('');serial=t/(name+'.serial');serial.write_text('01\n')
  conf=t/(name+'.cnf');conf.write_text(f'''[ca]
default_ca=c
[c]
database={db}
new_certs_dir={t}
certificate={t/(issuer+'.pem')}
private_key={t/(issuer+'.key')}
serial={serial}
default_md=sha256
policy=p
x509_extensions=e
[p]
commonName=supplied
[e]
basicConstraints=critical,CA:{'TRUE,pathlen:0' if ca else 'FALSE'}
keyUsage=critical,{'keyCertSign,cRLSign' if ca else 'digitalSignature'}
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
''')
  run(openssl,'ca','-batch','-notext','-config',conf,'-in',t/(name+'.csr'),'-out',t/(name+'.pem'),'-startdate',start,'-enddate',end)
  return run(openssl,'x509','-in',t/(name+'.pem'),'-outform','DER')
 now=dt.datetime.now(dt.timezone.utc);fmt=lambda v:v.strftime('%Y%m%d%H%M%SZ');before=fmt(now-dt.timedelta(days=1));after=fmt(now+dt.timedelta(days=2))
 req('root','Synthetic CMS test root')
 run(openssl,'req','-config',request_config,'-x509','-new','-key',t/'root.key','-subj','/CN=Synthetic CMS test root','-days','3','-sha256','-addext','basicConstraints=critical,CA:TRUE,pathlen:1','-addext','keyUsage=critical,keyCertSign,cRLSign','-addext','subjectKeyIdentifier=hash','-out',t/'root.pem')
 anchor=run(openssl,'x509','-in',t/'root.pem','-outform','DER')
 req('issuer','Apple iPhone Certification Authority');issue('issuer','root',before,after,True)
 req('leaf','Apple iPhone OS Provisioning Profile Signing');pin=issue('leaf','issuer',before,after)
 payload=b'bounded synthetic profile authority';(t/'payload').write_bytes(payload)
 def sign(name='leaf',digest='sha256',options=()):
  return run(openssl,'cms','-sign','-binary','-in',t/'payload','-signer',t/(name+'.pem'),'-inkey',t/(name+'.key'),'-certfile',t/'issuer.pem','-md',digest,'-outform','DER',*options)
 valid=sign(options=('-nodetach',))
 check('test_legacy_chain_and_math',verify(valid,anchor=anchor)==(0,payload))
 check('test_inner_exact_pin_chain_and_math',verify(valid,True,anchor,pin)==(0,payload))
 check('production_rejects_synthetic_outer',verify(valid)[0]==3)
 check('production_rejects_unknown_inner_pin',verify(valid,True)[0]==6)
 check('test_rejects_wrong_inner_pin',verify(valid,True,anchor,anchor)[0]==6)
 check('signature_tamper_rejected',verify(valid[:-1]+bytes([valid[-1]^1]),True,anchor,pin)[0]==4)
 check('content_tamper_rejected',verify(valid.replace(payload,b'X'+payload[1:]),True,anchor,pin)[0]==4)
 check('trailing_data_rejected',verify(valid+b'X',True,anchor,pin)[0]==1)
 check('truncated_data_rejected',verify(valid[:-1],True,anchor,pin)[0]==1)
 check('detached_rejected',verify(sign(),True,anchor,pin)[0]==2)
 check('no_signed_attributes_rejected',verify(sign(options=('-nodetach','-noattr')),True,anchor,pin)[0]==2)
 check('unsupported_digest_rejected',verify(sign(digest='sha224',options=('-nodetach',)),True,anchor,pin)[0]==2)
 check('sha1_not_inner_authority',verify(sign(digest='sha1',options=('-nodetach',)),True,anchor,pin)[0]==2)
 check('sha1_only_legacy_envelope',verify(sign(digest='sha1',options=('-nodetach',)),anchor=anchor)==(0,payload))
 for label,lo,hi in [('expired',now-dt.timedelta(days=3),now-dt.timedelta(days=2)),('future',now+dt.timedelta(days=1),now+dt.timedelta(days=2))]:
  req(label,'Apple iPhone OS Provisioning Profile Signing');newpin=issue(label,'issuer',fmt(lo),fmt(hi));cms=sign(label,options=('-nodetach',))
  check(label+'_inner_time_rejected',verify(cms,True,anchor,newpin)[0]==7)
  check(label+'_legacy_documented_no_time',verify(cms,anchor=anchor)==(0,payload))
 # Rewrite only bounded synthetic DER to exercise adversarial cert/SID inventory.
 def tlv(tag,body):
  n=len(body);length=bytes([n]) if n<128 else bytes([128+(n.bit_length()+7)//8])+n.to_bytes((n.bit_length()+7)//8,'big')
  return bytes([tag])+length+body
 def nodes(data):
  out=[];pos=0
  while pos<len(data):
   start=pos;tag=data[pos];pos+=1;n=data[pos];pos+=1
   if n&128:
    count=n&127;n=int.from_bytes(data[pos:pos+count],'big');pos+=count
   body=data[pos:pos+n];pos+=n;out.append((tag,body,data[start:pos]))
  return out
 outer=nodes(valid)[0];parts=nodes(outer[1]);signed=nodes(parts[1][1])[0];fields=nodes(signed[1]);certindex=next(i for i,f in enumerate(fields) if f[0]==160)
 def rewrite_certificates(certs):
  changed=[f[2] for f in fields];changed[certindex]=tlv(160,b''.join(certs))
  return tlv(48,parts[0][2]+tlv(160,tlv(48,b''.join(changed))))
 certs=[n[2] for n in nodes(fields[certindex][1])]
 check('reordered_certificates_same_authority',verify(rewrite_certificates(list(reversed(certs))),True,anchor,pin)==(0,payload))
 check('duplicate_matching_sid_rejected',verify(rewrite_certificates(certs+[pin]),True,anchor,pin)[0]==2)
 # Same issuer+serial but a different subject/key, still untrusted ambiguity.
 req('collision','Different synthetic signer');collision=issue('collision','issuer',before,after)
 for index,inventory in enumerate([certs+[collision],[collision]+certs]):
  check('conflicting_same_sid_order_'+str(index),verify(rewrite_certificates(inventory),True,anchor,pin)[0]==2)
 # Signed contentType OID byte mutation cannot be hidden by valid content bytes.
 oid=bytes.fromhex('06092a864886f70d010701');at=valid.rfind(oid)
 check('signed_content_type_tamper_rejected',verify(valid[:at]+oid[:-1]+b'\x03'+valid[at+len(oid):],True,anchor,pin)[0]==4)
 changed=[f[2] for f in fields];signers=nodes(fields[-1][1]);changed[-1]=tlv(49,signers[0][2]*2)
 check('multiple_signers_rejected',verify(tlv(48,parts[0][2]+tlv(160,tlv(48,b''.join(changed)))),True,anchor,pin)[0]==2)
 # Enlarge the synthetic RSA modulus without performing expensive key generation.
 # The candidate is rejected before pin/chain math, not interpreted as a signer.
 def oversized_key_der(data):
  rewritten=[]
  for tag,body,raw in nodes(data):
   if tag&32:rewritten.append(tlv(tag,oversized_key_der(body)))
   elif tag==3 and body[:2]==b'\x00\x30':
    rsa=nodes(body[1:])
    if len(rsa)==1 and rsa[0][0]==48:
     ints=nodes(rsa[0][1])
     if len(ints)==2 and all(i[0]==2 for i in ints):
      rewritten.append(tlv(3,b'\x00'+tlv(48,tlv(2,b'\x01'+b'\x01'*1024)+ints[1][2])));continue
    rewritten.append(raw)
   else:rewritten.append(raw)
  return b''.join(rewritten)
 oversized=oversized_key_der(pin)
 check('oversized_rsa_candidate_rejected_before_math',oversized!=pin and verify(rewrite_certificates([oversized if c==pin else c for c in certs]),True,anchor,pin)[0]==2)
 check('empty_input_rejected',verify(b'')[0]==5)
 check('oversized_input_rejected',verify(b'x'*(1024*1024+1))[0]==5)
expected=json.loads((P(__file__).resolve().parent/'expected-cases.json').read_text())
if checks!=expected['checks'] or len(checks)!=expected['count']:raise AssertionError('Exact security case inventory changed')
result={'schema':'profile-cms-native-v1','openssl':version,'qualified':not args.development,'time_policy':'inner-current-system-time;legacy-no-check-time','tested_at_utc':dt.datetime.now(dt.timezone.utc).isoformat(),'checks':checks,'count':len(checks),'status':'passed'}
P(args.output).write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');print('CMS native checks:',len(checks),'PASS')
