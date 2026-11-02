"""Finite ctypes bridge used by both development and pinned-native C tests."""
import ctypes as C
class Evidence(C.Structure):
 _fields_=[(n,C.c_int) for n in ['algorithm_and_attributes','pin','chain','temporal','signature']]+[(n,C.c_uint8) for n in ['profile_subject_marker','profile_issuer_marker','profile_extension_marker','app_developer_marker','fingerprint_valid']]+[('signer_sha256',C.c_uint8*32)]
def diagnose(lib,data,anchor=None,pin=None):
 out=Evidence();C.memset(C.byref(out),0xff,C.sizeof(out))
 b=C.create_string_buffer(data)
 if anchor is None:
  f=lib.v3_profile_cms_diagnose_inner;f.argtypes=[C.c_void_p,C.c_size_t,C.POINTER(Evidence)];f.restype=None
  f(b,len(data),C.byref(out))
 else:
  f=lib.v3_test_cms_diagnose_inner;f.argtypes=[C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t,C.POINTER(Evidence)];f.restype=None
  a=C.create_string_buffer(anchor);p=C.create_string_buffer(pin)
  f(b,len(data),a,len(anchor),p,len(pin),C.byref(out))
 assert all(getattr(out,n) in (0,1,2) for n in ['algorithm_and_attributes','pin','chain','temporal','signature'])
 if not out.fingerprint_valid: assert bytes(out.signer_sha256)==b'\0'*32
 return out

class CryptographicInspection(C.Structure):
 _fields_=[('untrusted_bytes',C.c_void_p),('length',C.c_size_t),('matches_approved_signer',C.c_uint8),('signer_sha256',C.c_uint8*32)]
def inspect_cryptography(lib,data,anchor=None,pin=None):
 out=CryptographicInspection();C.memset(C.byref(out),0xff,C.sizeof(out));b=C.create_string_buffer(data)
 if anchor is None:
  f=lib.v3_profile_cms_inspect_inner_cryptography;f.argtypes=[C.c_void_p,C.c_size_t,C.POINTER(CryptographicInspection)]
  f.restype=C.c_int;status=f(b,len(data),C.byref(out))
 else:
  f=lib.v3_test_cms_inspect_inner_cryptography;f.argtypes=[C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t,C.POINTER(CryptographicInspection)]
  a=C.create_string_buffer(anchor);p=C.create_string_buffer(pin);f.restype=C.c_int
  status=f(b,len(data),a,len(anchor),p,len(pin),C.byref(out))
 content=C.string_at(out.untrusted_bytes,out.length) if out.untrusted_bytes else None
 result=(status,content,out.matches_approved_signer,bytes(out.signer_sha256))
 if status:assert bytes(out)==b'\0'*C.sizeof(out),'Inspection failure leaked content or observations'
 lib.v3_profile_cms_inspection_free.argtypes=[C.POINTER(CryptographicInspection)]
 lib.v3_profile_cms_inspection_free(C.byref(out));assert bytes(out)==b'\0'*C.sizeof(out)
 return result
