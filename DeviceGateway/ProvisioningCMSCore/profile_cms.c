#include "profile_cms.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
/* SwiftPM receives the existing binary framework via -F; its headers are flat.
   The host qualification uses the ordinary installed OpenSSL include tree. */
#if __has_include(<OpenSSL/OpenSSL.h>)
#include <OpenSSL/OpenSSL.h>
#else
#include <openssl/cms.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#endif

#define MAX_CMS_BYTES (1024u * 1024u)
#define MAX_CONTENT_BYTES (512u * 1024u)
#define MAX_CERT_BYTES (64u * 1024u)
#define MAX_CERTS 16
/* Production root bytes are compiled in; synthetic roots are never accepted here. */
#include "production_roots.h"
#include "approved_inner.h"
typedef enum { LEGACY_OUTER, PINNED_INNER } cms_role;

static int exact_cn(X509_NAME *name, const char *expected) {
 int index = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
 if (index < 0 || X509_NAME_get_index_by_NID(name, NID_commonName, index) >= 0) return 0;
 X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, index);
 unsigned char *utf8 = NULL;
 int n = ASN1_STRING_to_UTF8(&utf8, X509_NAME_ENTRY_get_data(entry));
 int ok = n >= 0 && (size_t)n == strlen(expected) && memcmp(utf8, expected, (size_t)n) == 0;
 OPENSSL_free(utf8); return ok;
}
static int permitted_key(EVP_PKEY *key) {
 if (!key) return 0;
 if (EVP_PKEY_is_a(key,"RSA") || EVP_PKEY_is_a(key,"RSA-PSS")) return EVP_PKEY_get_bits(key) >= 2048 && EVP_PKEY_get_bits(key) <= 8192;
 if (EVP_PKEY_is_a(key,"EC")) {
  char group[80]; size_t n=0;
  return EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME,group,sizeof(group),&n) &&
   (!strcmp(group,"prime256v1") || !strcmp(group,"secp384r1") || !strcmp(group,"secp521r1"));
 }
 return 0;
}
static int permitted_signer(CMS_SignerInfo *si, X509 *signer, cms_role role) {
 X509_ALGOR *digest=NULL,*signature=NULL;
 CMS_SignerInfo_get0_algs(si,NULL,NULL,&digest,&signature);
 if (!digest || !signature) return 0;
 int dn=OBJ_obj2nid(digest->algorithm),sn=OBJ_obj2nid(signature->algorithm);
 int legacy_sha1 = role==LEGACY_OUTER && dn==NID_sha1 &&
  (sn==NID_rsaEncryption || sn==NID_sha1WithRSAEncryption);
 if (!legacy_sha1 && dn!=NID_sha256 && dn!=NID_sha384 && dn!=NID_sha512) return 0;
 if (!legacy_sha1 && sn!=NID_rsaEncryption && sn!=NID_rsassaPss && sn!=NID_sha256WithRSAEncryption &&
     sn!=NID_sha384WithRSAEncryption && sn!=NID_sha512WithRSAEncryption &&
     sn!=NID_ecdsa_with_SHA256 && sn!=NID_ecdsa_with_SHA384 && sn!=NID_ecdsa_with_SHA512) return 0;
 /* OpenSSL checks attribute cardinality, signed contentType and messageDigest.
    Unknown bounded attributes are not interpreted or used as authority. */
 int attribute_count=CMS_signed_get_attr_count(si);
 if (attribute_count<2 || attribute_count>32 || CMS_unsigned_get_attr_count(si)>16) return 0;
 int type_index=CMS_signed_get_attr_by_NID(si,NID_pkcs9_contentType,-1);
 int digest_index=CMS_signed_get_attr_by_NID(si,NID_pkcs9_messageDigest,-1);
 if(type_index<0 || digest_index<0 ||
    CMS_signed_get_attr_by_NID(si,NID_pkcs9_contentType,type_index)>=0 ||
    CMS_signed_get_attr_by_NID(si,NID_pkcs9_messageDigest,digest_index)>=0) return 0;
 EVP_PKEY *key=X509_get_pubkey(signer); int ok=permitted_key(key); EVP_PKEY_free(key); return ok;
}
static int add_root(X509_STORE *store,const uint8_t *der,size_t n) {
 if (!der || !n || n>MAX_CERT_BYTES) return 0;
 const unsigned char *p=der; X509 *root=d2i_X509(NULL,&p,(long)n);
 if (!root || p!=der+n) { X509_free(root); return 0; }
 int ok=X509_STORE_add_cert(store,root); X509_free(root); return ok==1;
}
static int production_roots(X509_STORE *store, cms_role role) {
 if(role==PINNED_INNER) return add_root(store,root_2,sizeof(root_2));
 if (V3_PRODUCTION_ROOT_COUNT==0) return 0;
 for(size_t i=0;i<V3_PRODUCTION_ROOT_COUNT;i++)
  if(!add_root(store,v3_production_roots[i].bytes,v3_production_roots[i].length)) return 0;
 return 1;
}
static int matches_der(X509 *cert, const uint8_t *expected, size_t n) {
 unsigned char *encoded=NULL; int length=i2d_X509(cert,&encoded);
 int ok=length>0 && (size_t)length==n && CRYPTO_memcmp(encoded,expected,n)==0;
 OPENSSL_free(encoded); return ok;
}
static int approved_inner(X509 *signer, const uint8_t *test_pin, size_t test_pin_length) {
#ifdef V3_CMS_TESTING
 if(test_pin) return matches_der(signer,test_pin,test_pin_length);
#else
 (void)test_pin; (void)test_pin_length;
#endif
 for(size_t i=0;i<APPROVED_INNER_PIN_COUNT;i++)
  if(matches_der(signer,approved_inner_pins[i].bytes,approved_inner_pins[i].length)) return 1;
 return 0;
}
static v3_cms_status verify_chain(X509_STORE *store, X509 *signer, STACK_OF(X509) *certs,
 cms_role role, const uint8_t *test_pin, size_t test_pin_length) {
 X509_STORE_CTX *ctx=X509_STORE_CTX_new(); if(!ctx) return V3_CMS_RESOURCE;
 v3_cms_status ok=V3_CMS_UNTRUSTED;
 if(!X509_STORE_CTX_init(ctx,store,signer,certs)) goto done;
 X509_VERIFY_PARAM *param=X509_STORE_CTX_get0_param(ctx);
 /* Apple profile-signing policy excludes temporal validity. This applies ONLY
    to this CMS issuer chain, not provisioning expiry or app developer certs. */
 unsigned long flags=X509_V_FLAG_X509_STRICT;
 if(role==LEGACY_OUTER) flags |= X509_V_FLAG_NO_CHECK_TIME;
 if(!X509_VERIFY_PARAM_set_flags(param,flags)) goto done;
 if(!X509_VERIFY_PARAM_set_purpose(param,X509_PURPOSE_ANY)) goto done;
 X509_VERIFY_PARAM_set_auth_level(param,2); X509_VERIFY_PARAM_set_depth(param,2);
 if(X509_verify_cert(ctx)!=1) {
  int error=X509_STORE_CTX_get_error(ctx);
  if(role==PINNED_INNER && (error==X509_V_ERR_CERT_HAS_EXPIRED || error==X509_V_ERR_CERT_NOT_YET_VALID))
   ok=V3_CMS_SIGNER_TIME_INVALID;
  goto done;
 }
 STACK_OF(X509) *chain=X509_STORE_CTX_get0_chain(ctx);
 if(!chain || sk_X509_num(chain)!=3) goto done;
 if(role==LEGACY_OUTER) {
  if(!exact_cn(X509_get_subject_name(sk_X509_value(chain,0)),"Apple iPhone OS Provisioning Profile Signing") ||
     !exact_cn(X509_get_subject_name(sk_X509_value(chain,1)),"Apple iPhone Certification Authority")) goto done;
 }
 (void)test_pin; (void)test_pin_length;
 /* X509 verifies CA signatures/linkage/constraints/critical extensions; the
    final anchor comes only from compiled pins, never a CMS or system store. */
 ok=V3_CMS_OK;
done: X509_STORE_CTX_free(ctx); return ok;
}
static v3_cms_status authenticate(const uint8_t *data,size_t length,
 const uint8_t *test_root,size_t test_root_length, cms_role role,
 const uint8_t *test_pin,size_t test_pin_length,v3_cms_content *result, v3_cms_signer_evidence *evidence, v3_cms_cryptographic_inspection *inspection) {
 v3_cms_status status=V3_CMS_MALFORMED;
 CMS_ContentInfo *cms=NULL; STACK_OF(X509) *certs=NULL,*only_signer=NULL;
 X509_STORE *store=NULL; BIO *verified=NULL;
 if(evidence) memset(evidence,0,sizeof(*evidence));
 if(inspection) memset(inspection,0,sizeof(*inspection));
 if(!result) return V3_CMS_MALFORMED;
 result->bytes=NULL; result->length=0;
 if(!data || !length || length>MAX_CMS_BYTES || length>LONG_MAX) return V3_CMS_RESOURCE;
 const unsigned char *cursor=data;
 cms=d2i_CMS_ContentInfo(NULL,&cursor,(long)length);
 if(!cms || cursor!=data+length) goto done;
 if(OBJ_obj2nid(CMS_get0_type(cms))!=NID_pkcs7_signed || CMS_is_detached(cms)!=0 ||
    OBJ_obj2nid(CMS_get0_eContentType(cms))!=NID_pkcs7_data) { status=V3_CMS_UNSUPPORTED; goto done; }
 ASN1_OCTET_STRING **content=CMS_get0_content(cms);
 if(!content || !*content || ASN1_STRING_length(*content)<=0 ||
    (size_t)ASN1_STRING_length(*content)>MAX_CONTENT_BYTES) { status=V3_CMS_RESOURCE; goto done; }
 STACK_OF(CMS_SignerInfo) *signers=CMS_get0_SignerInfos(cms);
 if(!signers || sk_CMS_SignerInfo_num(signers)!=1) { status=V3_CMS_UNSUPPORTED; goto done; }
 certs=CMS_get1_certs(cms);
 if(!certs || sk_X509_num(certs)<1 || sk_X509_num(certs)>MAX_CERTS) { status=V3_CMS_RESOURCE; goto done; }
 for(int i=0;i<sk_X509_num(certs);i++) {
  int n=i2d_X509(sk_X509_value(certs,i),NULL);
  if(n<=0 || n>(int)MAX_CERT_BYTES) { status=V3_CMS_RESOURCE; goto done; }
  /* Bound every untrusted candidate key before chain or signature arithmetic. */
  EVP_PKEY *candidate_key=X509_get_pubkey(sk_X509_value(certs,i));
  int key_ok=permitted_key(candidate_key); EVP_PKEY_free(candidate_key);
  if(!key_ok) { status=V3_CMS_UNSUPPORTED; goto done; }
 }
 CMS_SignerInfo *si=sk_CMS_SignerInfo_value(signers,0);
 int sid_matches=0;
 for(int i=0;i<sk_X509_num(certs);i++)
  if(CMS_SignerInfo_cert_cmp(si,sk_X509_value(certs,i))==0) sid_matches++;
 if(sid_matches!=1) { status=V3_CMS_UNSUPPORTED; goto done; }
 if(CMS_set1_signers_certs(cms,certs,0)!=1) goto done;
 X509 *signer=NULL;
 CMS_SignerInfo_get0_algs(si,NULL,&signer,NULL,NULL);
 int algorithms_ok=signer && permitted_signer(si,signer,role);
 if(evidence) evidence->algorithm_and_attributes=algorithms_ok ? V3_CMS_PASSED : V3_CMS_FAILED;
 if(!algorithms_ok) { status=V3_CMS_UNSUPPORTED; goto done; }
 int pin_ok=role!=PINNED_INNER || approved_inner(signer,test_pin,test_pin_length);
 if(evidence) evidence->pin=pin_ok ? V3_CMS_PASSED : V3_CMS_FAILED;
 if(!pin_ok && !evidence && !inspection) { status=V3_CMS_UNSUPPORTED_SIGNER; goto done; }
 store=X509_STORE_new(); if(!store) { status=V3_CMS_RESOURCE; goto done; }
 int roots_ok=0;
#ifdef V3_CMS_TESTING
 if(test_root) roots_ok=add_root(store,test_root,test_root_length); else
#else
 (void)test_root; (void)test_root_length;
#endif
 roots_ok=production_roots(store,role);
 if(!roots_ok) { status=V3_CMS_UNTRUSTED; goto done; }
 status=verify_chain(store,signer,certs,role,test_pin,test_pin_length);
 if(evidence) {
  evidence->chain=status==V3_CMS_OK ? V3_CMS_PASSED :
   (status==V3_CMS_RESOURCE ? V3_CMS_UNCHECKED : V3_CMS_FAILED);
  evidence->temporal=status==V3_CMS_OK ? V3_CMS_PASSED :
   (status==V3_CMS_SIGNER_TIME_INVALID ? V3_CMS_FAILED : V3_CMS_UNCHECKED);
 }
 if(status!=V3_CMS_OK) goto done;
 only_signer=sk_X509_new_null(); verified=BIO_new(BIO_s_mem());
 if(!only_signer || !verified || !sk_X509_push(only_signer,signer)) { status=V3_CMS_RESOURCE; goto done; }
 /* Trust is already mandatory and pinned above. Only that signer may be used.
    Never skip CMS signature, signed attributes, or content-digest verification. */
 if(CMS_verify(cms,only_signer,NULL,NULL,verified,
    CMS_BINARY|CMS_NOINTERN|CMS_NO_SIGNER_CERT_VERIFY)!=1) {
  if(evidence) evidence->signature=V3_CMS_FAILED;
  status=V3_CMS_BAD_SIGNATURE; goto done;
 }
 if(evidence) {
  evidence->signature=V3_CMS_PASSED;
  unsigned int digest_length=0;
  if(X509_digest(signer,EVP_sha256(),evidence->signer_sha256,&digest_length)==1 && digest_length==32) {
   evidence->fingerprint_valid=1;
  } else memset(evidence->signer_sha256,0,sizeof(evidence->signer_sha256));
  evidence->profile_subject_marker=exact_cn(X509_get_subject_name(signer),"WWDR Provisioning Profile Signing");
  evidence->profile_issuer_marker=exact_cn(X509_get_issuer_name(signer),"Apple System Integration CA 4");
  /* Presence observations, NOT role authorization. No arbitrary OID output. */
  ASN1_OBJECT *profile_oid=OBJ_txt2obj("1.2.840.113635.100.12.19",1);
  ASN1_OBJECT *developer_oid=OBJ_txt2obj("1.2.840.113635.100.6.1.2",1);
  evidence->profile_extension_marker=profile_oid && X509_get_ext_by_OBJ(signer,profile_oid,-1)>=0;
  evidence->app_developer_marker=developer_oid && X509_get_ext_by_OBJ(signer,developer_oid,-1)>=0;
  ASN1_OBJECT_free(profile_oid); ASN1_OBJECT_free(developer_oid);
  /* Diagnostics NEVER reach content allocation, even for an approved pin. */
  status=pin_ok ? V3_CMS_OK : V3_CMS_UNSUPPORTED_SIGNER; goto done;
 }
 char *bytes=NULL; long n=BIO_get_mem_data(verified,&bytes);
 if(n<=0 || (size_t)n>MAX_CONTENT_BYTES) { status=V3_CMS_RESOURCE; goto done; }
 if(inspection) {
  /* Strong chain/math alone does NOT establish a provisioning-signing role.
     Return a distinct untrusted-content type, never an authenticated result. */
  unsigned int digest_length=0;
  if(X509_digest(signer,EVP_sha256(),inspection->signer_sha256,&digest_length)!=1 || digest_length!=32) {
   status=V3_CMS_RESOURCE; goto done;
  }
  inspection->untrusted_bytes=malloc((size_t)n);
  if(!inspection->untrusted_bytes) { status=V3_CMS_RESOURCE; goto done; }
  memcpy(inspection->untrusted_bytes,bytes,(size_t)n);
  inspection->length=(size_t)n; inspection->matches_approved_signer=(uint8_t)pin_ok;
  status=V3_CMS_OK; goto done;
 }
 result->bytes=malloc((size_t)n); if(!result->bytes) { status=V3_CMS_RESOURCE; goto done; }
 memcpy(result->bytes,bytes,(size_t)n); result->length=(size_t)n; status=V3_CMS_OK;
done:
 if(inspection && status!=V3_CMS_OK) v3_profile_cms_inspection_free(inspection);
 BIO_free(verified); sk_X509_free(only_signer); X509_STORE_free(store);
 sk_X509_pop_free(certs,X509_free); CMS_ContentInfo_free(cms);
 /* Error codes stay finite; callers never receive OpenSSL/provider/profile text. */
 return status;
}
v3_cms_status v3_profile_cms_verify_legacy_outer(const uint8_t *data,size_t n,v3_cms_content *out) {
 return authenticate(data,n,NULL,0,LEGACY_OUTER,NULL,0,out,NULL,NULL);
}
v3_cms_status v3_profile_cms_verify_pinned_inner(const uint8_t *data,size_t n,v3_cms_content *out) {
 return authenticate(data,n,NULL,0,PINNED_INNER,NULL,0,out,NULL,NULL);
}
void v3_profile_cms_content_free(v3_cms_content *result) {
 if(result) { free(result->bytes); result->bytes=NULL; result->length=0; }
}
#ifdef V3_CMS_TESTING
v3_cms_status v3_test_cms_authenticate(const uint8_t *data,size_t n,const uint8_t *root,size_t root_n,v3_cms_content *out) {
 if(!root) { if(out){out->bytes=NULL;out->length=0;} return V3_CMS_UNTRUSTED; }
 return authenticate(data,n,root,root_n,LEGACY_OUTER,NULL,0,out,NULL,NULL);
}
#endif

#ifdef V3_CMS_TESTING
v3_cms_status v3_test_inner_authenticate(const uint8_t *data,size_t n,const uint8_t *root,size_t root_n,const uint8_t *pin,size_t pin_n,v3_cms_content *out) {
 if(!root || !pin || !pin_n || pin_n>MAX_CERT_BYTES) { if(out){out->bytes=NULL;out->length=0;} return V3_CMS_UNTRUSTED; }
 return authenticate(data,n,root,root_n,PINNED_INNER,pin,pin_n,out,NULL,NULL);
}
#endif

void v3_profile_cms_diagnose_inner(const uint8_t *data,size_t n,v3_cms_signer_evidence *evidence) {
 if(!evidence) return;
 v3_cms_content out={NULL,0};
 (void)authenticate(data,n,NULL,0,PINNED_INNER,NULL,0,&out,evidence,NULL);
 v3_profile_cms_content_free(&out);
}
#ifdef V3_CMS_TESTING
void v3_test_cms_diagnose_inner(const uint8_t *data,size_t n,const uint8_t *root,size_t root_n,
 const uint8_t *pin,size_t pin_n,v3_cms_signer_evidence *evidence) {
 if(!evidence) return;
 memset(evidence,0,sizeof(*evidence));
 if(!root || !pin || !pin_n || pin_n>MAX_CERT_BYTES) return;
 v3_cms_content out={NULL,0};
 (void)authenticate(data,n,root,root_n,PINNED_INNER,pin,pin_n,&out,evidence,NULL);
 v3_profile_cms_content_free(&out);
}
#endif

/* This API does not authenticate an Apple profile, even on V3_CMS_OK. */
v3_cms_status v3_profile_cms_inspect_inner_cryptography(const uint8_t *data,size_t n,
 v3_cms_cryptographic_inspection *inspection) {
 if(!inspection) return V3_CMS_MALFORMED;
 v3_cms_content authenticated={NULL,0};
 v3_cms_status status=authenticate(data,n,NULL,0,PINNED_INNER,NULL,0,&authenticated,NULL,inspection);
 v3_profile_cms_content_free(&authenticated);
 return status;
}
void v3_profile_cms_inspection_free(v3_cms_cryptographic_inspection *inspection) {
 if(inspection) { free(inspection->untrusted_bytes); memset(inspection,0,sizeof(*inspection)); }
}
#ifdef V3_CMS_TESTING
v3_cms_status v3_test_cms_inspect_inner_cryptography(const uint8_t *data,size_t n,
 const uint8_t *root,size_t root_n,const uint8_t *pin,size_t pin_n,
 v3_cms_cryptographic_inspection *inspection) {
 if(!inspection) return V3_CMS_MALFORMED;
 memset(inspection,0,sizeof(*inspection));
 if(!root || !pin || !pin_n || pin_n>MAX_CERT_BYTES) return V3_CMS_UNTRUSTED;
 v3_cms_content authenticated={NULL,0};
 v3_cms_status status=authenticate(data,n,root,root_n,PINNED_INNER,pin,pin_n,&authenticated,NULL,inspection);
 v3_profile_cms_content_free(&authenticated);
 return status;
}
#endif
