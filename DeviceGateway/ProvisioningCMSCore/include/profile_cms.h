#ifndef PROFILE_CMS_H
#define PROFILE_CMS_H
#include <stddef.h>
#include <stdint.h>
typedef enum { V3_CMS_OK=0, V3_CMS_MALFORMED=1, V3_CMS_UNSUPPORTED=2,
 V3_CMS_UNTRUSTED=3, V3_CMS_BAD_SIGNATURE=4, V3_CMS_RESOURCE=5, V3_CMS_UNSUPPORTED_SIGNER=6, V3_CMS_SIGNER_TIME_INVALID=7 } v3_cms_status;
typedef struct { uint8_t *bytes; size_t length; } v3_cms_content;
/* Evidence is diagnostic only. No certificate bytes, names, OIDs or content. */
typedef enum { V3_CMS_UNCHECKED=0, V3_CMS_PASSED=1, V3_CMS_FAILED=2 } v3_cms_check;
typedef struct {
 v3_cms_check algorithm_and_attributes, pin, chain, temporal, signature;
 uint8_t profile_subject_marker, profile_issuer_marker, profile_extension_marker;
 uint8_t app_developer_marker, fingerprint_valid;
 uint8_t signer_sha256[32];
} v3_cms_signer_evidence;
/* Never authenticates or returns content. Hash/role observations require a
   strict pinned-root current chain AND valid CMS signature/digest/attributes. */
void v3_profile_cms_diagnose_inner(const uint8_t *, size_t, v3_cms_signer_evidence *);
/* No caller-supplied anchors, verify flags, dates, or network callbacks. */
/* Legacy outer proof is NOT strong authority: mandatory strong inner verification
   and complete field binding are required before any preservation decision. */
v3_cms_status v3_profile_cms_verify_legacy_outer(const uint8_t *, size_t, v3_cms_content *);
v3_cms_status v3_profile_cms_verify_pinned_inner(const uint8_t *, size_t, v3_cms_content *);
void v3_profile_cms_content_free(v3_cms_content *);
#ifdef V3_CMS_TESTING
void v3_test_cms_diagnose_inner(const uint8_t *, size_t,
 const uint8_t *, size_t, const uint8_t *, size_t, v3_cms_signer_evidence *);
/* Not compiled/exported by the production target. Synthetic test anchors only. */
v3_cms_status v3_test_cms_authenticate(const uint8_t *, size_t,
 const uint8_t *, size_t, v3_cms_content *);
v3_cms_status v3_test_inner_authenticate(const uint8_t *, size_t,
 const uint8_t *, size_t, const uint8_t *, size_t, v3_cms_content *);
#endif
#endif
