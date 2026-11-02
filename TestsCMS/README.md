# Provisioning CMS verification

Production source: `DeviceGateway/ProvisioningCMSCore`, called through the actual gateway and Minimuxer Swift wrappers. No caller-controlled roots, dates, verification flags or pin sets. Production does not define `V3_CMS_TESTING`.

`python3 -B TestsCMS/test_cms.py` compiles that exact C source and runs 33 adversarial/synthetic cases. Synthetic roots and pins exist only in a separately compiled test library; production rejects those identities. These optional development tests require Python cryptography; they are not the mandatory native runner and do not authorize installing an additional dependency.

Native qualification uses only Python standard library: `python3 -B TestsCMS/run_native.py --openssl-root /absolute/lts-host-build/install --openssl-cli /absolute/lts-host-build/apps/openssl --output /temporary/cms-native.json`. Build that test-only CLI with `make apps/openssl` in the existing verified host OpenSSL 3.5.9 build, without additional acquisition or product embedding. The runner checks exact header and linked-runtime/CLI versions, compiles production and separate test-macro libraries against the existing static archive (lib or lib64), and runs 58 named security checks. Synthetic keys exist only in an automatically removed temporary directory. `--development` is explicitly unqualified.

`verify_profile_cms.c` is a no-logging CLI for public-fixture integration. Arguments: `outer|inner input output`. Outputs must stay in temporary directories excluded from artifacts. Only authenticated bytes are written. SS tests/preservation_der owns hash-pinned public fixture acquisition and full Swift field-binding composition.

## Bounded policy

Legacy outer envelopes follow the published Apple iPhone provisioning signer role: exact three-cert Apple-root chain and leaf/issuer CN, strict constraints, SHA1/RSA allowed only for this historical envelope, no temporal check only for this documented role. This is not sufficient authorization for semantic comparison.

Inner CMS requires SHA256 or stronger, exact approved full leaf certificate DER (two explicitly reviewed public fixture signers), strict three-cert chain terminating at the compiled Apple Root G3, and current chain temporal validity. Unknown signer rotations are unsupported, not called an invalid signature. This deliberately bounded signer policy is not represented as Apple's full unpublished CoreTrust policy. Provenance files identify the official root URLs and exact approved public certificate fingerprints.

Both layers must authenticate independently, followed by complete outer/inner operative-field binding. The outer legacy SHA1 envelope is not a strong-authority claim; authorization comes from the strong inner signature and full binding. Existing profile/developer-certificate expiry checks remain independent. No network trust/revocation lookup or system trust store is used.

Bounds: 1 MiB input, 512 KiB output, 16 certificates of at most 64 KiB, one unambiguous signer SID, required unique contentType/messageDigest attributes, full-buffer CMS decoding. Additional bounded attributes are ignored as authority. Mandatory pinned chain validation precedes CMS signature, attribute and digest validation. Failure outputs are empty and errors finite.

## Diagnostic-only signer evidence

`diagnoseInnerSigner` / `v3_profile_cms_diagnose_inner` never return profile content,
never grant authority, and never change `authenticateInner` pin policy. A pin miss
still fails closed even when chain and signature diagnostics pass. The SHA256 is
of the public CMS signer certificate DER, **not** any app developer certificate
embedded in profile content; it must never be promoted to a pin automatically.

Evidence uses only unchecked/passed/failed checks for algorithm-and-attribute
policy, leaf pin, strict pinned-root chain, current chain temporal validity, and
CMS signature/attributes/content digest. A chain failure leaves signature
unchecked and temporal unchecked unless an actual expired/not-yet-valid chain
error was observed. This does not independently establish which certificate in
that chain failed. No-time legacy verification is never used for diagnostics.
Only after strict current Apple Root G3 chain verification and CMS verification
succeed may a signer digest or finite role observations be returned. Role fields
are observations of exact known subject/issuer CNs and known extension presence,
not proof of authorization or Apple's unpublished role policy. The app-developer
marker observes the known iPhone developer extension; its absence is not proof
that a certificate is not a developer certificate. No certificate, CN, OID,
profile content, owner data, or OpenSSL error text is emitted.

The diagnostic API shares all existing parsing/resource bounds. Its separate
synthetic-root/pin entrypoint exists only under `V3_CMS_TESTING`. The development
suite now has 29 cases; the standard-library native runner has 40 named checks,
including verified-but-unpinned, tamper, temporal, unsupported algorithm, reset,
role-observation non-authority, and untrusted-role non-disclosure checks.
System OpenSSL development passes do not qualify the pinned 3.5.9 build.

## Cryptographic inspection is not authentication

`ProfileCMSVerifier.inspectInnerCryptography` / the distinct C
`v3_profile_cms_inspect_inner_cryptography` return an explicitly **untrusted**
content result. They establish only current strict three-certificate Apple Root
G3 chain validity, bounded approved algorithm/attribute shapes, unique signer
SID, and CMS signature/content-digest correctness. They do not establish that
Apple authorized the signer for provisioning profiles, or that the input came
from Apple. A generic Apple-chain or app-developer certificate is not promoted
to a provisioning authority by this API. `matchesApprovedSigner` and signer
SHA256 are observations, not a pin-registration or trust-store mechanism.

The preservation integration must independently obtain an operation-bound,
non-forgeable exact-full-outer-profile Apple-origin receipt, check its current
account/team/owner binding, and complete outer-envelope authentication plus all
outer/inner operative-field bindings before using inspection content as authority.
The receipt must match the entire immutable outer CMS, not its hash alone, signer,
inner payload, UUID or team. Inspection results must never be cached, logged,
serialized, or used as a diagnostic shortcut for a future operation. This API
accepts no caller root, date, pin, flags, trust callback, or authorization boolean.

`authenticateInner` remains unchanged: unknown full-DER leaf pins are rejected
with empty authenticated content, even if separate cryptographic inspection
succeeds. `diagnoseInnerSigner` remains content-free. Inspection allocates its
separate untrusted content only after all chain and cryptographic checks; every
failure and explicit free zeroes all result fields. Synthetic injection exists
only in the separately compiled test library. The test suites now have 33
unittest cases and 58 exact-inventory native checks, including unknown-pin
non-authority, wrong roots, tampered signature/content, temporal validity,
algorithm/attribute, multiple/ambiguous SID, key/input bounds, and empty-output
regressions. System OpenSSL passes remain development-only, not 3.5.9 qualification.
