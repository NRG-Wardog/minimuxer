# Provisioning CMS verification

Production source: `DeviceGateway/ProvisioningCMSCore`, called through the actual gateway and Minimuxer Swift wrappers. No caller-controlled roots, dates, verification flags or pin sets. Production does not define `V3_CMS_TESTING`.

`python3 -B TestsCMS/test_cms.py` compiles that exact C source and runs 23 adversarial/synthetic cases. Synthetic roots and pins exist only in a separately compiled test library; production rejects those identities. These optional development tests require Python cryptography; they are not the mandatory native runner and do not authorize installing an additional dependency.

Native qualification uses only Python standard library: `python3 -B TestsCMS/run_native.py --openssl-root /absolute/lts-host-build/install --openssl-cli /absolute/lts-host-build/apps/openssl --output /temporary/cms-native.json`. Build that test-only CLI with `make apps/openssl` in the existing verified host OpenSSL 3.5.9 build, without additional acquisition or product embedding. The runner checks exact header and linked-runtime/CLI versions, compiles production and separate test-macro libraries against the existing static archive (lib or lib64), and runs 28 named security checks. Synthetic keys exist only in an automatically removed temporary directory. `--development` is explicitly unqualified.

`verify_profile_cms.c` is a no-logging CLI for public-fixture integration. Arguments: `outer|inner input output`. Outputs must stay in temporary directories excluded from artifacts. Only authenticated bytes are written. SS tests/preservation_der owns hash-pinned public fixture acquisition and full Swift field-binding composition.

## Bounded policy

Legacy outer envelopes follow the published Apple iPhone provisioning signer role: exact three-cert Apple-root chain and leaf/issuer CN, strict constraints, SHA1/RSA allowed only for this historical envelope, no temporal check only for this documented role. This is not sufficient authorization for semantic comparison.

Inner CMS requires SHA256 or stronger, exact approved full leaf certificate DER (two explicitly reviewed public fixture signers), strict three-cert chain terminating at the compiled Apple Root G3, and current chain temporal validity. Unknown signer rotations are unsupported, not called an invalid signature. This deliberately bounded signer policy is not represented as Apple's full unpublished CoreTrust policy. Provenance files identify the official root URLs and exact approved public certificate fingerprints.

Both layers must authenticate independently, followed by complete outer/inner operative-field binding. The outer legacy SHA1 envelope is not a strong-authority claim; authorization comes from the strong inner signature and full binding. Existing profile/developer-certificate expiry checks remain independent. No network trust/revocation lookup or system trust store is used.

Bounds: 1 MiB input, 512 KiB output, 16 certificates of at most 64 KiB, one unambiguous signer SID, required unique contentType/messageDigest attributes, full-buffer CMS decoding. Additional bounded attributes are ignored as authority. Mandatory pinned chain validation precedes CMS signature, attribute and digest validation. Failure outputs are empty and errors finite.
