# In-memory installed-profile readback

`REQUIRE_NATIVE_PROFILE_READBACK=1 python .ci/test-profile-readback.py` requires
Swift and runs the actual policy plus the actual idevice gateway synchronous
method with fake external service/allocation effects. It verifies copied bytes
survive native frees, buffers/service/error are freed on success and failure,
strict status/payload rejection, and finite count/per-profile/aggregate limits.
Structural controls cover real gateway dispatch and no mutation/export calls.

This does not execute a physical device, prove OS launch-time profile selection,
or validate certificate trust. Full production compilation must cover both
native gateways. Rust `profile_readback_tests` in the paired idevice source verify
strict protocol decoding and bounds before FFI duplication. Transport frame
allocation remains the underlying transport's behavior.

Returned profiles remain in memory and must never be included in support logs.
Callers retain the original transport batch through completion and compare exact
expected profiles; readback errors do not authorize an installation retry.

The idevice backend uses a new readback-only atomic FFI transaction, with a
10-second Tokio deadline covering service connect and CopyAll. The owned query
client is dropped before returning; borrowed provider/adapter/handshake survives.
RSD requires an existing owned batch and prepared handles, never builds/retries a
tunnel in this observation. TCP provider construction parses local data only.
The libimobiledevice backend explicitly reports readback unsupported because its
available connect/send/query APIs provide no total native deadline. Existing
installation and diagnostic export are not removed. Do not label that backend's
refresh verified when observation is unsupported.

No overall refresh or FFI queue-admission deadline is claimed. The read-only
transaction timeout does not change the signing/installation mutation timeouts.
