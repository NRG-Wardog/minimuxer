# Source-bound pairing crypto input

`DeviceGateway/Package.swift` explicitly selects
`GeneratedDependencies/RemotePairingKit` instead of fetching a mutable remote branch.
The SAR `ci/issue53-lts/embedded.py` adapter materializes the full source tree from
`mahee96/RemotePairingKit` commit `e3f70d16c0c551540a533a39d540e78e5b0a60a8`.
Only its binary-target URL/checksum is replaced with the separate generated
OpenSSL 3.5.9 XCFramework path. Pairing source implementation and licenses are not
changed. The original commit object, full Git tree/blob/mode inventory, exact
manifest delta and generated framework receipt are recorded and verified.

The old remote package pin must be removed explicitly from the application's
reviewed resolved-lock source when adopting this local package. Other resolved
pins remain exact; this does not authorize unrestricted resolver drift.

Both default and legacy providers are built in from the exact official 3.5.9
source archive. The embedded framework remains a distinct packaged file from
LiveContainer's host framework; no file deduplication occurs. Device loader
isolation and live pairing behavior are separate evidence, not implied by
successful SDK compilation, generated-file identity or macOS crypto probes.
