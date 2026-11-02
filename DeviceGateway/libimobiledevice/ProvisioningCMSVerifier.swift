import Foundation
import ProvisioningCMSCore

/// Finite diagnostics; unsupported rotations are not invalid-signature claims.
public enum GatewayProfileCMSVerificationError: Error {
    case unsupportedSigner, signerTimeInvalid, verificationFailed, unsupportedRepresentation
}

/// Observations only: neither this evidence nor its fingerprint grants authority.
public struct GatewayProfileCMSSignerEvidence {
    public enum Check: String { case unchecked, passed, failed }
    public let algorithmAndAttributes: Check
    public let pin: Check
    public let chain: Check
    public let temporal: Check
    public let signature: Check
    /// Only observed when chain, temporal and signature are passed; otherwise false means unchecked.
    public let profileSubjectMarker: Bool
    public let profileIssuerMarker: Bool
    public let profileExtensionMarker: Bool
    public let appDeveloperMarker: Bool
    /// Public CMS signer certificate DER digest, never an app DeveloperCertificate.
    /// Present only after pinned-root/current-chain and CMS verification succeed.
    public let signerSHA256: String?

    fileprivate init(_ raw: v3_cms_signer_evidence) {
        func check(_ value: v3_cms_check) -> Check {
            switch value {
            case V3_CMS_PASSED: return .passed
            case V3_CMS_FAILED: return .failed
            default: return .unchecked
            }
        }
        algorithmAndAttributes = check(raw.algorithm_and_attributes)
        pin = check(raw.pin)
        chain = check(raw.chain)
        temporal = check(raw.temporal)
        signature = check(raw.signature)
        profileSubjectMarker = raw.profile_subject_marker != 0
        profileIssuerMarker = raw.profile_issuer_marker != 0
        profileExtensionMarker = raw.profile_extension_marker != 0
        appDeveloperMarker = raw.app_developer_marker != 0
        var digest = raw.signer_sha256
        signerSHA256 = raw.fingerprint_valid == 1 ? withUnsafeBytes(of: &digest) {
            $0.map { String(format: "%02x", $0) }.joined()
        } : nil
    }
}

/// Cryptographic checks only, NOT a provisioning authority or authenticated profile.
/// Never promote these bytes without independent, operation-bound provenance of
/// the exact full outer profile and complete outer/inner operative-field binding.
public struct GatewayProfileCMSCryptographicInspection {
    public let untrustedContent: Data
    public let signerSHA256: String
    public let matchesApprovedSigner: Bool
    fileprivate init(content: Data, signerSHA256: String, matchesApprovedSigner: Bool) {
        self.untrustedContent = content
        self.signerSHA256 = signerSHA256
        self.matchesApprovedSigner = matchesApprovedSigner
    }
}

public enum GatewayProfileCMSVerifier {
    /// Requires strict current G3 chain, strong algorithm, unique SID and CMS math.
    /// Does NOT establish profile-signing role or Apple-origin provenance.
    public static func inspectInnerCryptography(_ data: Data) throws -> GatewayProfileCMSCryptographicInspection {
        var output = v3_cms_cryptographic_inspection()
        defer { v3_profile_cms_inspection_free(&output) }
        let status = data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
            v3_profile_cms_inspect_inner_cryptography(bytes.bindMemory(to: UInt8.self).baseAddress,
                                                     bytes.count, &output)
        }
        switch status {
        case V3_CMS_OK:
            guard let bytes = output.untrusted_bytes, output.length > 0 else {
                throw GatewayProfileCMSVerificationError.verificationFailed
            }
            var digest = output.signer_sha256
            let sha256 = withUnsafeBytes(of: &digest) { $0.map { String(format: "%02x", $0) }.joined() }
            return GatewayProfileCMSCryptographicInspection(content: Data(bytes: bytes, count: output.length),
                signerSHA256: sha256, matchesApprovedSigner: output.matches_approved_signer == 1)
        case V3_CMS_SIGNER_TIME_INVALID:
            throw GatewayProfileCMSVerificationError.signerTimeInvalid
        case V3_CMS_MALFORMED, V3_CMS_UNSUPPORTED, V3_CMS_RESOURCE:
            throw GatewayProfileCMSVerificationError.unsupportedRepresentation
        default:
            throw GatewayProfileCMSVerificationError.verificationFailed
        }
    }

    /// Diagnostic-only. Returns no profile content and cannot authorize renewal.
    public static func diagnoseInnerSigner(_ data: Data) -> GatewayProfileCMSSignerEvidence {
        var evidence = v3_cms_signer_evidence()
        data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
            v3_profile_cms_diagnose_inner(bytes.bindMemory(to: UInt8.self).baseAddress,
                                        bytes.count, &evidence)
        }
        return GatewayProfileCMSSignerEvidence(evidence)
    }

    /// Legacy envelope authentication alone is not preservation authority.
    public static func authenticateOuter(_ data: Data) throws -> Data {
        try authenticate(data, inner: false)
    }

    /// Requires an explicitly approved full signer certificate and current chain validity.
    public static func authenticateInner(_ data: Data) throws -> Data {
        try authenticate(data, inner: true)
    }

    private static func authenticate(_ data: Data, inner: Bool) throws -> Data {
        var output = v3_cms_content(bytes: nil, length: 0)
        defer { v3_profile_cms_content_free(&output) }
        let status = data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
            let pointer = bytes.bindMemory(to: UInt8.self).baseAddress
            return inner
                ? v3_profile_cms_verify_pinned_inner(pointer, bytes.count, &output)
                : v3_profile_cms_verify_legacy_outer(pointer, bytes.count, &output)
        }
        switch status {
        case V3_CMS_OK:
            guard let bytes = output.bytes, output.length > 0 else {
                throw GatewayProfileCMSVerificationError.verificationFailed
            }
            return Data(bytes: bytes, count: output.length)
        case V3_CMS_UNSUPPORTED_SIGNER:
            throw GatewayProfileCMSVerificationError.unsupportedSigner
        case V3_CMS_SIGNER_TIME_INVALID:
            throw GatewayProfileCMSVerificationError.signerTimeInvalid
        case V3_CMS_MALFORMED, V3_CMS_UNSUPPORTED, V3_CMS_RESOURCE:
            throw GatewayProfileCMSVerificationError.unsupportedRepresentation
        default:
            throw GatewayProfileCMSVerificationError.verificationFailed
        }
    }
}
