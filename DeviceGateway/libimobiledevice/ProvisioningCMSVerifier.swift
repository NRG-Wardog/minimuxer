import Foundation
import ProvisioningCMSCore

/// Finite diagnostics; unsupported rotations are not invalid-signature claims.
public enum GatewayProfileCMSVerificationError: Error {
    case unsupportedSigner, signerTimeInvalid, verificationFailed, unsupportedRepresentation
}

public enum GatewayProfileCMSVerifier {
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
