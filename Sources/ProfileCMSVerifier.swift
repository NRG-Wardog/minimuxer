import Foundation
import LibimobiledeviceGateway

public typealias ProfileCMSCryptographicInspection = GatewayProfileCMSCryptographicInspection
public typealias ProfileCMSSignerEvidence = GatewayProfileCMSSignerEvidence
public typealias ProfileCMSVerificationError = GatewayProfileCMSVerificationError

/// Cryptographic decoding only. Callers must bind every outer authority field
/// to the independently authenticated inner profile before semantic comparison.
public enum ProfileCMSVerifier {
    /// Cryptography only; returned content is NOT authenticated profile authority.
    public static func inspectInnerCryptography(_ data: Data) throws -> ProfileCMSCryptographicInspection {
        try GatewayProfileCMSVerifier.inspectInnerCryptography(data)
    }

    public static func diagnoseInnerSigner(_ data: Data) -> ProfileCMSSignerEvidence {
        GatewayProfileCMSVerifier.diagnoseInnerSigner(data)
    }

    public static func authenticateOuter(_ data: Data) throws -> Data {
        try GatewayProfileCMSVerifier.authenticateOuter(data)
    }

    public static func authenticateInner(_ data: Data) throws -> Data {
        try GatewayProfileCMSVerifier.authenticateInner(data)
    }
}
