import Foundation
import CoreFoundation

/// Transport-level bounds and schema checks only. Presence is not proof of
/// launch-time profile selection or certificate trust. Never log profile data.
public enum InstalledProfileReadback {
    // Deliberate finite limits: oversized stores become unverified, not truncated.
    public static let maximumCount = 4096
    public static let maximumProfileBytes = 1_048_576
    public static let maximumTotalBytes = 33_554_432

    public static func requireSuccessStatus(_ response: [String: Any]) throws {
        guard let status = response["Status"] as? NSNumber,
              CFGetTypeID(status) != CFBooleanGetTypeID(),
              String(cString: status.objCType) != "f",
              String(cString: status.objCType) != "d",
              status.int64Value == 0 else {
            throw DeviceGatewayError(.serviceError, reason: "profile_response_status_invalid")
        }
    }

    public static func validateLength(_ length: Int, total: inout Int) throws {
        guard length > 0, length <= maximumProfileBytes,
              total <= maximumTotalBytes - length else {
            throw DeviceGatewayError(.serviceError, reason: "profile_readback_size_invalid")
        }
        total += length
    }

    public static func validate(_ profiles: [Data]) throws -> [Data] {
        guard profiles.count <= maximumCount else {
            throw DeviceGatewayError(.serviceError, reason: "profile_readback_count_invalid")
        }
        var total = 0
        for profile in profiles { try validateLength(profile.count, total: &total) }
        return profiles
    }

    public static func decodeResponse(_ response: [String: Any]) throws -> [Data] {
        try requireSuccessStatus(response)
        guard let payload = response["Payload"] as? [Data] else {
            throw DeviceGatewayError(.serviceError, reason: "profile_readback_payload_invalid")
        }
        return try validate(payload)
    }
}
