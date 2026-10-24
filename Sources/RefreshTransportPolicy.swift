import Foundation
public import MinimuxerCommon

public enum RefreshTransport: String, Sendable {
    case coreDevice = "COREDEVICE_LOCALDEVVPN"
    case lockdownIPSec = "LOCKDOWN_IPSEC"
    case lockdownLegacy = "LOCKDOWN_LEGACY"
    case remotePairing = "REMOTE_PAIRING"
    case proxy = "UPSTREAM_PROXY"
    case unavailable = "FAILED_NO_VALID_TRANSPORT"
}

// Internal classification from the exact policy input snapshot. No new public
// error case or string matching is needed at the app/wire boundary.
internal enum RefreshTransportUnavailableCause: Equatable, Sendable {
    case pairingUnavailable
    case connectionModeNotConfigured
    case missingRequiredVPNInterface
    case unsupportedBackend
}

public struct RefreshTransportDecision: Sendable {
    public let transport: RefreshTransport
    public let reason: String
    internal let unavailableCause: RefreshTransportUnavailableCause?

    internal init(transport: RefreshTransport, reason: String,
                  unavailableCause: RefreshTransportUnavailableCause? = nil) {
        self.transport = transport
        self.reason = reason
        self.unavailableCause = unavailableCause
    }
}

public enum RefreshTransportPolicy {
    public static func select(modernOS: Bool, mode: DeviceConnectionMode,
                              pairing: PairingProtocol, utun: Bool, ipsec: Bool,
                              coreDeviceSupported: Bool) -> RefreshTransportDecision {
        if pairing == .unknown {
            return .init(transport: .unavailable, reason: "No valid pairing record", unavailableCause: .pairingUnavailable)
        }
        if mode == .remoteServer {
            return .init(transport: .proxy, reason: "Explicit upstream remote-server configuration")
        }
        guard mode == .localVPN else {
            return .init(transport: .unavailable, reason: "Local VPN requires a reachable utun route; IPSec alone is not an upstream local-VPN route", unavailableCause: .connectionModeNotConfigured)
        }
        guard utun else {
            // Do not let a missing interface mask an unsupported backend. A
            // modern Lockdown backend without CoreDevice needs IPSec as well;
            // merely enabling a utun is not a supported route in this snapshot.
            let cause: RefreshTransportUnavailableCause =
                modernOS && pairing == .lockdown && !coreDeviceSupported && !ipsec
                ? .unsupportedBackend : .missingRequiredVPNInterface
            return .init(transport: .unavailable, reason: "Local VPN requires a reachable utun route; IPSec alone is not an upstream local-VPN route", unavailableCause: cause)
        }
        if pairing == .rppairing {
            return .init(transport: .remotePairing, reason: "RemotePairing-only record; not CoreDevice proof")
        }
        if modernOS && coreDeviceSupported {
            return .init(transport: .coreDevice, reason: "iOS>=26.4 local VPN with Lockdown record and patched CoreDevice backend; initialization pending")
        }
        if ipsec {
            return .init(transport: .lockdownIPSec, reason: "Upstream Lockdown with utun and IPSec interfaces")
        }
        if !modernOS {
            return .init(transport: .lockdownLegacy, reason: "Preserve upstream Lockdown below iOS26.4")
        }
        return .init(transport: .unavailable, reason: "Selected backend has no CoreDevice implementation and IPSec is absent", unavailableCause: .unsupportedBackend)
    }
}
