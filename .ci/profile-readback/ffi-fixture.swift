// Fixture replaces external C allocation/service effects only; the production
// syncReadInstalledProvisioningProfiles method is inserted verbatim below.
import Foundation

typealias IdeviceGatewayError = DeviceGatewayError
var mode = "normal"
var arrayFrees = 0
var errorFrees = 0
var serviceFrees = 0
struct IdeviceFfiError {}
let nativeError = UnsafeMutablePointer<IdeviceFfiError>.allocate(capacity: 1)
var bytesAllocated = 0
func misagent_connect_rsd() {}
func misagent_connect() {}
func misagent_client_free(_ client: Int) { serviceFrees += 1 }
func idevice_error_free(_ error: UnsafeMutablePointer<IdeviceFfiError>) { errorFrees += 1 }
func misagent_read_profiles(_ client: OpaquePointer,
                      _ output: inout UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                      _ lengths: inout UnsafeMutablePointer<Int>?, _ count: inout Int) -> UnsafeMutablePointer<IdeviceFfiError>? {
    defer { serviceFrees += 1 }
    if mode == "native-error" { return nativeError }
    if mode == "empty" { count = 0; return nil }
    count = mode == "too-many" ? 4097 : 2
    let out = UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>.allocate(capacity: count)
    let lens = UnsafeMutablePointer<Int>.allocate(capacity: count)
    for index in 0..<count {
        if mode == "null-item" && index == 1 { out[index] = nil; lens[index] = 2; continue }
        let length = mode == "oversized" && index == 1 ? 1_048_577 : 2
        let bytes = UnsafeMutablePointer<UInt8>.allocate(capacity: length)
        bytes.initialize(repeating: UInt8(index % 255), count: length)
        bytesAllocated += 1
        out[index] = bytes; lens[index] = length
    }
    output = out; lengths = lens
    return nil
}
func misagent_free_profiles(_ profiles: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                            _ lengths: UnsafeMutablePointer<Int>?, _ count: Int) {
    if let profiles, let lengths {
        for index in 0..<count {
            if let bytes = profiles[index] { bytes.deallocate(); bytesAllocated -= 1 }
        }
        profiles.deallocate(); lengths.deallocate(); arrayFrees += 1
    }
}
func misagent_read_profiles_rsd(_ adapter: OpaquePointer, _ handshake: OpaquePointer,
                      _ output: inout UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                      _ lengths: inout UnsafeMutablePointer<Int>?, _ count: inout Int) -> UnsafeMutablePointer<IdeviceFfiError>? {
    misagent_read_profiles(adapter, &output, &lengths, &count)
}
final class Gateway {
    func verifyInitialized() throws {}
    enum Pairing { case lockdown, rppairing }
    var pairingFileType = Pairing.lockdown
    var usesCoreDevice = false
    var batchCount = 1
    var adapter: OpaquePointer? = OpaquePointer(bitPattern: 1)
    var handshake: OpaquePointer? = OpaquePointer(bitPattern: 2)
    func withReadbackTCPProvider<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
        try body(OpaquePointer(bitPattern: 3)!)
    }
    // PRODUCTION_SYNC_METHOD
    func read() throws -> [Data] { try syncReadInstalledProvisioningProfiles() }
}
let gateway = Gateway()
let result = try gateway.read()
precondition(result == [Data([0,0]),Data([1,1])])
precondition(bytesAllocated == 0 && arrayFrees == 1 && serviceFrees == 1)
// Data remains owned after native allocations have been released.
precondition(result[1][0] == 1)
for failure in ["null-item", "oversized", "too-many", "native-error"] {
    mode = failure
    do { _ = try gateway.read(); fatalError("Expected failure") } catch {}
    precondition(bytesAllocated == 0)
}
precondition(arrayFrees == 4 && errorFrees == 1 && serviceFrees == 5)
mode = "empty"
let empty = try gateway.read()
precondition(empty.isEmpty && bytesAllocated == 0 && serviceFrees == 6)

gateway.batchCount = 0
let tcpCalls = serviceFrees
do { _ = try gateway.read(); fatalError("Expected TCP absent batch refusal") } catch {}
precondition(serviceFrees == tcpCalls)
gateway.batchCount = 1
gateway.pairingFileType = .rppairing
gateway.batchCount = 0
let callsBefore = serviceFrees
do { _ = try gateway.read(); fatalError("Expected absent batch refusal") } catch {}
precondition(serviceFrees == callsBefore)
gateway.batchCount = 1
gateway.adapter = nil
do { _ = try gateway.read(); fatalError("Expected absent transport refusal") } catch {}
precondition(serviceFrees == callsBefore)
gateway.adapter = OpaquePointer(bitPattern: 1)
mode = "normal"
let rsd = try gateway.read()
precondition(rsd == result && bytesAllocated == 0)
nativeError.deallocate()

print("PASS actual idevice profile readback ownership controls")
