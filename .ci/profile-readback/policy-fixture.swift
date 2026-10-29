import Foundation

func mustReject(_ body: () throws -> Void) {
    do { try body(); fatalError("Expected refusal") } catch {}
}
let bytes = Data([0x30, 0x01])
let accepted = try InstalledProfileReadback.decodeResponse(["Status": 0, "Payload": [bytes]])
precondition(accepted == [bytes])
let empty = try InstalledProfileReadback.decodeResponse(["Status": 0, "Payload": [Data]()])
precondition(empty.isEmpty)
let invalidStatuses: [Any] = [true, false, 1, -1, "0", NSNumber(value: 0.0), NSNull()]
for status in invalidStatuses {
    mustReject { try InstalledProfileReadback.requireSuccessStatus(["Status": status]) }
}
mustReject { try InstalledProfileReadback.requireSuccessStatus([:]) }
mustReject { _ = try InstalledProfileReadback.decodeResponse(["Status": 0]) }
mustReject { _ = try InstalledProfileReadback.decodeResponse(["Status": 0, "ProfileArray": [bytes]]) }
mustReject { _ = try InstalledProfileReadback.decodeResponse(["Status": 0, "Payload": [bytes, "not-data"]]) }
mustReject { _ = try InstalledProfileReadback.validate([Data()]) }
mustReject { _ = try InstalledProfileReadback.validate(Array(repeating: bytes, count: 4097)) }
mustReject { _ = try InstalledProfileReadback.validate([Data(count: 1_048_577)]) }
mustReject { _ = try InstalledProfileReadback.validate(Array(repeating: Data(count: 1_048_576), count: 33)) }
let largest = try InstalledProfileReadback.validate(Array(repeating: Data(count: 1_048_576), count: 32))
precondition(largest.count == 32)
var total = 0
mustReject { try InstalledProfileReadback.validateLength(-1, total: &total) }
precondition(total == 0)
print("PASS installed profile readback policy controls")
