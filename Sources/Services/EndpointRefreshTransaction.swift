import Foundation

// V3_ENDPOINT_TRANSACTION_BEGIN
/// Coalesces the entire scan + endpoint publication, not only the interface scan.
/// A cancelled waiter never cancels the shared observer-owned operation.
actor EndpointRefreshTransaction {
    private var running: (UUID, Task<Bool, Never>)?
    func run(_ operation: @escaping @Sendable () async -> Bool) async -> Bool {
        if let running { return await running.1.value }
        let id = UUID()
        let task = Task { await operation() }
        running = (id, task)
        let result = await task.value
        if running?.0 == id { running = nil }
        return result
    }
}
// V3_ENDPOINT_TRANSACTION_END
