//
//  DeviceProvider.swift
//  Minimuxer
//
//  Created by Magesh K on 20/09/26.
//  Copyright © 2026 SideStore. All rights reserved.
//

import Foundation
import DeviceGatewayAPI
import MinimuxerCommon

final class DeviceProvider: @unchecked Sendable {
    private let lock = NSLock()
    private var cachedGateway: any DeviceGatewayAPI
    private struct Configuration {
        let gateway: any DeviceGatewayAPI
        let remotePairingPort: UInt16
    }
    private var pendingConfiguration: Configuration?
    private var activeBatches = 0
    private var endingBatches = 0

    var gateway: any DeviceGatewayAPI {
        lock.withLock { cachedGateway }
    }

    init(gateway: any DeviceGatewayAPI) {
        self.cachedGateway = gateway
    }

    // Coalesce backend and port as one desired configuration. In particular, a
    // port-only update must target a pending backend, never its active predecessor.
    func setConfiguration(gateway newGateway: (any DeviceGatewayAPI)? = nil,
                          remotePairingPort: UInt16) {
        lock.withLock {
            pendingConfiguration = Configuration(
                gateway: newGateway ?? pendingConfiguration?.gateway ?? cachedGateway,
                remotePairingPort: remotePairingPort)
            applyPendingConfigurationIfIdle()
        }
    }

    // The caller holds lock; native end callbacks have completed before idle.
    private func applyPendingConfigurationIfIdle() {
        guard activeBatches == 0, let pendingConfiguration else { return }
        pendingConfiguration.gateway.setPort(pendingConfiguration.remotePairingPort, for: .rppairing)
        cachedGateway = pendingConfiguration.gateway
        self.pendingConfiguration = nil
    }

    func beginTransportBatch() async {
        let selected = lock.withLock {
            activeBatches += 1
            return cachedGateway
        }
        await selected.beginTransportBatch()
    }

    func endTransportBatch() async {
        let selected: (any DeviceGatewayAPI)? = lock.withLock {
            guard activeBatches > endingBatches else { return nil }
            endingBatches += 1
            return cachedGateway
        }
        guard let selected else { return }
        await selected.endTransportBatch()
        lock.withLock {
            endingBatches -= 1
            activeBatches -= 1
            applyPendingConfigurationIfIdle()
        }
    }
}
