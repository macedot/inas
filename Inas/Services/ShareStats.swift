// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import Foundation

/// Aggregated, anonymous activity counters for the running share.
/// Filled from the SMB server's atomic counters once per second.
struct ShareStats: Equatable {
    var connections: Int = 0
    var peakClients: Int = 0
    var activeTransfers: Int = 0
    var bytesRead: UInt64 = 0
    var bytesWritten: UInt64 = 0
    var bytesPerSecond: Double = 0

    var isIdle: Bool { connections == 0 && activeTransfers == 0 }

    var summary: String {
        if isIdle { return "Idle" }
        let rate = bytesPerSecond > 0 ? " · \(Self.speedText(bytesPerSecond))" : ""
        if connections > 0 {
            return "\(connections) connection\(connections == 1 ? "" : "s")\(rate)"
        }
        return "Transferring\(rate)"
    }

    static func speedText(_ bytesPerSecond: Double) -> String {
        "\(byteText(UInt64(bytesPerSecond)))/s"
    }

    /// Human byte size with one decimal below 10 and none above (e.g. 512 B, 4.2 MB, 18 GB).
    static func byteText(_ bytes: UInt64) -> String {
        let units: [(String, UInt64)] = [("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)]
        for (name, size) in units where bytes >= size {
            let value = Double(bytes) / Double(size)
            let digits = value < 10 ? 1 : 0
            return String(format: "%.\(digits)f %@", value, name)
        }
        return "\(bytes) B"
    }
}
