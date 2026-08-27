// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import XCTest
@testable import Inas

final class ShareStatsTests: XCTestCase {
    func testByteText() {
        XCTAssertEqual(ShareStats.byteText(0), "0 B")
        XCTAssertEqual(ShareStats.byteText(512), "512 B")
        XCTAssertEqual(ShareStats.byteText(1024), "1.0 KB")
        XCTAssertEqual(ShareStats.byteText(1536), "1.5 KB")
        XCTAssertEqual(ShareStats.byteText(4 * 1_048_576 + 200_000), "4.2 MB")
        XCTAssertEqual(ShareStats.byteText(18 * 1_073_741_824), "18 GB")
    }

    func testSpeedText() {
        XCTAssertEqual(ShareStats.speedText(0), "0 B/s")
        XCTAssertEqual(ShareStats.speedText(1024), "1.0 KB/s")
        XCTAssertEqual(ShareStats.speedText(4_400_000), "4.2 MB/s")
    }

    func testSummaryStates() {
        var stats = ShareStats()
        XCTAssertTrue(stats.isIdle)
        XCTAssertEqual(stats.summary, "Idle")

        stats = ShareStats(connections: 1, bytesPerSecond: 1_048_576)
        XCTAssertFalse(stats.isIdle)
        XCTAssertEqual(stats.summary, "1 connection · 1.0 MB/s")

        stats = ShareStats(connections: 3, activeTransfers: 1)
        XCTAssertEqual(stats.summary, "3 connections")

        stats = ShareStats(activeTransfers: 2, bytesPerSecond: 2_621_440)
        XCTAssertEqual(stats.summary, "Transferring · 2.5 MB/s")
    }

    func testEquatableDefaults() {
        XCTAssertEqual(ShareStats(), ShareStats())
    }
}
