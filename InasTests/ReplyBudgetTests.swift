// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import XCTest
@testable import Inas

final class ReplyBudgetTests: XCTestCase {
    private let t0 = Date(timeIntervalSince1970: 1_700_000_000)

    func testBurstThenDrain() {
        var budget = WindowsDiscovery.ReplyBudget()
        XCTAssertTrue(budget.allow(ip: "10.0.0.1", now: t0))
        XCTAssertTrue(budget.allow(ip: "10.0.0.1", now: t0))
        XCTAssertTrue(budget.allow(ip: "10.0.0.1", now: t0))
        XCTAssertFalse(budget.allow(ip: "10.0.0.1", now: t0), "burst of 3 is exhausted")
    }

    func testRefill() {
        var budget = WindowsDiscovery.ReplyBudget()
        for _ in 0..<3 {
            XCTAssertTrue(budget.allow(ip: "10.0.0.2", now: t0))
        }
        XCTAssertFalse(budget.allow(ip: "10.0.0.2", now: t0))
        // 5 tokens/s * 0.2 s = 1 token.
        XCTAssertTrue(budget.allow(ip: "10.0.0.2", now: t0.addingTimeInterval(0.2)))
        XCTAssertFalse(budget.allow(ip: "10.0.0.2", now: t0.addingTimeInterval(0.2)))
    }

    func testPerIPIsolation() {
        var budget = WindowsDiscovery.ReplyBudget()
        for _ in 0..<3 {
            XCTAssertTrue(budget.allow(ip: "10.0.0.3", now: t0))
        }
        XCTAssertFalse(budget.allow(ip: "10.0.0.3", now: t0))
        XCTAssertTrue(budget.allow(ip: "10.0.0.4", now: t0), "a second address keeps its own burst")
    }

    func testEvictsOldestWhenOverCap() {
        var budget = WindowsDiscovery.ReplyBudget()
        for i in 0..<32 {
            let ip = "10.0.0.\(i)"
            XCTAssertTrue(budget.allow(ip: ip, now: t0.addingTimeInterval(Double(i))))
        }
        XCTAssertEqual(budget.table.count, 32)
        XCTAssertTrue(budget.allow(ip: "10.0.1.1", now: t0.addingTimeInterval(40)))
        XCTAssertEqual(budget.table.count, 32)
        XCTAssertNil(budget.table["10.0.0.0"], "oldest address is evicted")
        XCTAssertNotNil(budget.table["10.0.1.1"])
        XCTAssertNotNil(budget.table["10.0.0.1"])
    }
}
