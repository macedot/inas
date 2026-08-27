// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import XCTest
@testable import Inas

final class AuthThrottleTests: XCTestCase {
    private func slot(_ ip: UInt32 = 0x0A000001) -> inas_auth_slot {
        inas_auth_slot(ip: ip, fails: 0, window_start: 0, locked_until: 0, last_used: 0)
    }

    func testLocksAfterMoreThanTenFailsInWindow() {
        var s = slot()
        let now: time_t = 1_000_000
        for i in 1...10 {
            XCTAssertEqual(inas_auth_on_failure(&s, now), 0, "fail \(i) should not lock")
        }
        XCTAssertEqual(inas_auth_on_failure(&s, now), 1)
        XCTAssertEqual(inas_auth_is_locked(&s, now), 1)
        XCTAssertEqual(inas_auth_is_locked(&s, now + 299), 1)
        XCTAssertEqual(inas_auth_is_locked(&s, now + 300), 0)
    }

    func testWindowResetsAfterSixtySeconds() {
        var s = slot(0x0A000002)
        let now: time_t = 2_000_000
        for _ in 1...10 {
            XCTAssertEqual(inas_auth_on_failure(&s, now), 0)
        }
        XCTAssertEqual(inas_auth_on_failure(&s, now + 60), 0)
        XCTAssertEqual(s.fails, 1)
    }

    func testSuccessClearsLock() {
        var s = slot(0x0A000003)
        let now: time_t = 3_000_000
        for _ in 1...11 {
            _ = inas_auth_on_failure(&s, now)
        }
        XCTAssertEqual(inas_auth_is_locked(&s, now), 1)
        inas_auth_on_success(&s)
        XCTAssertEqual(inas_auth_is_locked(&s, now), 0)
        XCTAssertEqual(s.fails, 0)
    }

    func testLookupReusesSlotAndEvictsOldest() {
        var table = [inas_auth_slot](repeating: slot(0), count: 4)
        let now: time_t = 4_000_000
        table.withUnsafeMutableBufferPointer { buf in
            XCTAssertEqual(inas_auth_lookup(buf.baseAddress, 4, 1, now)?.pointee.ip, 1)
            XCTAssertEqual(inas_auth_lookup(buf.baseAddress, 4, 2, now + 1)?.pointee.ip, 2)
            XCTAssertEqual(inas_auth_lookup(buf.baseAddress, 4, 3, now + 2)?.pointee.ip, 3)
            XCTAssertEqual(inas_auth_lookup(buf.baseAddress, 4, 4, now + 3)?.pointee.ip, 4)
            XCTAssertEqual(inas_auth_lookup(buf.baseAddress, 4, 5, now + 4)?.pointee.ip, 5)
            let ips = (0..<4).map { buf[$0].ip }
            XCTAssertFalse(ips.contains(1))
            XCTAssertTrue(ips.contains(5))
        }
    }

    private func globalSlot() -> inas_auth_global {
        inas_auth_global(fails: 0, window_start: 0, backoff_until: 0, streak: 0)
    }

    func testGlobalLocksAfterMoreThanOneHundredFailsInWindow() {
        var g = globalSlot()
        let now: time_t = 5_000_000
        for i in 1...100 {
            inas_auth_global_record_failure(&g, now)
            XCTAssertEqual(inas_auth_global_locked(&g, now), 0, "fail \(i) should not lock")
        }
        inas_auth_global_record_failure(&g, now)
        XCTAssertEqual(inas_auth_global_locked(&g, now), 1)
        XCTAssertEqual(inas_auth_global_locked(&g, now + 59), 1)
        XCTAssertEqual(inas_auth_global_locked(&g, now + 60), 0)
        XCTAssertEqual(g.streak, 1)
    }

    func testGlobalWindowResetsAfterFiveMinutes() {
        var g = globalSlot()
        let now: time_t = 6_000_000
        for _ in 1...100 {
            inas_auth_global_record_failure(&g, now)
        }
        XCTAssertEqual(g.fails, 100)
        inas_auth_global_record_failure(&g, now + 300)
        XCTAssertEqual(g.fails, 1)
        XCTAssertEqual(inas_auth_global_locked(&g, now + 300), 0)
    }

    func testGlobalBackoffDoublesThenCaps() {
        var g = globalSlot()
        var now: time_t = 7_000_000
        func trigger() {
            for _ in 1...101 {
                inas_auth_global_record_failure(&g, now)
            }
        }
        trigger()
        XCTAssertEqual(g.streak, 1)
        XCTAssertEqual(inas_auth_global_locked(&g, now + 59), 1)
        XCTAssertEqual(inas_auth_global_locked(&g, now + 60), 0)

        now += 60
        trigger()
        XCTAssertEqual(g.streak, 2)
        XCTAssertEqual(inas_auth_global_locked(&g, now + 119), 1)
        XCTAssertEqual(inas_auth_global_locked(&g, now + 120), 0)

        now += 120
        trigger()
        XCTAssertEqual(g.streak, 3)
        XCTAssertEqual(inas_auth_global_locked(&g, now + 239), 1)
        XCTAssertEqual(inas_auth_global_locked(&g, now + 240), 0)

        now += 240
        trigger()
        XCTAssertEqual(g.streak, 4)
        XCTAssertEqual(inas_auth_global_locked(&g, now + 479), 1)
        XCTAssertEqual(inas_auth_global_locked(&g, now + 480), 0)

        now += 480
        trigger()
        XCTAssertEqual(g.streak, 5)
        XCTAssertEqual(inas_auth_global_locked(&g, now + 899), 1)
        XCTAssertEqual(inas_auth_global_locked(&g, now + 900), 0)

        now += 900
        trigger()
        XCTAssertEqual(g.streak, 6)
        XCTAssertEqual(inas_auth_global_locked(&g, now + 899), 1)
        XCTAssertEqual(inas_auth_global_locked(&g, now + 900), 0)
    }

    func testGlobalSuccessClearsStreak() {
        var g = globalSlot()
        let now: time_t = 8_000_000
        for _ in 1...101 {
            inas_auth_global_record_failure(&g, now)
        }
        XCTAssertEqual(inas_auth_global_locked(&g, now), 1)
        inas_auth_global_record_success(&g)
        XCTAssertEqual(inas_auth_global_locked(&g, now), 0)
        XCTAssertEqual(g.fails, 0)
        XCTAssertEqual(g.streak, 0)
        for _ in 1...101 {
            inas_auth_global_record_failure(&g, now)
        }
        XCTAssertEqual(g.streak, 1)
        XCTAssertEqual(inas_auth_global_locked(&g, now + 59), 1)
        XCTAssertEqual(inas_auth_global_locked(&g, now + 60), 0)
    }
}
