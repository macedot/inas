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
}
