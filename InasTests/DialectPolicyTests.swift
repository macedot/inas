// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import XCTest
@testable import Inas

final class DialectPolicyTests: XCTestCase {
    func testAllowsSMB3Only() {
        XCTAssertFalse(DialectPolicy.accepts(0x0202))
        XCTAssertFalse(DialectPolicy.accepts(0x0210))
        XCTAssertFalse(DialectPolicy.accepts(0x0300))
        XCTAssertTrue(DialectPolicy.accepts(0x0302))
        XCTAssertTrue(DialectPolicy.accepts(0x0311))
        XCTAssertFalse(DialectPolicy.accepts(0x0100))
        XCTAssertFalse(DialectPolicy.accepts(0x0000))
        XCTAssertFalse(DialectPolicy.accepts(0x02FF))
        XCTAssertFalse(DialectPolicy.accepts(0xFFFF))
        XCTAssertEqual(SMBDialect.minimum, .smb302)
        XCTAssertEqual(SMBDialect.allowed, [.smb302, .smb311])
    }
}
