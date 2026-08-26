// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import XCTest
@testable import Inas

final class KeychainPasswordVaultTests: XCTestCase {
    func testRoundTripAndDelete() throws {
        let vault = KeychainPasswordVault(account: "inas-test-\(UUID().uuidString)")
        defer { vault.delete() }
        XCTAssertNil(vault.read())
        try vault.save("KeychainPass12")
        XCTAssertEqual(vault.read(), "KeychainPass12")
        try vault.save("OtherPass99xx")
        XCTAssertEqual(vault.read(), "OtherPass99xx")
        vault.delete()
        XCTAssertNil(vault.read())
    }
}

final class DialectPolicyCTests: XCTestCase {
    func testAllowedDialectsMatchVendorPolicy() {
        XCTAssertEqual(inas_smb_dialect_allowed(0x0202), 0)
        XCTAssertEqual(inas_smb_dialect_allowed(0x0210), 0)
        XCTAssertEqual(inas_smb_dialect_allowed(0x0300), 0)
        XCTAssertEqual(inas_smb_dialect_allowed(0x0302), 1)
        XCTAssertEqual(inas_smb_dialect_allowed(0x0311), 1)
        XCTAssertEqual(INAS_SMB_DIALECT_MIN, 0x0302)
        XCTAssertEqual(INAS_SMB_DIALECT_PREF, 0x0311)
    }
}
