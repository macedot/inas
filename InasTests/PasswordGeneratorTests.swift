// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import XCTest
@testable import Inas

final class PasswordGeneratorTests: XCTestCase {
    func testShape() {
        for _ in 0..<200 {
            let password = PasswordGenerator.generate()
            XCTAssertEqual(password.count, 12)
            XCTAssertTrue(PasswordGenerator.isGeneratedShape(password), password)
            XCTAssertTrue(password.prefix(8).contains { $0.isUppercase } || password.prefix(8).contains { $0.isLowercase })
        }
    }

    func testUniqueness() {
        let samples = Set((0..<80).map { _ in PasswordGenerator.generate() })
        XCTAssertGreaterThan(samples.count, 70)
    }

    func testAlphabetIsRestricted() {
        let letters = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
        let digits = Set("0123456789")
        for _ in 0..<100 {
            let password = PasswordGenerator.generate()
            XCTAssertTrue(password.prefix(8).allSatisfy { letters.contains($0) }, password)
            XCTAssertTrue(password.suffix(4).allSatisfy { digits.contains($0) }, password)
        }
    }

    func testShapeRejectsLookalikes() {
        XCTAssertFalse(PasswordGenerator.isGeneratedShape(""))
        XCTAssertFalse(PasswordGenerator.isGeneratedShape("short"))
        XCTAssertFalse(PasswordGenerator.isGeneratedShape("abcdefghijkl"))
        XCTAssertFalse(PasswordGenerator.isGeneratedShape("12345678abcd"))
        XCTAssertFalse(PasswordGenerator.isGeneratedShape("abcdEFGH12"))
        XCTAssertFalse(PasswordGenerator.isGeneratedShape("abcdEFGH12345"))
        XCTAssertTrue(PasswordGenerator.isGeneratedShape("abcdEFGH1234"))
    }
}
