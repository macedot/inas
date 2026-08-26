// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import XCTest
@testable import Inas

final class GlobMatchTests: XCTestCase {
    func testBasics() {
        XCTAssertEqual(inas_glob_match("file.txt", "*"), 1)
        XCTAssertEqual(inas_glob_match("file.txt", "*.*"), 1)
        XCTAssertEqual(inas_glob_match("file.txt", "file.txt"), 1)
        XCTAssertEqual(inas_glob_match("file.txt", "file.*"), 1)
        XCTAssertEqual(inas_glob_match("file.txt", "????.txt"), 1)
        XCTAssertEqual(inas_glob_match("file.txt", "nope"), 0)
        XCTAssertEqual(inas_glob_match("abc", "a?c"), 1)
        XCTAssertEqual(inas_glob_match("readme", "read*"), 1)
    }

    func testPathologicalStarPatternIsBounded() {
        let name = String(repeating: "a", count: 255)
        let pattern = String(repeating: "*a", count: 40) + "*b"
        let start = Date()
        let matched = inas_glob_match(name, pattern)
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertEqual(matched, 0)
        XCTAssertLessThan(elapsed, 0.05)
    }
}
