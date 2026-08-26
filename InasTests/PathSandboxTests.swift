// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import XCTest
@testable import Inas

final class PathSandboxTests: XCTestCase {
    var root: URL!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("inas-sandbox-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: root.appendingPathComponent("docs"), withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: root)
    }

    func testRootAndNested() {
        let resolvedRoot = PathSandbox.resolve(root: root.path, smbName: "")
        XCTAssertEqual(resolvedRoot, root.path)
        let nested = PathSandbox.resolve(root: root.path, smbName: "docs")
        XCTAssertEqual(nested, root.appendingPathComponent("docs").path)
        let slash = PathSandbox.resolve(root: root.path, smbName: #"docs\note.txt"#)
        XCTAssertEqual(slash, root.appendingPathComponent("docs/note.txt").path)
    }

    func testRejectsEscape() {
        XCTAssertNil(PathSandbox.resolve(root: root.path, smbName: "../etc/passwd"))
        XCTAssertNil(PathSandbox.resolve(root: root.path, smbName: "docs/../../etc"))
        XCTAssertNil(PathSandbox.resolve(root: root.path, smbName: "/etc/passwd"))
        XCTAssertNil(PathSandbox.resolve(root: root.path, smbName: #"..\inas"#))
        XCTAssertNil(PathSandbox.resolve(root: root.path, smbName: ".."))
        XCTAssertNil(PathSandbox.resolve(root: root.path, smbName: "docs/.."))
        XCTAssertNil(PathSandbox.resolve(root: root.path, smbName: "docs/../docs/../../etc"))
    }

    func testNormalizesDotsAndSlashes() {
        let nested = PathSandbox.resolve(root: root.path, smbName: "./docs")
        XCTAssertEqual(nested, root.appendingPathComponent("docs").path)
        let slashes = PathSandbox.resolve(root: root.path, smbName: "docs//note.txt")
        XCTAssertEqual(slashes, root.appendingPathComponent("docs/note.txt").path)
        let backslashRoot = PathSandbox.resolve(root: root.path, smbName: #"\docs"#)
        XCTAssertEqual(backslashRoot, root.appendingPathComponent("docs").path)
    }

    func testRejectsControlCharacters() {
        XCTAssertNil(PathSandbox.resolve(root: root.path, smbName: "docs/\nfile"))
        XCTAssertNil(PathSandbox.resolve(root: root.path, smbName: "docs/\tfile"))
        XCTAssertNil(PathSandbox.resolve(root: root.path, smbName: "docs/\u{007F}file"))
    }

    func testRejectsSymlinkEscape() throws {
        let outside = FileManager.default.temporaryDirectory.appendingPathComponent("inas-outside-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: outside) }
        let link = root.appendingPathComponent("escape")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: outside)
        XCTAssertNil(PathSandbox.resolve(root: root.path, smbName: "escape"))
        XCTAssertNil(PathSandbox.resolve(root: root.path, smbName: "escape/secret.txt"))
    }

    func testAllowsSymlinkInsideRoot() throws {
        let target = root.appendingPathComponent("docs")
        let link = root.appendingPathComponent("alias")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        let resolved = PathSandbox.resolve(root: root.path, smbName: "alias")
        XCTAssertEqual(resolved, target.path)
    }

    func testNewFileUsesExistingParent() {
        let path = PathSandbox.resolve(root: root.path, smbName: "docs/new.txt")
        XCTAssertEqual(path, root.appendingPathComponent("docs/new.txt").path)
        XCTAssertNil(PathSandbox.resolve(root: root.path, smbName: "missing-dir/new.txt"))
    }
}
