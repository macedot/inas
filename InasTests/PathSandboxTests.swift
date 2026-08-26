// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import Darwin
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

    func testTrailingSeparatorsAndUTF8() {
        let docs = PathSandbox.resolve(root: root.path, smbName: "docs/")
        XCTAssertEqual(docs, root.appendingPathComponent("docs").path)
        let utf8 = PathSandbox.resolve(root: root.path, smbName: "docs/café.txt")
        XCTAssertEqual(utf8, root.appendingPathComponent("docs/café.txt").path)
    }

    func testRejectsWhenOutputBufferIsTooSmall() {
        var tiny = [CChar](repeating: 0, count: 8)
        let status = root.path.withCString { rootPointer in
            "docs/note.txt".withCString { namePointer in
                inas_path_resolve(rootPointer, namePointer, &tiny, tiny.count)
            }
        }
        XCTAssertEqual(status, -1)
    }

    func testRejectsPathThatExceedsPATH_MAX() {
        let longName = String(repeating: "a", count: 1200)
        XCTAssertNil(PathSandbox.resolve(root: root.path, smbName: "docs/\(longName)"))
    }

    func testResolveAtDoesNotFollowSymlinkSwap() throws {
        let outside = FileManager.default.temporaryDirectory.appendingPathComponent("inas-outside-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: outside) }
        try "secret".write(to: outside.appendingPathComponent("secret.txt"), atomically: true, encoding: .utf8)
        try "ok".write(to: root.appendingPathComponent("docs/note.txt"), atomically: true, encoding: .utf8)

        let rootfd = open(root.path, O_RDONLY | O_DIRECTORY)
        XCTAssertGreaterThanOrEqual(rootfd, 0)
        defer { close(rootfd) }

        var resolved = inas_path()
        resolved.dirfd = -1
        let status = "docs/note.txt".withCString { name in
            inas_path_resolve_at(rootfd, name, &resolved)
        }
        XCTAssertEqual(status, 0)
        defer { inas_path_release(&resolved) }

        let link = root.appendingPathComponent("docs/note.txt")
        try FileManager.default.removeItem(at: link)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: outside.appendingPathComponent("secret.txt"))

        let fd = withUnsafePointer(to: &resolved.name) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: 256) { cstr in
                openat(resolved.dirfd, cstr, O_RDONLY | O_NOFOLLOW)
            }
        }
        XCTAssertLessThan(fd, 0, "O_NOFOLLOW must refuse the swapped symlink")
    }
}
