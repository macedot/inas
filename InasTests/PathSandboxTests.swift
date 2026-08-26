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
    }
}
