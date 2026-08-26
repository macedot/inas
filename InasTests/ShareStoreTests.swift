// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import XCTest
@testable import Inas

final class ShareNameTests: XCTestCase {
    func testLegalNames() {
        XCTAssertTrue(ShareName.isLegal("work"))
        XCTAssertTrue(ShareName.isLegal("Photos_1"))
        XCTAssertTrue(ShareName.isLegal("a-b"))
        XCTAssertFalse(ShareName.isLegal(""))
        XCTAssertFalse(ShareName.isLegal("has space"))
        XCTAssertFalse(ShareName.isLegal("slash/name"))
        XCTAssertFalse(ShareName.isLegal("weird$"))
    }

    func testReservedAndCollision() {
        XCTAssertTrue(ShareName.isReserved("inas"))
        XCTAssertTrue(ShareName.isReserved("IPC$"))
        XCTAssertFalse(ShareName.isAvailable("inas", extras: []))
        let extra = ExtraShare(id: UUID(), name: "work", folderTitle: "Work", bookmark: Data([1]))
        XCTAssertFalse(ShareName.isAvailable("WORK", extras: [extra]))
        XCTAssertTrue(ShareName.isAvailable("home", extras: [extra]))
        XCTAssertTrue(ShareName.isAvailable("work", extras: [extra], ignoring: extra.id))
    }

    func testNameLimitsMatchCStorage() {
        XCTAssertTrue(ShareName.isLegal(String(repeating: "a", count: 63)))
        XCTAssertFalse(ShareName.isLegal(String(repeating: "a", count: 64)))
        XCTAssertFalse(ShareName.isLegal(String(repeating: "é", count: 31))) // 62 bytes, non-ASCII
    }

    func testNameIsASCIIOnly() {
        XCTAssertFalse(ShareName.isLegal("følder"))
        XCTAssertFalse(ShareName.isLegal("日本語"))
        XCTAssertFalse(ShareName.isLegal("café"))
        XCTAssertFalse(ShareName.isLegal("dossier-ünïcode"))
        XCTAssertTrue(ShareName.isLegal("A1_b-c"))
    }
}

final class ShareStoreTests: XCTestCase {
    func testRoundTripCompleteShares() throws {
        let defaults = UserDefaults(suiteName: "inas.shares.\(UUID().uuidString)")!
        let store = ShareStore(defaults: defaults)
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("inas-share-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let bookmark = try folder.bookmarkData(options: [])
        let extra = ExtraShare(id: UUID(), name: "work", folderTitle: folder.lastPathComponent, bookmark: bookmark)
        store.save([extra, ExtraShare(id: UUID(), name: "bad name", folderTitle: "", bookmark: nil)])
        let loaded = store.load()
        XCTAssertEqual(loaded.count, 1)
        XCTAssertEqual(loaded[0].name, "work")
        XCTAssertNotNil(loaded[0].bookmark)
    }

    func testStaleBookmarkIsSkippedOnStart() {
        let defaults = UserDefaults(suiteName: "inas.shares.\(UUID().uuidString)")!
        let store = ShareStore(defaults: defaults)
        let documents = FileManager.default.temporaryDirectory.appendingPathComponent("inas-docs-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: documents, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: documents) }
        let extra = ExtraShare(id: UUID(), name: "gone", folderTitle: "gone", bookmark: Data("not-a-bookmark".utf8))
        let live = store.resolveForStart(documents: documents, extras: [extra])
        XCTAssertEqual(live.count, 1)
        XCTAssertEqual(live[0].name, "inas")
        XCTAssertEqual(live[0].root, documents)
    }
}
