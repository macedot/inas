// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import XCTest
@testable import Inas

final class CredentialStoreTests: XCTestCase {
    func testDefaultUserAndAutoPassword() {
        let defaults = UserDefaults(suiteName: "inas.tests.\(UUID().uuidString)")!
        let store = CredentialStore(defaults: defaults, vault: MemoryPasswordVault())
        var credentials = store.load()
        XCTAssertEqual(credentials.username, "inas")
        XCTAssertFalse(credentials.usesCustomPassword)
        let first = store.passwordForStart(&credentials)
        XCTAssertTrue(PasswordGenerator.isGeneratedShape(first))
        let second = store.passwordForStart(&credentials)
        XCTAssertTrue(PasswordGenerator.isGeneratedShape(second))
        XCTAssertNotEqual(first, second)
    }

    func testCustomPasswordPersists() {
        let defaults = UserDefaults(suiteName: "inas.tests.\(UUID().uuidString)")!
        let store = CredentialStore(defaults: defaults, vault: MemoryPasswordVault())
        var credentials = ShareCredentials(username: "alice", password: "SecretPass99", usesCustomPassword: true)
        store.save(credentials)
        let loaded = store.load()
        XCTAssertEqual(loaded.username, "alice")
        XCTAssertTrue(loaded.usesCustomPassword)
        let password = store.passwordForStart(&credentials)
        XCTAssertEqual(password, "SecretPass99")
    }

    func testEmptyCustomPasswordGenerates() {
        let defaults = UserDefaults(suiteName: "inas.tests.\(UUID().uuidString)")!
        let store = CredentialStore(defaults: defaults, vault: MemoryPasswordVault())
        var credentials = ShareCredentials(username: "inas", password: "   ", usesCustomPassword: true)
        let generated = store.passwordForStart(&credentials)
        XCTAssertTrue(PasswordGenerator.isGeneratedShape(generated))
        XCTAssertFalse(credentials.usesCustomPassword)
        XCTAssertFalse(store.load().usesCustomPassword)
    }

    func testTurningOffCustomDeletesVault() {
        let defaults = UserDefaults(suiteName: "inas.tests.\(UUID().uuidString)")!
        let vault = MemoryPasswordVault()
        let store = CredentialStore(defaults: defaults, vault: vault)
        store.save(ShareCredentials(username: "inas", password: "KeepMe1234", usesCustomPassword: true))
        XCTAssertEqual(vault.read(), "KeepMe1234")
        store.save(ShareCredentials(username: "inas", password: "", usesCustomPassword: false))
        XCTAssertNil(vault.read())
        XCTAssertFalse(store.load().usesCustomPassword)
    }

    func testBlankUsernameFallsBackToDefault() {
        let defaults = UserDefaults(suiteName: "inas.tests.\(UUID().uuidString)")!
        let store = CredentialStore(defaults: defaults, vault: MemoryPasswordVault())
        store.save(ShareCredentials(username: "", password: "", usesCustomPassword: false))
        XCTAssertEqual(store.load().username, "inas")
    }
}
