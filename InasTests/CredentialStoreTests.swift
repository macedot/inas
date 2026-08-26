// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import XCTest
@testable import Inas

private final class FailingPasswordVault: PasswordVault {
    func save(_ password: String) throws { throw PasswordVaultError.saveFailed }
    func read() -> String? { nil }
    func delete() {}
}

final class CredentialStoreTests: XCTestCase {
    func testDefaultUserAndAutoPassword() throws {
        let defaults = UserDefaults(suiteName: "inas.tests.\(UUID().uuidString)")!
        let store = CredentialStore(defaults: defaults, vault: MemoryPasswordVault())
        let credentials = store.load()
        XCTAssertEqual(credentials.username, "inas")
        XCTAssertFalse(credentials.usesCustomPassword)
        let first = try store.passwordForStart(credentials)
        XCTAssertTrue(PasswordGenerator.isGeneratedShape(first.password))
        let second = try store.passwordForStart(first.credentials)
        XCTAssertTrue(PasswordGenerator.isGeneratedShape(second.password))
        XCTAssertNotEqual(first.password, second.password)
    }

    func testCustomPasswordPersists() throws {
        let defaults = UserDefaults(suiteName: "inas.tests.\(UUID().uuidString)")!
        let store = CredentialStore(defaults: defaults, vault: MemoryPasswordVault())
        let credentials = ShareCredentials(username: "alice", password: "SecretPass99", usesCustomPassword: true)
        try store.save(credentials)
        let loaded = store.load()
        XCTAssertEqual(loaded.username, "alice")
        XCTAssertTrue(loaded.usesCustomPassword)
        let session = try store.passwordForStart(credentials)
        XCTAssertEqual(session.password, "SecretPass99")
    }

    func testEmptyCustomPasswordGenerates() throws {
        let defaults = UserDefaults(suiteName: "inas.tests.\(UUID().uuidString)")!
        let store = CredentialStore(defaults: defaults, vault: MemoryPasswordVault())
        let credentials = ShareCredentials(username: "inas", password: "   ", usesCustomPassword: true)
        let generated = try store.passwordForStart(credentials)
        XCTAssertTrue(PasswordGenerator.isGeneratedShape(generated.password))
        XCTAssertFalse(generated.credentials.usesCustomPassword)
        XCTAssertFalse(store.load().usesCustomPassword)
    }

    func testTurningOffCustomDeletesVault() throws {
        let defaults = UserDefaults(suiteName: "inas.tests.\(UUID().uuidString)")!
        let vault = MemoryPasswordVault()
        let store = CredentialStore(defaults: defaults, vault: vault)
        try store.save(ShareCredentials(username: "inas", password: "KeepMe1234", usesCustomPassword: true))
        XCTAssertEqual(vault.read(), "KeepMe1234")
        try store.save(ShareCredentials(username: "inas", password: "", usesCustomPassword: false))
        XCTAssertNil(vault.read())
        XCTAssertFalse(store.load().usesCustomPassword)
    }

    func testBlankUsernameFallsBackToDefault() throws {
        let defaults = UserDefaults(suiteName: "inas.tests.\(UUID().uuidString)")!
        let store = CredentialStore(defaults: defaults, vault: MemoryPasswordVault())
        try store.save(ShareCredentials(username: "", password: "", usesCustomPassword: false))
        XCTAssertEqual(store.load().username, "inas")
    }

    func testSaveFailureSurfaces() {
        let defaults = UserDefaults(suiteName: "inas.tests.\(UUID().uuidString)")!
        let store = CredentialStore(defaults: defaults, vault: FailingPasswordVault())
        XCTAssertThrowsError(
            try store.save(ShareCredentials(username: "inas", password: "x", usesCustomPassword: true))
        )
    }
}
