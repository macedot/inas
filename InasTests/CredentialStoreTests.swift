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
}
