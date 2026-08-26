import Foundation
import Security

struct ShareCredentials: Equatable {
    var username: String
    var password: String
    var usesCustomPassword: Bool
}

protocol PasswordVault {
    func save(_ password: String)
    func read() -> String?
    func delete()
}

final class KeychainPasswordVault: PasswordVault {
    private let service = "app.inas.Inas.credentials"
    private let account: String

    init(account: String = "share-password") {
        self.account = account
    }

    func save(_ password: String) {
        delete()
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: Data(password.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        SecItemAdd(query as CFDictionary, nil)
    }

    func read() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    func delete() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}

final class MemoryPasswordVault: PasswordVault {
    private var password: String?

    func save(_ password: String) { self.password = password }
    func read() -> String? { password }
    func delete() { password = nil }
}

final class CredentialStore {
    private let defaults: UserDefaults
    private let vault: PasswordVault

    private enum Keys {
        static let username = "inas.username"
        static let custom = "inas.usesCustomPassword"
    }

    init(defaults: UserDefaults = .standard, vault: PasswordVault = KeychainPasswordVault()) {
        self.defaults = defaults
        self.vault = vault
    }

    func load() -> ShareCredentials {
        let username = defaults.string(forKey: Keys.username)?.trimmingCharacters(in: .whitespacesAndNewlines)
        let custom = defaults.bool(forKey: Keys.custom)
        let stored = custom ? vault.read() : nil
        return ShareCredentials(
            username: (username?.isEmpty == false) ? username! : "inas",
            password: stored ?? "",
            usesCustomPassword: custom && !(stored ?? "").isEmpty
        )
    }

    func save(_ credentials: ShareCredentials) {
        defaults.set(credentials.username, forKey: Keys.username)
        defaults.set(credentials.usesCustomPassword, forKey: Keys.custom)
        if credentials.usesCustomPassword {
            vault.save(credentials.password)
        } else {
            vault.delete()
        }
    }

    func passwordForStart(_ credentials: inout ShareCredentials) -> String {
        if credentials.usesCustomPassword {
            let trimmed = credentials.password.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty {
                credentials.password = trimmed
                save(credentials)
                return trimmed
            }
        }
        credentials.usesCustomPassword = false
        credentials.password = PasswordGenerator.generate()
        save(credentials)
        return credentials.password
    }
}
