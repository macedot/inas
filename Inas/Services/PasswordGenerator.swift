import Foundation
import Security

enum PasswordGenerator {
    private static let letters = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
    private static let digits = Array("0123456789")

    /// 8 mixed-case letters followed by 4 digits, e.g. `kTmPqWxZ4821`.
    static func generate() -> String {
        var chars: [Character] = []
        chars.reserveCapacity(12)
        for _ in 0..<8 {
            chars.append(letters[randomIndex(letters.count)])
        }
        for _ in 0..<4 {
            chars.append(digits[randomIndex(digits.count)])
        }
        return String(chars)
    }

    static func isGeneratedShape(_ password: String) -> Bool {
        guard password.count == 12 else { return false }
        let lettersPart = password.prefix(8)
        let digitsPart = password.suffix(4)
        return lettersPart.allSatisfy(\.isLetter) && digitsPart.allSatisfy(\.isNumber)
    }

    private static func randomIndex(_ upper: Int) -> Int {
        var byte: UInt8 = 0
        let status = SecRandomCopyBytes(kSecRandomDefault, 1, &byte)
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed")
        return Int(byte) % upper
    }
}
