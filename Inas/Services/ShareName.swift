// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import Foundation

enum ShareName {
    static let builtin = "inas"
    static let maxExtra = 8

    /// C stores share names as `char name[64]`: ASCII `[A-Za-z0-9_-]`, 1–63 bytes.
    private static let legalCharacters = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")

    static func isLegal(_ name: String) -> Bool {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (1...63).contains(trimmed.utf8.count) else { return false }
        return trimmed.allSatisfy { legalCharacters.contains($0) }
    }

    static func isReserved(_ name: String) -> Bool {
        let lower = name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return lower == builtin || lower == "ipc$" || lower == "admin$"
    }

    static func isAvailable(_ name: String, extras: [ExtraShare], ignoring: UUID? = nil) -> Bool {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard isLegal(trimmed), !isReserved(trimmed) else { return false }
        return extras.allSatisfy { extra in
            extra.id == ignoring || extra.name.caseInsensitiveCompare(trimmed) != .orderedSame
        }
    }
}

struct ExtraShare: Equatable, Identifiable {
    var id: UUID
    var name: String
    var folderTitle: String
    var bookmark: Data?

    var isComplete: Bool {
        ShareName.isLegal(name) && bookmark != nil
    }
}
