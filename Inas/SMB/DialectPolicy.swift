// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import Foundation

enum SMBDialect: UInt16 {
    case smb202 = 0x0202
    case smb210 = 0x0210
    case smb300 = 0x0300
    case smb302 = 0x0302
    case smb311 = 0x0311

    var isAllowed: Bool { Self.allowed.contains(self) }

    static let allowed: Set<SMBDialect> = [.smb302, .smb311]
    static let minimum = SMBDialect.smb302
}

enum DialectPolicy {
    static func accepts(_ raw: UInt16) -> Bool {
        SMBDialect(rawValue: raw)?.isAllowed ?? false
    }
}
