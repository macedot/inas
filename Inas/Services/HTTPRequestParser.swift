// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import Foundation

enum HTTPRequestParser {
    static func isComplete(_ data: Data) -> Bool {
        guard let text = String(data: data, encoding: .utf8),
              let headerEnd = text.range(of: "\r\n\r\n") else { return false }
        let headers = text[..<headerEnd.lowerBound]
        if let range = headers.range(of: "Content-Length:", options: .caseInsensitive) {
            let rest = headers[range.upperBound...].trimmingCharacters(in: .whitespaces)
            let lengthStr = rest.prefix(while: { $0.isNumber })
            let length = Int(lengthStr) ?? 0
            let bodyStart = text.distance(from: text.startIndex, to: headerEnd.upperBound)
            return data.count >= bodyStart + length
        }
        return true
    }
}
