// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import Foundation

enum WSDMessageBuilder {
    static func xmlEscaped(_ value: String) -> String {
        var out = ""
        out.reserveCapacity(value.count)
        for scalar in value.unicodeScalars {
            switch scalar {
            case "&": out += "&amp;"
            case "<": out += "&lt;"
            case ">": out += "&gt;"
            case "\"": out += "&quot;"
            case "'": out += "&apos;"
            default:
                if scalar.value < 0x20 && scalar != "\t" && scalar != "\n" && scalar != "\r" {
                    continue
                }
                out.unicodeScalars.append(scalar)
            }
        }
        return out
    }

    static func soapAction(_ xml: String) -> String {
        guard let start = xml.range(of: "<wsa:Action>") ?? xml.range(of: "<Action>") else { return "" }
        let rest = xml[start.upperBound...]
        guard let end = rest.range(of: "</") else { return "" }
        return rest[..<end.lowerBound].trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static func uuidFromXML(_ xml: String, tag: String) -> String? {
        guard let start = xml.range(of: "<wsa:\(tag)>") ?? xml.range(of: "<\(tag)>") else { return nil }
        let rest = xml[start.upperBound...]
        guard let end = rest.range(of: "</") else { return nil }
        let value = rest[..<end.lowerBound].trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : String(value)
    }

    static func httpRequestComplete(_ data: Data) -> Bool {
        HTTPRequestParser.isComplete(data)
    }
}
