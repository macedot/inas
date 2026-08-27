// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import SwiftUI

enum InasTheme {
    static let sharing = Color(red: 0.12, green: 0.72, blue: 0.52)
    static let stopped = Color(red: 0.35, green: 0.42, blue: 0.52)
    static let ink = Color(red: 0.07, green: 0.10, blue: 0.16)
    static let paper = Color(red: 0.97, green: 0.95, blue: 0.91)
    static let cardFill = Color.primary.opacity(0.05)
    static let cardStroke = Color.primary.opacity(0.08)

    static var titleFont: Font {
        .system(.largeTitle, design: .rounded).weight(.bold)
    }

    static var mono: Font {
        .system(.body, design: .monospaced)
    }
}

/// Shared folded-card header: icon, small caption title, and a one-line
/// mono summary. Used by every DisclosureGroup card so they read as one
/// family (Status, Connection, Settings sections).
struct CardHeader: View {
    let icon: String
    let title: String
    let summary: String

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .font(.footnote.weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Text(summary)
                    .font(InasTheme.mono)
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
    }
}
