// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import Foundation

struct LiveShare: Equatable {
    var name: String
    var root: URL
    var scoped: Bool
}

final class ShareStore {
    private let defaults: UserDefaults
    private let key = "inas.extraShares"

    private struct Record: Codable {
        var id: UUID
        var name: String
        var folderTitle: String
        var bookmark: Data
    }

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    func load() -> [ExtraShare] {
        guard let data = defaults.data(forKey: key),
              let records = try? JSONDecoder().decode([Record].self, from: data) else {
            return []
        }
        var extras: [ExtraShare] = []
        for record in records {
            guard ShareName.isAvailable(record.name, extras: extras, ignoring: record.id) else { continue }
            extras.append(
                ExtraShare(
                    id: record.id,
                    name: record.name,
                    folderTitle: record.folderTitle,
                    bookmark: record.bookmark
                )
            )
        }
        return extras
    }

    func save(_ extras: [ExtraShare]) {
        let records: [Record] = extras.compactMap { extra in
            let name = extra.name.trimmingCharacters(in: .whitespacesAndNewlines)
            guard ShareName.isAvailable(name, extras: extras, ignoring: extra.id),
                  let bookmark = extra.bookmark else { return nil }
            return Record(id: extra.id, name: name, folderTitle: extra.folderTitle, bookmark: bookmark)
        }
        if let data = try? JSONEncoder().encode(records) {
            defaults.set(data, forKey: key)
        }
    }

    func resolveForStart(documents: URL, extras: [ExtraShare]) -> [LiveShare] {
        var live = [LiveShare(name: ShareName.builtin, root: documents, scoped: false)]
        var seen = Set([ShareName.builtin.lowercased()])
        for extra in extras {
            let name = extra.name.trimmingCharacters(in: .whitespacesAndNewlines)
            guard ShareName.isLegal(name), !seen.contains(name.lowercased()),
                  let bookmark = extra.bookmark else { continue }
            var stale = false
            guard let url = try? URL(
                resolvingBookmarkData: bookmark,
                options: [],
                relativeTo: nil,
                bookmarkDataIsStale: &stale
            ) else { continue }
            guard url.startAccessingSecurityScopedResource() else { continue }
            live.append(LiveShare(name: name, root: url, scoped: true))
            seen.insert(name.lowercased())
        }
        return live
    }

    static func bookmark(for url: URL) -> (Data, String)? {
        let access = url.startAccessingSecurityScopedResource()
        defer {
            if access {
                url.stopAccessingSecurityScopedResource()
            }
        }
        guard let data = try? url.bookmarkData(options: []) else { return nil }
        return (data, url.lastPathComponent)
    }
}
