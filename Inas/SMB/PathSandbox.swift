// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import Foundation

enum PathSandbox {
    static func resolve(root: String, smbName: String) -> String? {
        var buffer = [CChar](repeating: 0, count: 1024)
        let status = root.withCString { rootPointer in
            smbName.withCString { namePointer in
                inas_path_resolve(rootPointer, namePointer, &buffer, buffer.count)
            }
        }
        guard status == 0 else { return nil }
        return String(cString: buffer)
    }
}
