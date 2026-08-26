// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import SwiftUI

@main
struct InasApp: App {
    @State private var controller = ShareController()

    var body: some Scene {
        WindowGroup {
            ShareScreen(controller: controller)
        }
    }
}
