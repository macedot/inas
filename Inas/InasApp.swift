// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import BackgroundTasks
import SwiftUI

@main
struct InasApp: App {
    @State private var controller = ShareController()

    init() {
        if #available(iOS 26.0, *) {
            BGTaskScheduler.shared.register(
                forTaskWithIdentifier: BackgroundShareKeeper.taskIdentifier,
                using: nil
            ) { task in
                guard let task = task as? BGContinuedProcessingTask else {
                    task.setTaskCompleted(success: false)
                    return
                }
                task.expirationHandler = {
                    task.setTaskCompleted(success: false)
                }
                task.updateTitle("Sharing files", subtitle: "SMB 3 · iNAS")
            }
        }
    }

    var body: some Scene {
        WindowGroup {
            ShareScreen(controller: controller)
        }
    }
}
