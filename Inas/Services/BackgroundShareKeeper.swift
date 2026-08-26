// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import BackgroundTasks
import UIKit
import UserNotifications

@MainActor
final class BackgroundShareKeeper {
    static let taskIdentifier = "app.inas.Inas.share-session"

    private var backgroundTask: UIBackgroundTaskIdentifier = .invalid
    private var progressTimer: Timer?
    private var onExpire: (() -> Void)?

    func sharingDidStart(onExpire: @escaping () -> Void) {
        self.onExpire = onExpire
        UIApplication.shared.isIdleTimerDisabled = true
        requestNotificationPermission()
        beginGraceTask()
        if #available(iOS 26.0, *) {
            startContinuedProcessing()
        }
    }

    func sharingDidStop() {
        UIApplication.shared.isIdleTimerDisabled = false
        endGraceTask()
        progressTimer?.invalidate()
        progressTimer = nil
        onExpire = nil
    }

    func notifyStoppedBySystem() {
        let content = UNMutableNotificationContent()
        content.title = "Sharing stopped"
        content.body = "Open iNAS and tap Start to share again."
        content.sound = .default
        let request = UNNotificationRequest(
            identifier: "inas.share.stopped",
            content: content,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(request)
    }

    private func beginGraceTask() {
        endGraceTask()
        backgroundTask = UIApplication.shared.beginBackgroundTask(withName: "inas.share.grace") { [weak self] in
            self?.endGraceTask()
            self?.onExpire?()
        }
    }

    private func endGraceTask() {
        if backgroundTask != .invalid {
            UIApplication.shared.endBackgroundTask(backgroundTask)
            backgroundTask = .invalid
        }
    }

    private func requestNotificationPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    @available(iOS 26.0, *)
    private func startContinuedProcessing() {
        let request = BGContinuedProcessingTaskRequest(
            identifier: Self.taskIdentifier,
            title: "Sharing files",
            subtitle: "SMB 3 · iNAS"
        )
        do {
            try BGTaskScheduler.shared.submit(request)
        } catch {
            // Foreground + grace period still apply.
        }
        progressTimer?.invalidate()
        progressTimer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { _ in
            // Progress is reported from the registered task handler in ShareController.
        }
    }
}
