// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import BackgroundTasks
import Foundation
import Observation
import UIKit

@MainActor
@Observable
final class ShareController {
    enum State: Equatable {
        case stopped
        case starting
        case sharing
        case stopping
        case failed(String)

        var isSharing: Bool {
            if case .sharing = self { return true }
            return false
        }

        var isBusy: Bool {
            self == .starting || self == .stopping
        }
    }

    private let store: CredentialStore
    private let shareStore: ShareStore
    private let server: SMBServing
    private let bonjour: BonjourAdvertising
    private let windowsDiscovery: WindowsDiscovering
    private let background: BackgroundShareKeeping
    private let lan: LANAddressing
    private var statsTimer: Timer?
    private var scopedRoots: [URL] = []

    var state: State = .stopped
    var credentials: ShareCredentials
    var extras: [ExtraShare] = []
    var endpoint: SMBEndpoint?
    var showPassword = false
    var clientCount = 0
    var bytesTransferred: UInt64 = 0

    init(
        store: CredentialStore = CredentialStore(),
        shareStore: ShareStore = ShareStore(),
        server: SMBServing? = nil,
        bonjour: BonjourAdvertising? = nil,
        windowsDiscovery: WindowsDiscovering? = nil,
        background: BackgroundShareKeeping? = nil,
        lan: LANAddressing = SystemLANAddress(),
        registerBackground: Bool = true
    ) {
        self.store = store
        self.shareStore = shareStore
        self.server = server ?? SMBServer()
        self.bonjour = bonjour ?? BonjourAdvertiser()
        self.windowsDiscovery = windowsDiscovery ?? WindowsDiscovery()
        self.background = background ?? BackgroundShareKeeper()
        self.lan = lan
        credentials = store.load()
        extras = shareStore.load()
        seedDocumentsIfNeeded()
        if registerBackground {
            registerBackgroundTask()
            NotificationCenter.default.addObserver(
                forName: UIApplication.didEnterBackgroundNotification,
                object: nil,
                queue: .main
            ) { [weak self] _ in
                Task { @MainActor in
                    self?.handleBackground()
                }
            }
        }
    }

    var connectionURL: String {
        endpoint?.smbURL ?? "smb://—"
    }

    var canAddShare: Bool { extras.count < ShareName.maxExtra }

    func toggle() {
        if state.isSharing || state == .starting {
            stop()
        } else {
            start()
        }
    }

    func start() {
        guard !state.isBusy else { return }
        guard let ip = lan.lanIPv4() else {
            state = .failed(SMBServerError.noWiFi.localizedDescription)
            return
        }
        let username = credentials.username.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !username.isEmpty else {
            state = .failed("Choose a username first.")
            return
        }
        credentials.username = username
        let password: String
        do {
            let session = try store.passwordForStart(credentials)
            credentials = session.credentials
            password = session.password
        } catch {
            state = .failed("Could not store the password.")
            return
        }
        persistShares()
        let live = shareStore.resolveForStart(documents: documentsURL, extras: extras)
        scopedRoots = live.filter(\.scoped).map(\.root)
        state = .starting

        let host = WindowsDiscovery.hostName
        let server = self.server
        Task.detached {
            do {
                let port = try server.start(shares: live, username: username, password: password, hostname: host, bindIP: ip)
                await MainActor.run { [weak self] in
                    guard let self else { return }
                    if self.state != .starting {
                        server.stop()
                        self.releaseScopedRoots()
                        if self.state == .stopping {
                            self.finishStop(notify: false)
                        }
                        return
                    }
                    self.endpoint = SMBEndpoint(ip: ip, port: port)
                    if !self.credentials.usesCustomPassword {
                        self.showPassword = true
                    }
                    self.bonjour.start(port: port)
                    self.windowsDiscovery.start(ip: ip, port: port)
                    self.background.sharingDidStart { [weak self] in
                        self?.stop(notify: true)
                    }
                    self.state = .sharing
                    self.beginStats()
                }
            } catch {
                await MainActor.run { [weak self] in
                    guard let self else { return }
                    self.releaseScopedRoots()
                    if self.state == .stopping {
                        self.finishStop(notify: false)
                    } else {
                        self.state = .failed(error.localizedDescription)
                    }
                }
            }
        }
    }

    func stop(notify: Bool = false) {
        guard state != .stopped, state != .stopping else { return }
        state = .stopping
        statsTimer?.invalidate()
        statsTimer = nil
        bonjour.stop()
        windowsDiscovery.stop()
        background.sharingDidStop()
        let server = self.server
        let notifyStopped = notify
        Task.detached {
            server.stop()
            await MainActor.run { [weak self] in
                self?.finishStop(notify: notifyStopped)
            }
        }
    }

    private func finishStop(notify: Bool) {
        releaseScopedRoots()
        if !credentials.usesCustomPassword {
            credentials.password = ""
            showPassword = false
        }
        endpoint = nil
        state = .stopped
        if notify {
            background.notifyStoppedBySystem()
        }
    }

    func persistShares() {
        shareStore.save(extras)
    }

    func addShare() {
        guard canAddShare, !state.isSharing else { return }
        extras.append(ExtraShare(id: UUID(), name: "", folderTitle: "", bookmark: nil))
    }

    func removeShare(id: UUID) {
        guard !state.isSharing else { return }
        extras.removeAll { $0.id == id }
        persistShares()
    }

    func setShareName(_ name: String, id: UUID) {
        guard let index = extras.firstIndex(where: { $0.id == id }) else { return }
        extras[index].name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        persistShares()
    }

    func setShareFolder(_ url: URL, id: UUID) {
        // Replacing the bookmark is intentional: a new folder pick must
        // refresh the security-scoped bookmark, not reuse the previous one.
        guard let index = extras.firstIndex(where: { $0.id == id }),
              let (bookmark, title) = ShareStore.bookmark(for: url) else { return }
        extras[index].bookmark = bookmark
        extras[index].folderTitle = title
        persistShares()
    }

    func passwordDidChange() {
        if !credentials.password.isEmpty {
            credentials.usesCustomPassword = true
        }
        persistCredentials()
    }

    func setGeneratesPasswordEachStart(_ enabled: Bool) {
        credentials.usesCustomPassword = !enabled
        if enabled {
            credentials.password = ""
        }
        persistCredentials()
    }

    func persistCredentials() {
        let trimmed = credentials.username.trimmingCharacters(in: .whitespacesAndNewlines)
        credentials.username = trimmed.isEmpty ? "inas" : trimmed
        if credentials.usesCustomPassword {
            credentials.password = credentials.password.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        do {
            try store.save(credentials)
        } catch {
            if !state.isSharing {
                state = .failed("Could not store the password.")
            }
            return
        }
        if !credentials.usesCustomPassword && !state.isSharing {
            credentials.password = ""
        }
    }

    func copyConnection() {
        UIPasteboard.general.string = connectionURL
    }

    private func handleBackground() {
        // Layers B/C: keep running while iOS allows; grace task expiry calls stop(notify:).
    }

    private func beginStats() {
        statsTimer?.invalidate()
        statsTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                if let expected = self.endpoint?.ip, self.lan.lanIPv4() != expected {
                    self.stop(notify: true)
                    return
                }
                self.clientCount = self.server.clientCount
                self.bytesTransferred = self.server.bytesTransferred
            }
        }
    }

    private func registerBackgroundTask() {
        if #available(iOS 26.0, *) {
            BGTaskScheduler.shared.register(
                forTaskWithIdentifier: BackgroundShareKeeper.taskIdentifier,
                using: nil
            ) { [weak self] task in
                guard let continued = task as? BGContinuedProcessingTask else {
                    task.setTaskCompleted(success: false)
                    return
                }
                continued.expirationHandler = {
                    Task { @MainActor in
                        self?.stop(notify: true)
                    }
                    continued.setTaskCompleted(success: false)
                }
                continued.updateTitle("Sharing files", subtitle: "SMB 3 · iNAS")
            }
        }
    }

    private func releaseScopedRoots() {
        for url in scopedRoots {
            url.stopAccessingSecurityScopedResource()
        }
        scopedRoots = []
    }

    private var documentsURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }

    private func seedDocumentsIfNeeded() {
        let readme = documentsURL.appendingPathComponent("README.txt")
        guard !FileManager.default.fileExists(atPath: readme.path) else { return }
        let text = """
        iNAS share
        ==========

        This folder is what other computers see when iNAS is sharing.

        Add files here with the Files app:
        On My iPhone / iPad → iNAS

        Or with Finder on a Mac (device connected): iNAS → Files.

        Tap Start in iNAS, then connect from another device:

          Mac:     smb://<this-device-ip>/inas
          Windows: \\\\<this-device-ip>\\inas

        Default user is inas. Use the password shown on the iNAS screen.
        """
        try? text.write(to: readme, atomically: true, encoding: .utf8)
    }
}
