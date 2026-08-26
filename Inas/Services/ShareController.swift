// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

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

    private let store = CredentialStore()
    private let server = SMBServer()
    private let bonjour = BonjourAdvertiser()
    private let windowsDiscovery = WindowsDiscovery()
    private let background = BackgroundShareKeeper()
    private var statsTimer: Timer?

    var state: State = .stopped
    var credentials: ShareCredentials
    var endpoint: SMBEndpoint?
    var showPassword = false
    var clientCount = 0
    var bytesTransferred: UInt64 = 0

    init() {
        credentials = store.load()
        seedDocumentsIfNeeded()
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

    var connectionURL: String {
        endpoint?.smbURL ?? "smb://—/\(SMBServer.shareName)"
    }

    func toggle() {
        if state.isSharing || state == .starting {
            stop()
        } else {
            start()
        }
    }

    func start() {
        guard !state.isBusy else { return }
        guard let ip = NetworkAddress.lanIPv4() else {
            state = .failed(SMBServerError.noWiFi.localizedDescription)
            return
        }
        let username = credentials.username.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !username.isEmpty else {
            state = .failed("Choose a username first.")
            return
        }
        credentials.username = username
        let password = store.passwordForStart(&credentials)
        state = .starting

        let root = documentsURL
        let host = WindowsDiscovery.hostName
        let server = self.server
        Task.detached {
            do {
                let port = try server.start(root: root, username: username, password: password, hostname: host)
                await MainActor.run { [weak self] in
                    guard let self else { return }
                    self.endpoint = SMBEndpoint(ip: ip, port: port, share: SMBServer.shareName)
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
                    self?.state = .failed(error.localizedDescription)
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
        Task.detached {
            server.stop()
            await MainActor.run { [weak self] in
                guard let self else { return }
                self.state = .stopped
                if notify {
                    self.background.notifyStoppedBySystem()
                }
            }
        }
    }

    func persistCredentials() {
        let trimmed = credentials.username.trimmingCharacters(in: .whitespacesAndNewlines)
        credentials.username = trimmed.isEmpty ? "inas" : trimmed
        if credentials.usesCustomPassword {
            credentials.password = credentials.password.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        store.save(credentials)
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
                self.clientCount = self.server.clientCount
                self.bytesTransferred = self.server.bytesTransferred
            }
        }
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
