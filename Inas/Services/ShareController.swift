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
    var stats = ShareStats()
    private var lastStatsTotal: UInt64 = 0
    /// Consecutive watchdog ticks where the LAN IP differed from the
    /// endpoint; the share only stops after a sustained mismatch.
    private var watchdogStrikes = 0

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
        #if DEBUG
        // Simulator testing: boot straight into sharing without UI taps.
        if ProcessInfo.processInfo.environment["INAS_SIM_AUTOSTART"] == "1" {
            start()
        }
        #endif
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
        #if DEBUG
        // Simulator/device testing: INAS_SIM_BIND_IP skips the Wi-Fi check
        // ("any" binds every interface), INAS_SIM_USER / INAS_SIM_PASSWORD
        // pin credentials for scripted clients.
        let sim = ProcessInfo.processInfo.environment
        if var simIP = sim["INAS_SIM_BIND_IP"], !simIP.isEmpty {
            if simIP == "any" {
                simIP = ""
            }
            if let simUser = sim["INAS_SIM_USER"], !simUser.isEmpty {
                credentials.username = simUser
            }
            start(overrideIP: simIP, overridePassword: sim["INAS_SIM_PASSWORD"])
            return
        }
        #endif
        start(overrideIP: nil, overridePassword: nil)
    }

    private func start(overrideIP: String?, overridePassword: String?) {
        guard !state.isBusy else { return }
        let ip: String
        if let overrideIP {
            ip = overrideIP
        } else {
            guard let lanIP = lan.lanIPv4() else {
                state = .failed(SMBServerError.noWiFi.localizedDescription)
                return
            }
            ip = lanIP
        }
        let username = credentials.username.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !username.isEmpty else {
            state = .failed("Choose a username first.")
            return
        }
        credentials.username = username
        let password: String
        do {
            if let overridePassword {
                password = overridePassword
            } else {
                let session = try store.passwordForStart(credentials)
                credentials = session.credentials
                password = session.password
            }
        } catch {
            state = .failed("Could not store the password.")
            return
        }
        persistShares()
        seedDocumentsIfNeeded()
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
        clientCount = 0
        bytesTransferred = 0
        lastStatsTotal = 0
        stats = ShareStats()
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
        #if DEBUG
        // Simulator testing: endpoint is pinned to 127.0.0.1 which the LAN
        // probe will never report, so skip its "left Wi-Fi" auto-stop.
        let simNoWatchdog = ProcessInfo.processInfo.environment["INAS_SIM_AUTOSTART"] == "1"
        #else
        let simNoWatchdog = false
        #endif
        lastStatsTotal = 0
        watchdogStrikes = 0
        statsTimer?.invalidate()
        let tick: () -> Void = { [weak self] in
            guard let self else { return }
            if !simNoWatchdog, let expected = self.endpoint?.ip, self.lan.lanIPv4() != expected {
                // A transient radio blip or DHCP renew makes lanIPv4()
                // differ (or vanish) for a tick or two; killing the share
                // mid-copy for that aborts GNOME clients. Stop only once
                // the address has stayed wrong for ~5s (20 x 0.25s).
                watchdogStrikes += 1
                if watchdogStrikes >= 20 {
                    self.stop(notify: true)
                    return
                }
            } else {
                watchdogStrikes = 0
            }
            self.clientCount = self.server.clientCount
            self.bytesTransferred = self.server.bytesTransferred
            let total = self.bytesTransferred
            // A smaller total than the previous tick means the server
            // restarted underneath us; report no rate for that tick.
            let delta = total >= self.lastStatsTotal ? total - self.lastStatsTotal : 0
            self.lastStatsTotal = total
            // 0.25s window: scale to bytes/s for the Speed row.
            self.stats = ShareStats(
                connections: self.clientCount,
                peakClients: self.server.peakClients,
                activeTransfers: self.server.activeTransfers,
                bytesRead: self.server.bytesRead,
                bytesWritten: self.server.bytesWritten,
                bytesPerSecond: Double(delta) * 4
            )
        }
        tick()
        let timer = Timer(timeInterval: 0.25, repeats: true) { _ in
            Task { @MainActor in tick() }
        }
        RunLoop.main.add(timer, forMode: .common)
        statsTimer = timer
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
        let docs = documentsURL
        try? FileManager.default.createDirectory(at: docs, withIntermediateDirectories: true)
        let readme = docs.appendingPathComponent("README.txt")
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
