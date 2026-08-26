// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import XCTest
@testable import Inas

private struct FixedLAN: LANAddressing {
    var ip: String?
    func lanIPv4() -> String? { ip }
}

private final class MockServer: SMBServing, @unchecked Sendable {
    var startError: SMBServerError?
    var blockStart = false
    let gate = DispatchSemaphore(value: 0)
    private(set) var started = false
    private(set) var stopped = false
    var clientCount = 0
    var bytesTransferred: UInt64 = 0

    func start(shares: [LiveShare], username: String, password: String, hostname: String, bindIP: String) throws -> UInt16 {
        if blockStart {
            gate.wait()
        }
        if let startError {
            throw startError
        }
        started = true
        return 4455
    }

    func stop() {
        stopped = true
        started = false
        gate.signal()
    }
}

private final class MockAdvertiser: BonjourAdvertising {
    var startedPort: UInt16?
    func start(port: UInt16) { startedPort = port }
    func stop() { startedPort = nil }
}

private final class MockDiscovery: WindowsDiscovering {
    var startedIP: String?
    func start(ip: String, port: UInt16) { startedIP = ip }
    func stop() { startedIP = nil }
}

private final class MockBackground: BackgroundShareKeeping {
    var expire: (() -> Void)?
    var notified = false
    func sharingDidStart(onExpire: @escaping () -> Void) { expire = onExpire }
    func sharingDidStop() { expire = nil }
    func notifyStoppedBySystem() { notified = true }
}

@MainActor
final class ShareControllerTests: XCTestCase {
    private func makeController(
        lan: String? = "192.168.1.8",
        server: MockServer = MockServer(),
        background: MockBackground = MockBackground(),
        vault: PasswordVault = MemoryPasswordVault()
    ) -> (ShareController, MockServer, MockBackground) {
        let defaults = UserDefaults(suiteName: "inas.ctrl.\(UUID().uuidString)")!
        let store = CredentialStore(defaults: defaults, vault: vault)
        let controller = ShareController(
            store: store,
            shareStore: ShareStore(defaults: defaults),
            server: server,
            bonjour: MockAdvertiser(),
            windowsDiscovery: MockDiscovery(),
            background: background,
            lan: FixedLAN(ip: lan),
            registerBackground: false
        )
        return (controller, server, background)
    }

    func testStartWithoutWiFiFails() {
        let (controller, _, _) = makeController(lan: nil)
        controller.start()
        XCTAssertEqual(controller.state, .failed(SMBServerError.noWiFi.localizedDescription))
    }

    func testStartFailureSurfaces() async {
        let server = MockServer()
        server.startError = .bindFailed
        let (controller, _, _) = makeController(server: server)
        controller.start()
        let deadline = Date().addingTimeInterval(2)
        while controller.state == .starting, Date() < deadline {
            await Task.yield()
        }
        XCTAssertEqual(controller.state, .failed(SMBServerError.bindFailed.localizedDescription))
    }

    func testStopDuringStarting() async {
        let server = MockServer()
        server.blockStart = true
        let (controller, _, _) = makeController(server: server)
        controller.start()
        XCTAssertEqual(controller.state, .starting)
        controller.stop()
        XCTAssertEqual(controller.state, .stopping)
        let deadline = Date().addingTimeInterval(2)
        while controller.state == .stopping, Date() < deadline {
            await Task.yield()
        }
        XCTAssertEqual(controller.state, .stopped)
        XCTAssertTrue(server.stopped)
    }

    func testExpiryStopsAndWipesAutoPassword() async {
        let background = MockBackground()
        let (controller, _, _) = makeController(background: background)
        controller.start()
        let deadline = Date().addingTimeInterval(2)
        while controller.state != .sharing, Date() < deadline {
            await Task.yield()
        }
        XCTAssertEqual(controller.state, .sharing)
        XCTAssertFalse(controller.credentials.password.isEmpty)
        background.expire?()
        let stopDeadline = Date().addingTimeInterval(2)
        while controller.state != .stopped, Date() < stopDeadline {
            await Task.yield()
        }
        XCTAssertEqual(controller.state, .stopped)
        XCTAssertEqual(controller.credentials.password, "")
        XCTAssertTrue(background.notified)
    }

    func testPasswordDidChangeMarksCustom() {
        let (controller, _, _) = makeController()
        controller.credentials.password = "Secret99"
        controller.passwordDidChange()
        XCTAssertTrue(controller.credentials.usesCustomPassword)
    }
}
