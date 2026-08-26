// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import Darwin
import XCTest
@testable import Inas

final class SMBLoopbackTests: XCTestCase {
    private var root: URL!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("inas-loop-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        inas_smb_stop()
        try? FileManager.default.removeItem(at: root)
    }

    func testBindOnLoopbackPortZero() throws {
        let port = try startServer()
        XCTAssertGreaterThan(port, 0)
        XCTAssertNotEqual(port, 445)
        XCTAssertEqual(inas_smb_is_running(), 1)
    }

    func testRefusesSMB2AndSMB300() throws {
        let port = try startServer()
        var err = [CChar](repeating: 0, count: 256)
        var negotiated: UInt16 = 0
        XCTAssertNotEqual(
            inas_smb_client_connect("127.0.0.1", port, "inas", "correct1", "inas", 0x0210, &negotiated, &err, Int32(err.count)),
            0,
            "SMB 2.1 must be refused"
        )
        XCTAssertNotEqual(
            inas_smb_client_connect("127.0.0.1", port, "inas", "correct1", "inas", 0x0300, &negotiated, &err, Int32(err.count)),
            0,
            "SMB 3.0.0 must be refused"
        )
    }

    func testAcceptsSMB302And311() throws {
        let port = try startServer()
        var err = [CChar](repeating: 0, count: 256)
        var negotiated: UInt16 = 0
        XCTAssertEqual(
            inas_smb_client_connect("127.0.0.1", port, "inas", "correct1", "inas", 0x0302, &negotiated, &err, Int32(err.count)),
            0,
            String(cString: err)
        )
        XCTAssertEqual(negotiated, 0x0302)
        XCTAssertEqual(
            inas_smb_client_connect("127.0.0.1", port, "inas", "correct1", "inas", 0x0311, &negotiated, &err, Int32(err.count)),
            0,
            String(cString: err)
        )
        XCTAssertEqual(negotiated, 0x0311)
    }

    func testWrongPasswordFails() throws {
        let port = try startServer()
        var err = [CChar](repeating: 0, count: 256)
        var negotiated: UInt16 = 0
        XCTAssertNotEqual(
            inas_smb_client_connect("127.0.0.1", port, "inas", "wrong-password", "inas", 0, &negotiated, &err, Int32(err.count)),
            0,
            String(cString: err)
        )
    }

    func testRoundtripAndTraversalRefusal() throws {
        let port = try startServer()
        var err = [CChar](repeating: 0, count: 256)
        XCTAssertEqual(
            inas_smb_client_roundtrip("127.0.0.1", port, "inas", "correct1", "inas", &err, Int32(err.count)),
            0,
            String(cString: err)
        )
    }

    func testThrottleLocksPeerAfterElevenFailures() throws {
        let port = try startServer()
        var err = [CChar](repeating: 0, count: 256)
        var negotiated: UInt16 = 0
        for _ in 0..<11 {
            XCTAssertNotEqual(
                inas_smb_client_connect("127.0.0.1", port, "inas", "wrong-password", "inas", 0, &negotiated, &err, Int32(err.count)),
                0,
                "wrong password must fail before lockout too"
            )
        }
        var peers: Int32 = 0
        var locked: Int32 = 0
        XCTAssertEqual(inas_smb_auth_stats(&peers, &locked), 0)
        XCTAssertEqual(peers, 1)
        XCTAssertEqual(locked, 1)
        // The locked peer cannot connect even with the correct password.
        XCTAssertNotEqual(
            inas_smb_client_connect("127.0.0.1", port, "inas", "correct1", "inas", 0, &negotiated, &err, Int32(err.count)),
            0,
            "locked peer must be rejected"
        )
    }

    func testHandleExhaustionAtTableSize() throws {
        let port = try startServer()
        var err = [CChar](repeating: 0, count: 256)
        let opened = inas_smb_client_open_many("127.0.0.1", port, "inas", "correct1", "inas", 257, &err, Int32(err.count))
        XCTAssertEqual(opened, 256, "exactly the handle table size must succeed: \(String(cString: err))")
    }

    func testDirectoryCyclesDoNotLeakServerFDs() throws {
        let port = try startServer()
        let before = openFDCount()
        var err = [CChar](repeating: 0, count: 256)
        XCTAssertEqual(
            inas_smb_client_dir_cycle("127.0.0.1", port, "inas", "correct1", "inas", 300, &err, Int32(err.count)),
            0,
            String(cString: err)
        )
        let after = openFDCount()
        if let before, let after {
            XCTAssertLessThan(after - before, 16, "directory open/close cycles must not leak fds")
        }
    }

    func testWriteBounds() throws {
        let port = try startServer()
        var err = [CChar](repeating: 0, count: 256)
        XCTAssertEqual(
            inas_smb_client_write_bounds(
                "127.0.0.1", port, "inas", "correct1", "inas",
                0x100000, 0x100001, &err, Int32(err.count)
            ),
            0,
            String(cString: err)
        )
    }

    func testRejectsIllegalShareNames() throws {
        XCTAssertEqual(startServerRaw(shareName: "bad name!"), -Int32(EINVAL))
        XCTAssertEqual(startServerRaw(shareName: "dossier-ünïcode"), -Int32(EINVAL))
        XCTAssertEqual(startServerRaw(shareName: String(repeating: "a", count: 64)), -Int32(EINVAL))
        XCTAssertEqual(inas_smb_is_running(), 0)
    }

    private func openFDCount() -> Int? {
        try? FileManager.default.contentsOfDirectory(atPath: "/dev/fd").count
    }

    private func startServer(shareName: String = "inas") throws -> UInt16 {
        let rc = startServerRaw(shareName: shareName)
        XCTAssertEqual(rc, 0, "inas_smb_start failed: \(rc)")
        let port = UInt16(inas_smb_bound_port())
        XCTAssertGreaterThan(port, 0)
        return port
    }

    private func startServerRaw(shareName: String) -> Int32 {
        root.path.withCString { rootPtr in
            shareName.withCString { namePtr in
                "inas".withCString { userPtr in
                    "correct1".withCString { passPtr in
                        "iNAS".withCString { hostPtr in
                            "127.0.0.1".withCString { bindPtr in
                                var share = inas_smb_share(name: namePtr, root_path: rootPtr)
                                return withUnsafePointer(to: &share) { sharePtr in
                                    var config = inas_smb_config(
                                        username: userPtr,
                                        password: passPtr,
                                        hostname: hostPtr,
                                        bind_ip: bindPtr,
                                        port: 0,
                                        try_ports: nil,
                                        try_port_count: 0,
                                        share_count: 1,
                                        shares: sharePtr
                                    )
                                    return inas_smb_start(&config)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
