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

    func testTransferStatsCounters() throws {
        let port = try startServer()
        XCTAssertEqual(inas_smb_bytes_read(), 0)
        XCTAssertEqual(inas_smb_bytes_written(), 0)
        XCTAssertEqual(inas_smb_peak_clients(), 0)
        XCTAssertEqual(inas_smb_active_transfers(), 0)
        var err = [CChar](repeating: 0, count: 256)
        XCTAssertEqual(
            inas_smb_client_roundtrip("127.0.0.1", port, "inas", "correct1", "inas", &err, Int32(err.count)),
            0,
            String(cString: err)
        )
        // The roundtrip writes and reads back a file; both directions count.
        XCTAssertGreaterThan(inas_smb_bytes_written(), 0, "file write must count")
        XCTAssertGreaterThan(inas_smb_bytes_read(), 0, "file read must count")
        XCTAssertGreaterThanOrEqual(inas_smb_peak_clients(), 1, "session must register a peak")
        // No transfer is in flight once the probe disconnected.
        XCTAssertEqual(inas_smb_active_transfers(), 0)
        // The server thread tears the context down asynchronously; wait briefly.
        for _ in 0..<100 where inas_smb_client_count() != 0 {
            usleep(20000)
        }
        XCTAssertEqual(inas_smb_client_count(), 0)
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
        XCTAssertEqual(inas_smb_auth_global_locked(), 0)
    }

    func testGlobalThrottleLocksAfterOneHundredOneFailures() throws {
        let port = try startServer()
        var err = [CChar](repeating: 0, count: 256)
        var negotiated: UInt16 = 0
        for _ in 0..<101 {
            XCTAssertNotEqual(
                inas_smb_client_connect("127.0.0.1", port, "inas", "wrong-password", "inas", 0, &negotiated, &err, Int32(err.count)),
                0
            )
        }
        XCTAssertEqual(inas_smb_auth_global_locked(), 1)
        XCTAssertNotEqual(
            inas_smb_client_connect("127.0.0.1", port, "inas", "correct1", "inas", 0, &negotiated, &err, Int32(err.count)),
            0,
            "global backoff must reject even the correct password"
        )
    }

    func testRejectsPlaintextAfterSealedSession() throws {
        let port = try startServer()
        var err = [CChar](repeating: 0, count: 256)
        XCTAssertEqual(
            inas_smb_client_plaintext_after_session("127.0.0.1", port, "inas", "correct1", "inas", &err, Int32(err.count)),
            0,
            String(cString: err)
        )
    }

    func testRejectsOverlongShareName() throws {
        let port = try startServer()
        var err = [CChar](repeating: 0, count: 256)
        var negotiated: UInt16 = 0
        let longName = String(repeating: "a", count: 200)
        XCTAssertNotEqual(
            inas_smb_client_connect("127.0.0.1", port, "inas", "correct1", longName, 0, &negotiated, &err, Int32(err.count)),
            0,
            "tree-connect to a 200-byte share name must fail"
        )
        XCTAssertEqual(inas_smb_is_running(), 1, "failed TREE_CONNECT must not take the listener down")
        XCTAssertEqual(
            inas_smb_client_connect("127.0.0.1", port, "inas", "correct1", "inas", 0, &negotiated, &err, Int32(err.count)),
            0,
            String(cString: err)
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

    func testTreeConnectTrailingSlash() throws {
        let port = try startServer()
        var err = [CChar](repeating: 0, count: 256)
        var negotiated: UInt16 = 0
        XCTAssertEqual(
            inas_smb_client_connect("127.0.0.1", port, "inas", "correct1", "inas/", 0, &negotiated, &err, Int32(err.count)),
            0,
            "Linux TREE_CONNECT with a trailing slash must succeed: \(String(cString: err))"
        )
    }

    func testIpcTreeConnectAfterLogin() throws {
        let port = try startServer()
        var err = [CChar](repeating: 0, count: 256)
        var negotiated: UInt16 = 0
        XCTAssertEqual(
            inas_smb_client_connect("127.0.0.1", port, "inas", "correct1", "IPC$", 0, &negotiated, &err, Int32(err.count)),
            0,
            "Linux/Samba IPC$ TREE_CONNECT after login must not be NOT_IMPLEMENTED: \(String(cString: err))"
        )
    }

    func testShareEnumOverIpcSrvsvc() throws {
        let port = try startServer()
        var err = [CChar](repeating: 0, count: 256)
        XCTAssertEqual(
            inas_smb_client_share_enum("127.0.0.1", port, "inas", "correct1", "inas", &err, Int32(err.count)),
            0,
            String(cString: err)
        )
    }

    func testQueryDirectoryWireMatchesMacOSParser() throws {
        let port = try startServer()
        var err = [CChar](repeating: 0, count: 256)
        XCTAssertEqual(
            inas_smb_client_query_dir_wire("127.0.0.1", port, "inas", "correct1", "inas", &err, Int32(err.count)),
            0,
            String(cString: err)
        )
    }

    func testSetInfoDeleteAndRename() throws {
        let port = try startServer()
        var err = [CChar](repeating: 0, count: 256)
        XCTAssertEqual(
            inas_smb_client_setinfo_delete_rename("127.0.0.1", port, "inas", "correct1", "inas", &err, Int32(err.count)),
            0,
            "macOS-style SET_INFO delete/rename must work: \(String(cString: err))"
        )
    }

    func testStatSubdirectoryLikeLinuxFileManager() throws {
        let port = try startServer()
        var err = [CChar](repeating: 0, count: 256)
        XCTAssertEqual(
            inas_smb_client_stat_entry("127.0.0.1", port, "inas", "correct1", "inas", &err, Int32(err.count)),
            0,
            String(cString: err)
        )
    }

    func testQueryDirectoryLinuxClassesOnSubdir() throws {
        let port = try startServer()
        var err = [CChar](repeating: 0, count: 256)
        XCTAssertEqual(
            inas_smb_client_query_dir_classes("127.0.0.1", port, "inas", "correct1", "inas", &err, Int32(err.count)),
            0,
            String(cString: err)
        )
    }

    func testLinuxPostLoginQueriesAreImplemented() throws {
        let port = try startServer()
        var err = [CChar](repeating: 0, count: 256)
        XCTAssertEqual(
            inas_smb_client_linux_post_login("127.0.0.1", port, "inas", "correct1", "inas", &err, Int32(err.count)),
            0,
            String(cString: err)
        )
    }

    func testSetInfoDeleteEdges() throws {
        let port = try startServer()
        var err = [CChar](repeating: 0, count: 256)
        XCTAssertEqual(
            inas_smb_client_setinfo_delete_edges("127.0.0.1", port, "inas", "correct1", "inas", &err, Int32(err.count)),
            0,
            String(cString: err)
        )
    }

    func testChangeNotifyCompletesOnCreateNotWrite() throws {
        let port = try startServer()
        var err = [CChar](repeating: 0, count: 256)
        XCTAssertEqual(
            inas_smb_client_change_notify_mutate("127.0.0.1", port, "inas", "correct1", "inas", &err, Int32(err.count)),
            0,
            String(cString: err)
        )
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
