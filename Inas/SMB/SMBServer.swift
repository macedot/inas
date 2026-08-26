// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import Foundation

struct SMBEndpoint: Equatable {
    var ip: String
    var port: UInt16
    var share: String

    var smbURL: String {
        if port == 445 {
            return "smb://\(ip)/\(share)"
        }
        return "smb://\(ip):\(port)/\(share)"
    }

    var windowsHint: String {
        if port == 445 {
            return "\\\\\(ip)\\\(share)"
        }
        return "\\\\\(ip)@\(port)\\\(share)"
    }

    /// Name-based UNC. Windows Explorer talks SMB on 445 only.
    var windowsNameHint: String? {
        guard port == 445 else { return nil }
        return "\\\\\(WindowsDiscovery.localName)\\\(share)"
    }
}

enum SMBServerError: LocalizedError {
    case alreadyRunning
    case bindFailed
    case noWiFi
    case invalidConfig

    var errorDescription: String? {
        switch self {
        case .alreadyRunning: "Share is already running."
        case .bindFailed: "Could not open an SMB port on this device."
        case .noWiFi: "Connect to Wi-Fi, then tap Start."
        case .invalidConfig: "Username and password are required."
        }
    }
}

final class SMBServer: @unchecked Sendable {
    static let shareName = "inas"
    private let queue = DispatchQueue(label: "app.inas.smb")

    func start(root: URL, username: String, password: String, hostname: String) throws -> UInt16 {
        try queue.sync {
            var lastError: Int32 = 0
            let result: UInt16? = root.path.withCString { rootPtr in
                SMBServer.shareName.withCString { sharePtr in
                    username.withCString { userPtr in
                        password.withCString { passPtr in
                            hostname.withCString { hostPtr in
                                for port: UInt16 in [445, 4455] {
                                    var config = inas_smb_config(
                                        root_path: rootPtr,
                                        share_name: sharePtr,
                                        username: userPtr,
                                        password: passPtr,
                                        hostname: hostPtr,
                                        port: port
                                    )
                                    let rc = inas_smb_start(&config)
                                    if rc == 0 {
                                        let bound = UInt16(inas_smb_bound_port())
                                        return bound == 0 ? port : bound
                                    }
                                    lastError = rc
                                }
                                return nil
                            }
                        }
                    }
                }
            }
            if let result {
                return result
            }
            throw lastError == -Int32(EALREADY) ? SMBServerError.alreadyRunning : SMBServerError.bindFailed
        }
    }

    func stop() {
        queue.sync {
            inas_smb_stop()
        }
    }

    var isRunning: Bool { inas_smb_is_running() != 0 }
    var clientCount: Int { Int(inas_smb_client_count()) }
    var bytesTransferred: UInt64 { inas_smb_bytes_transferred() }
}
