// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import Foundation

struct SMBEndpoint: Equatable {
    var ip: String
    var port: UInt16

    var smbURL: String {
        if port == 445 {
            return "smb://\(ip)"
        }
        return "smb://\(ip):\(port)"
    }

    var windowsHint: String {
        if port == 445 {
            return "\\\\\(ip)"
        }
        return "\\\\\(ip)@\(port)"
    }

    var windowsNameHint: String? {
        guard port == 445 else { return nil }
        return "\\\\\(WindowsDiscovery.localName)"
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
        case .invalidConfig: "Username, password, and share names must be valid."
        }
    }
}

final class SMBServer: SMBServing, @unchecked Sendable {
    static let shareName = ShareName.builtin
    private let queue = DispatchQueue(label: "app.inas.smb")
    var ports: [UInt16]

    init(ports: [UInt16] = [445, 4455]) {
        #if DEBUG
        // Simulator testing: INAS_SIM_PORT pins a single unprivileged port.
        if let raw = ProcessInfo.processInfo.environment["INAS_SIM_PORT"],
           let pinned = UInt16(raw), pinned > 0 {
            self.ports = [pinned]
            return
        }
        #endif
        self.ports = ports.isEmpty ? [445, 4455] : ports
    }

    func start(shares: [LiveShare], username: String, password: String, hostname: String, bindIP: String) throws -> UInt16 {
        try queue.sync {
            guard !shares.isEmpty, shares.count <= Int(INAS_MAX_SHARES) else {
                throw SMBServerError.invalidConfig
            }
            let names = shares.map(\.name)
            let roots = shares.map { $0.root.path }
            let tryPorts = ports
            let rc: Int32 = withSharePointers(names: names, roots: roots) { table, count in
                username.withCString { userPtr in
                    password.withCString { passPtr in
                        hostname.withCString { hostPtr in
                            bindIP.withCString { bindPtr in
                                tryPorts.withUnsafeBufferPointer { portBuf in
                                    var config = inas_smb_config(
                                        username: userPtr,
                                        password: passPtr,
                                        hostname: hostPtr,
                                        bind_ip: bindPtr,
                                        port: tryPorts[0],
                                        try_ports: portBuf.baseAddress,
                                        try_port_count: Int32(tryPorts.count),
                                        share_count: Int32(count),
                                        shares: table
                                    )
                                    return inas_smb_start(&config)
                                }
                            }
                        }
                    }
                }
            }
            if rc == 0 {
                let bound = UInt16(inas_smb_bound_port())
                return bound == 0 ? tryPorts[0] : bound
            }
            if rc == -Int32(EALREADY) {
                throw SMBServerError.alreadyRunning
            }
            if rc == -Int32(EINVAL) || rc == -Int32(ENAMETOOLONG) {
                throw SMBServerError.invalidConfig
            }
            throw SMBServerError.bindFailed
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

    private func withSharePointers<T>(names: [String], roots: [String], body: (UnsafePointer<inas_smb_share>, Int) -> T) -> T {
        var nameCStrings: [UnsafeMutablePointer<CChar>] = names.map { strdup($0)! }
        var rootCStrings: [UnsafeMutablePointer<CChar>] = roots.map { strdup($0)! }
        defer {
            nameCStrings.forEach { free($0) }
            rootCStrings.forEach { free($0) }
        }
        var table = zip(nameCStrings, rootCStrings).map { name, root in
            inas_smb_share(name: name, root_path: root)
        }
        return table.withUnsafeBufferPointer { buf in
            body(buf.baseAddress!, names.count)
        }
    }
}
