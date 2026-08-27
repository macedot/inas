// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import Foundation

protocol LANAddressing: Sendable {
    func lanIPv4() -> String?
}

struct SystemLANAddress: LANAddressing {
    func lanIPv4() -> String? { NetworkAddress.lanIPv4() }
}

protocol SMBServing: AnyObject {
    func start(shares: [LiveShare], username: String, password: String, hostname: String, bindIP: String) throws -> UInt16
    func stop()
    var clientCount: Int { get }
    var bytesTransferred: UInt64 { get }
    var activeTransfers: Int { get }
    var bytesRead: UInt64 { get }
    var bytesWritten: UInt64 { get }
    var peakClients: Int { get }
}

protocol BonjourAdvertising: AnyObject {
    func start(port: UInt16)
    func stop()
}

protocol WindowsDiscovering: AnyObject {
    func start(ip: String, port: UInt16)
    func stop()
}

protocol BackgroundShareKeeping: AnyObject {
    func sharingDidStart(onExpire: @escaping () -> Void)
    func sharingDidStop()
    func notifyStoppedBySystem()
}
