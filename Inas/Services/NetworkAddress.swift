// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import Darwin
import Foundation

enum NetworkAddress {
    struct Interface: Equatable {
        var name: String
        var ip: String
        var up: Bool
        var loopback: Bool
    }

    static func lanIPv4() -> String? {
        pick(interfaces())
    }

    /// Wi-Fi (`en*`) first, then a bridge; never loopback, cellular, or AWDL.
    static func pick(_ interfaces: [Interface]) -> String? {
        let usable = interfaces.filter { iface in
            guard iface.up, !iface.loopback else { return false }
            return iface.name.hasPrefix("en") || iface.name.hasPrefix("bridge")
        }
        if let wifi = usable.first(where: { $0.name.hasPrefix("en") }) {
            return wifi.ip
        }
        return usable.first?.ip
    }

    private static func interfaces() -> [Interface] {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return [] }
        defer { freeifaddrs(ifaddr) }

        var result: [Interface] = []
        for ptr in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let interface = ptr.pointee
            guard interface.ifa_addr.pointee.sa_family == UInt8(AF_INET) else { continue }
            let flags = Int32(interface.ifa_flags)
            var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let rc = getnameinfo(
                interface.ifa_addr,
                socklen_t(interface.ifa_addr.pointee.sa_len),
                &hostname,
                socklen_t(hostname.count),
                nil,
                0,
                NI_NUMERICHOST
            )
            guard rc == 0 else { continue }
            result.append(
                Interface(
                    name: String(cString: interface.ifa_name),
                    ip: String(cString: hostname),
                    up: (flags & IFF_UP) == IFF_UP,
                    loopback: (flags & IFF_LOOPBACK) == IFF_LOOPBACK
                )
            )
        }
        return result
    }
}
