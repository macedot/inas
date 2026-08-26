// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import Darwin
import Foundation

final class BonjourAdvertiser: BonjourAdvertising {
    static let serviceName = "iNAS"
    private var service: DNSServiceRef?

    func start(port: UInt16) {
        stop()
        let pair = "path=/inas"
        var txt = Data([UInt8(pair.utf8.count)])
        txt.append(contentsOf: pair.utf8)
        var sdRef: DNSServiceRef?
        let err: DNSServiceErrorType = txt.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return DNSServiceErrorType(kDNSServiceErr_Unknown) }
            return Self.serviceName.withCString { namePtr in
                "_smb._tcp".withCString { typePtr in
                    DNSServiceRegister(
                        &sdRef,
                        0,
                        0,
                        namePtr,
                        typePtr,
                        "local.",
                        nil,
                        port.bigEndian,
                        UInt16(txt.count),
                        base,
                        nil,
                        nil
                    )
                }
            }
        }
        guard err == kDNSServiceErr_NoError, let registered = sdRef else { return }
        guard DNSServiceSetDispatchQueue(registered, .main) == kDNSServiceErr_NoError else {
            DNSServiceRefDeallocate(registered)
            return
        }
        service = registered
    }

    func stop() {
        if let service {
            DNSServiceRefDeallocate(service)
        }
        service = nil
    }

    deinit {
        stop()
    }
}
