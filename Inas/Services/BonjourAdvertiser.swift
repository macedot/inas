// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import Foundation

final class BonjourAdvertiser: NSObject, NetServiceDelegate {
    static let serviceName = "iNAS"

    private var netService: NetService?

    func start(port: UInt16) {
        stop()
        let service = NetService(domain: "local.", type: "_smb._tcp.", name: Self.serviceName, port: Int32(port))
        service.includesPeerToPeer = false
        service.delegate = self
        service.setTXTRecord(NetService.data(fromTXTRecord: ["path": Data("/inas".utf8)]))
        service.publish()
        netService = service
    }

    func stop() {
        netService?.stop()
        netService?.delegate = nil
        netService = nil
    }
}
