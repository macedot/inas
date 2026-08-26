// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import XCTest
@testable import Inas

final class NetworkAddressTests: XCTestCase {
    func testPrefersWiFiOverBridge() {
        let interfaces = [
            NetworkAddress.Interface(name: "lo0", ip: "127.0.0.1", up: true, loopback: true),
            NetworkAddress.Interface(name: "bridge100", ip: "192.168.64.1", up: true, loopback: false),
            NetworkAddress.Interface(name: "en0", ip: "10.0.0.8", up: true, loopback: false)
        ]
        XCTAssertEqual(NetworkAddress.pick(interfaces), "10.0.0.8")
    }

    func testSkipsCellularAWDLAndDownLinks() {
        let interfaces = [
            NetworkAddress.Interface(name: "pdp_ip0", ip: "10.32.0.2", up: true, loopback: false),
            NetworkAddress.Interface(name: "awdl0", ip: "169.254.9.9", up: true, loopback: false),
            NetworkAddress.Interface(name: "utun0", ip: "192.168.1.1", up: true, loopback: false),
            NetworkAddress.Interface(name: "en0", ip: "192.168.1.20", up: false, loopback: false),
            NetworkAddress.Interface(name: "en1", ip: "192.168.1.21", up: true, loopback: false)
        ]
        XCTAssertEqual(NetworkAddress.pick(interfaces), "192.168.1.21")
    }

    func testFallsBackToBridge() {
        let interfaces = [
            NetworkAddress.Interface(name: "bridge0", ip: "172.20.10.1", up: true, loopback: false)
        ]
        XCTAssertEqual(NetworkAddress.pick(interfaces), "172.20.10.1")
    }

    func testEmptyWhenOnlyLoopback() {
        let interfaces = [
            NetworkAddress.Interface(name: "lo0", ip: "127.0.0.1", up: true, loopback: true)
        ]
        XCTAssertNil(NetworkAddress.pick(interfaces))
    }
}
