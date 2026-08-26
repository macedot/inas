// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import XCTest
@testable import Inas

final class WindowsDiscoveryTests: XCTestCase {
    func testLLMNRReplyForINAS() throws {
        var query = Data()
        query.append(contentsOf: [0x12, 0x34])
        query.append(contentsOf: [0x00, 0x00])
        query.append(contentsOf: [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        query.append(4)
        query.append(contentsOf: Array("iNAS".utf8))
        query.append(0)
        query.append(contentsOf: [0x00, 0x01, 0x00, 0x01])

        let reply = WindowsDiscovery.llmnrReply(for: query, hostName: "iNAS", ipv4: "10.0.0.5")
        XCTAssertNotNil(reply)
        let data = try XCTUnwrap(reply)
        XCTAssertEqual(data[0], 0x12)
        XCTAssertEqual(data[1], 0x34)
        XCTAssertEqual(data[2], 0x80)
        XCTAssertEqual(Array(data.suffix(4)), [10, 0, 0, 5])
    }

    func testLLMNRIgnoresOtherNames() {
        var query = Data()
        query.append(contentsOf: [0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        query.append(2)
        query.append(contentsOf: Array("pc".utf8))
        query.append(0)
        query.append(contentsOf: [0x00, 0x01, 0x00, 0x01])
        XCTAssertNil(WindowsDiscovery.llmnrReply(for: query, hostName: "iNAS", ipv4: "10.0.0.5"))
    }

    func testWindowsUNCHints() {
        let on445 = SMBEndpoint(ip: "192.168.1.8", port: 445)
        XCTAssertEqual(on445.windowsHint, "\\\\192.168.1.8")
        XCTAssertEqual(on445.windowsNameHint, "\\\\iNAS.local")
        XCTAssertEqual(on445.smbURL, "smb://192.168.1.8")

        let on4455 = SMBEndpoint(ip: "192.168.1.8", port: 4455)
        XCTAssertEqual(on4455.windowsHint, "\\\\192.168.1.8@4455")
        XCTAssertNil(on4455.windowsNameHint)
        XCTAssertEqual(on4455.smbURL, "smb://192.168.1.8:4455")
    }

    func testLLMNRIgnoresResponsesAndShortPackets() {
        var response = Data([0x00, 0x01, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        response.append(4)
        response.append(contentsOf: Array("iNAS".utf8))
        response.append(0)
        response.append(contentsOf: [0x00, 0x01, 0x00, 0x01])
        XCTAssertNil(WindowsDiscovery.llmnrReply(for: response, hostName: "iNAS", ipv4: "10.0.0.5"))
        XCTAssertNil(WindowsDiscovery.llmnrReply(for: Data([0x00, 0x01]), hostName: "iNAS", ipv4: "10.0.0.5"))
    }

    func testLLMNRIsCaseInsensitiveAndAcceptsANY() throws {
        var query = Data()
        query.append(contentsOf: [0xAB, 0xCD, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        query.append(4)
        query.append(contentsOf: Array("inas".utf8))
        query.append(0)
        query.append(contentsOf: [0x00, 0xFF, 0x00, 0x01])
        let reply = try XCTUnwrap(WindowsDiscovery.llmnrReply(for: query, hostName: "iNAS", ipv4: "192.168.0.9"))
        XCTAssertEqual(Array(reply.suffix(4)), [192, 168, 0, 9])
    }

    func testXMLEscapesInjection() {
        XCTAssertEqual(WSDMessageBuilder.xmlEscaped("a<b>&\"'"), "a&lt;b&gt;&amp;&quot;&apos;")
        XCTAssertEqual(
            WSDMessageBuilder.xmlEscaped("urn:uuid:1</wsa:RelatesTo><wsa:Action>x"),
            "urn:uuid:1&lt;/wsa:RelatesTo&gt;&lt;wsa:Action&gt;x"
        )
        XCTAssertEqual(WindowsDiscovery.xmlEscaped("<x>"), "&lt;x&gt;")
    }

    func testHTTPRequestCompleteAndMessageID() {
        let headers = "POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\n"
        XCTAssertFalse(WSDMessageBuilder.httpRequestComplete(Data(headers.utf8)))
        XCTAssertTrue(HTTPRequestParser.isComplete(Data((headers + "hello").utf8)))
        XCTAssertTrue(WSDMessageBuilder.httpRequestComplete(Data((headers + "hello").utf8)))
        XCTAssertTrue(WSDMessageBuilder.httpRequestComplete(Data("GET / HTTP/1.1\r\n\r\n".utf8)))
        XCTAssertFalse(WSDMessageBuilder.httpRequestComplete(Data("GET / HTTP/1.1\r\n".utf8)))
        XCTAssertEqual(
            WSDMessageBuilder.uuidFromXML("<wsa:MessageID>urn:uuid:abc</wsa:MessageID>", tag: "MessageID"),
            "urn:uuid:abc"
        )
        XCTAssertNil(WSDMessageBuilder.uuidFromXML("<wsa:MessageID></wsa:MessageID>", tag: "MessageID"))
    }

    func testWSDActionDistinguishesProbeFromProbeMatches() {
        let probe = "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>"
        let matches = "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action>"
        XCTAssertTrue(WindowsDiscovery.wsdAction(probe).hasSuffix("/Probe"))
        XCTAssertFalse(WindowsDiscovery.wsdAction(probe).hasSuffix("/ProbeMatches"))
        XCTAssertTrue(WindowsDiscovery.wsdAction(matches).hasSuffix("/ProbeMatches"))
        XCTAssertFalse(WindowsDiscovery.wsdAction(matches).hasSuffix("/Probe") && !WindowsDiscovery.wsdAction(matches).hasSuffix("/ProbeMatches"))
    }

    func testSubnetBroadcast() {
        XCTAssertEqual(WindowsDiscovery.subnetBroadcast(for: "192.168.1.8"), "192.168.1.255")
        XCTAssertNil(WindowsDiscovery.subnetBroadcast(for: "not-an-ip"))
    }

    func testLLMNRRejectsCompressionPointers() {
        var query = Data()
        query.append(contentsOf: [0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        query.append(0xC0)
        query.append(0x0C)
        query.append(contentsOf: [0x00, 0x01, 0x00, 0x01])
        XCTAssertNil(WindowsDiscovery.llmnrReply(for: query, hostName: "iNAS", ipv4: "10.0.0.5"))
    }
}
