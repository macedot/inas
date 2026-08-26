// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import Foundation
import Network

/// Windows name resolution and Network-neighborhood discovery.
///
/// Macs find the share via Bonjour `_smb._tcp` (see `BonjourAdvertiser`).
/// Windows Explorer uses WS-Discovery, then LLMNR / mDNS, then SMB on 445.
///
/// Custom multicast (WSD + LLMNR) may be denied on iOS without Apple's
/// multicast entitlement. Bind/join failures are ignored so SMB still works.
/// The `iNAS.local` A record uses the system mDNSResponder (allowed).
final class WindowsDiscovery {
    static let hostName = "iNAS"
    static let localName = "iNAS.local"
    private static let metadataPort: UInt16 = 5357

    private let queue = DispatchQueue(label: "app.inas.discovery")
    private var generation = 0
    private var wsdGroup: NWConnectionGroup?
    private var llmnrGroup: NWConnectionGroup?
    private var metadataListener: NWListener?
    private var mdnsService: DNSServiceRef?
    private var instanceId = "1"
    private var messageNumber: UInt32 = 0
    private var endpointUUID = UUID()
    private var advertisedIP = ""
    private var advertisedPort: UInt16 = 445

    func start(ip: String, port: UInt16) {
        queue.async { [self] in
            stopLocked()
            generation += 1
            advertisedIP = ip
            advertisedPort = port
            instanceId = String(Int(Date().timeIntervalSince1970))
            messageNumber = 0
            endpointUUID = UUID()
            startMDNSHostname()
            startWSD()
            startLLMNR()
            startMetadataHTTP()
        }
    }

    func stop() {
        queue.async { [self] in
            stopLocked()
        }
    }

    private func stopLocked() {
        generation += 1
        sendWSDBye()
        wsdGroup?.cancel()
        wsdGroup = nil
        llmnrGroup?.cancel()
        llmnrGroup = nil
        metadataListener?.cancel()
        metadataListener = nil
        if let mdnsService {
            DNSServiceRefDeallocate(mdnsService)
        }
        mdnsService = nil
    }

    // MARK: - mDNS A record (`iNAS.local`)

    private func startMDNSHostname() {
        let parts = Self.ipv4Bytes(advertisedIP)
        guard parts.count == 4 else { return }

        var sdRef: DNSServiceRef?
        guard DNSServiceCreateConnection(&sdRef) == kDNSServiceErr_NoError, let connected = sdRef else { return }
        guard DNSServiceSetDispatchQueue(connected, queue) == kDNSServiceErr_NoError else {
            DNSServiceRefDeallocate(connected)
            return
        }

        var recordRef: DNSRecordRef?
        let fullName = "\(Self.localName)."
        let err = parts.withUnsafeBytes { buf -> DNSServiceErrorType in
            guard let base = buf.baseAddress else { return DNSServiceErrorType(kDNSServiceErr_Unknown) }
            return fullName.withCString { namePtr in
                DNSServiceRegisterRecord(
                    connected,
                    &recordRef,
                    DNSServiceFlags(kDNSServiceFlagsUnique),
                    0,
                    namePtr,
                    UInt16(kDNSServiceType_A),
                    UInt16(kDNSServiceClass_IN),
                    UInt16(parts.count),
                    base,
                    120,
                    { _, _, _, _, _ in },
                    nil
                )
            }
        }
        guard err == kDNSServiceErr_NoError else {
            DNSServiceRefDeallocate(connected)
            return
        }
        mdnsService = connected
    }

    // MARK: - WS-Discovery (UDP 3702 / 239.255.255.250)

    private func startWSD() {
        do {
            let multicast = try NWMulticastGroup(for: [
                .hostPort(host: NWEndpoint.Host("239.255.255.250"), port: 3702)
            ])
            let group = NWConnectionGroup(with: multicast, using: udpLinkLocalParameters())
            let gen = generation
            group.setReceiveHandler(maximumMessageSize: 64 * 1024, rejectOversizedMessages: true) { [weak self] message, content, _ in
                guard let self, self.generation == gen, let content else { return }
                self.handleWSD(content, reply: message)
            }
            group.stateUpdateHandler = { [weak self] state in
                guard let self, self.generation == gen else { return }
                if case .ready = state {
                    self.sendWSDHello()
                }
                if case .failed = state {
                    group.cancel()
                    if self.wsdGroup === group {
                        self.wsdGroup = nil
                    }
                }
            }
            group.start(queue: queue)
            wsdGroup = group
        } catch {
            // Soft-fail: no multicast entitlement / join denied.
        }
    }

    private func handleWSD(_ data: Data, reply message: NWConnectionGroup.Message) {
        guard let xml = String(data: data, encoding: .utf8) else { return }
        let isProbe = xml.contains("Probe") && xml.contains("http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe")
        guard isProbe else { return }
        let relates = uuidFromXML(xml, tag: "MessageID") ?? "urn:uuid:\(UUID().uuidString)"
        guard let body = wsdProbeMatch(relatesTo: relates).data(using: .utf8) else { return }
        message.reply(content: body)
    }

    private func sendWSDHello() {
        sendWSD(wsdHelloOrBye(action: "Hello"))
    }

    private func sendWSDBye() {
        sendWSD(wsdHelloOrBye(action: "Bye"))
    }

    private func sendWSD(_ xml: String) {
        guard let group = wsdGroup, let data = xml.data(using: .utf8) else { return }
        group.send(content: data, to: nil, message: .default) { _ in }
    }

    private func nextMessageNumber() -> UInt32 {
        messageNumber += 1
        return messageNumber
    }

    private var xaddrs: String {
        "http://\(advertisedIP):\(Self.metadataPort)/\(endpointUUID.uuidString.lowercased())"
    }

    private func wsdHelloOrBye(action: String) -> String {
        let msgID = "urn:uuid:\(UUID().uuidString.lowercased())"
        let n = nextMessageNumber()
        let types = action == "Bye" ? "" : """
        <wsd:Types>wsdp:Device pub:Computer</wsd:Types>
        <wsd:Scopes>wsd.microsoft.com/windows</wsd:Scopes>
        <wsd:XAddrs>\(xaddrs)</wsd:XAddrs>
        <wsd:MetadataVersion>1</wsd:MetadataVersion>
        """
        return """
        <?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof" xmlns:pub="http://schemas.microsoft.com/windows/pub/2005/07">
          <soap:Header>
            <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
            <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/\(action)</wsa:Action>
            <wsa:MessageID>\(msgID)</wsa:MessageID>
            <wsd:AppSequence InstanceId="\(instanceId)" MessageNumber="\(n)"/>
          </soap:Header>
          <soap:Body>
            <wsd:\(action)>
              <wsa:EndpointReference><wsa:Address>urn:uuid:\(endpointUUID.uuidString.lowercased())</wsa:Address></wsa:EndpointReference>
              \(types)
            </wsd:\(action)>
          </soap:Body>
        </soap:Envelope>
        """
    }

    private func wsdProbeMatch(relatesTo: String) -> String {
        let msgID = "urn:uuid:\(UUID().uuidString.lowercased())"
        let n = nextMessageNumber()
        let uuid = endpointUUID.uuidString.lowercased()
        return """
        <?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof" xmlns:pub="http://schemas.microsoft.com/windows/pub/2005/07">
          <soap:Header>
            <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
            <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action>
            <wsa:MessageID>\(msgID)</wsa:MessageID>
            <wsa:RelatesTo>\(relatesTo)</wsa:RelatesTo>
            <wsd:AppSequence InstanceId="\(instanceId)" MessageNumber="\(n)"/>
          </soap:Header>
          <soap:Body>
            <wsd:ProbeMatches>
              <wsd:ProbeMatch>
                <wsa:EndpointReference><wsa:Address>urn:uuid:\(uuid)</wsa:Address></wsa:EndpointReference>
                <wsd:Types>wsdp:Device pub:Computer</wsd:Types>
                <wsd:Scopes>wsd.microsoft.com/windows</wsd:Scopes>
                <wsd:XAddrs>\(xaddrs)</wsd:XAddrs>
                <wsd:MetadataVersion>1</wsd:MetadataVersion>
              </wsd:ProbeMatch>
            </wsd:ProbeMatches>
          </soap:Body>
        </soap:Envelope>
        """
    }

    private func wsdGetResponse(relatesTo: String) -> String {
        let msgID = "urn:uuid:\(UUID().uuidString.lowercased())"
        let uuid = endpointUUID.uuidString.lowercased()
        let name = Self.hostName
        return """
        <?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof" xmlns:wsx="http://schemas.xmlsoap.org/ws/2004/09/mex" xmlns:pub="http://schemas.microsoft.com/windows/pub/2005/07">
          <soap:Header>
            <wsa:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To>
            <wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse</wsa:Action>
            <wsa:MessageID>\(msgID)</wsa:MessageID>
            <wsa:RelatesTo>\(relatesTo)</wsa:RelatesTo>
          </soap:Header>
          <soap:Body>
            <wsx:Metadata>
              <wsx:MetadataSection Dialect="http://schemas.xmlsoap.org/ws/2006/02/devprof/ThisDevice">
                <wsdp:ThisDevice>
                  <wsdp:FriendlyName>\(name)</wsdp:FriendlyName>
                  <wsdp:FirmwareVersion>1.0</wsdp:FirmwareVersion>
                  <wsdp:SerialNumber>1</wsdp:SerialNumber>
                </wsdp:ThisDevice>
              </wsx:MetadataSection>
              <wsx:MetadataSection Dialect="http://schemas.xmlsoap.org/ws/2006/02/devprof/ThisModel">
                <wsdp:ThisModel>
                  <wsdp:Manufacturer>iNAS</wsdp:Manufacturer>
                  <wsdp:ModelName>iNAS</wsdp:ModelName>
                  <wsdp:ModelNumber>1</wsdp:ModelNumber>
                </wsdp:ThisModel>
              </wsx:MetadataSection>
              <wsx:MetadataSection Dialect="http://schemas.xmlsoap.org/ws/2006/02/devprof/Relationship">
                <wsdp:Relationship Type="http://schemas.xmlsoap.org/ws/2006/02/devprof/host">
                  <wsdp:Host>
                    <wsa:EndpointReference><wsa:Address>urn:uuid:\(uuid)</wsa:Address></wsa:EndpointReference>
                    <wsdp:Types>pub:Computer</wsdp:Types>
                    <wsdp:ServiceId>urn:uuid:\(uuid)</wsdp:ServiceId>
                    <pub:Computer>\(name)/Workgroup:WORKGROUP</pub:Computer>
                  </wsdp:Host>
                </wsdp:Relationship>
              </wsx:MetadataSection>
            </wsx:Metadata>
          </soap:Body>
        </soap:Envelope>
        """
    }

    private func uuidFromXML(_ xml: String, tag: String) -> String? {
        guard let start = xml.range(of: "<wsa:\(tag)>") ?? xml.range(of: "<\(tag)>") else { return nil }
        let rest = xml[start.upperBound...]
        guard let end = rest.range(of: "</") else { return nil }
        let value = rest[..<end.lowerBound].trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : String(value)
    }

    // MARK: - WSD metadata HTTP (TCP 5357)

    private func startMetadataHTTP() {
        do {
            let params = NWParameters.tcp
            params.allowLocalEndpointReuse = true
            params.includePeerToPeer = false
            let listener = try NWListener(using: params, on: NWEndpoint.Port(rawValue: Self.metadataPort)!)
            let gen = generation
            listener.newConnectionHandler = { [weak self] connection in
                guard let self, self.generation == gen else {
                    connection.cancel()
                    return
                }
                self.handleMetadataConnection(connection)
            }
            listener.stateUpdateHandler = { [weak self] state in
                guard let self, self.generation == gen else { return }
                if case .failed = state {
                    listener.cancel()
                    if self.metadataListener === listener {
                        self.metadataListener = nil
                    }
                }
            }
            listener.start(queue: queue)
            metadataListener = listener
        } catch {
            // Soft-fail.
        }
    }

    private func handleMetadataConnection(_ connection: NWConnection) {
        connection.start(queue: queue)
        receiveHTTP(connection, accumulated: Data())
    }

    private func receiveHTTP(_ connection: NWConnection, accumulated: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] content, _, isComplete, error in
            guard let self else {
                connection.cancel()
                return
            }
            if error != nil {
                connection.cancel()
                return
            }
            var buffer = accumulated
            if let content {
                buffer.append(content)
            }
            if let request = String(data: buffer, encoding: .utf8),
               request.contains("\r\n\r\n") {
                let relates = self.uuidFromXML(request, tag: "MessageID") ?? "urn:uuid:\(UUID().uuidString.lowercased())"
                self.sendMetadataResponse(on: connection, relatesTo: relates)
                return
            }
            if isComplete || buffer.count > 64 * 1024 {
                connection.cancel()
                return
            }
            self.receiveHTTP(connection, accumulated: buffer)
        }
    }

    private func sendMetadataResponse(on connection: NWConnection, relatesTo: String) {
        let xml = wsdGetResponse(relatesTo: relatesTo)
        let body = Data(xml.utf8)
        var header = "HTTP/1.1 200 OK\r\n"
        header += "Content-Type: application/soap+xml; charset=utf-8\r\n"
        header += "Content-Length: \(body.count)\r\n"
        header += "Connection: close\r\n\r\n"
        var packet = Data(header.utf8)
        packet.append(body)
        connection.send(content: packet, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { _ in
            connection.cancel()
        })
    }

    // MARK: - LLMNR (UDP 5355 / 224.0.0.252)

    private func startLLMNR() {
        do {
            let multicast = try NWMulticastGroup(for: [
                .hostPort(host: NWEndpoint.Host("224.0.0.252"), port: 5355)
            ])
            let group = NWConnectionGroup(with: multicast, using: udpLinkLocalParameters())
            let gen = generation
            group.setReceiveHandler(maximumMessageSize: 4096, rejectOversizedMessages: true) { [weak self] message, content, _ in
                guard let self, self.generation == gen, let content else { return }
                if let reply = Self.llmnrReply(for: content, hostName: Self.hostName, ipv4: self.advertisedIP) {
                    message.reply(content: reply)
                }
            }
            group.stateUpdateHandler = { [weak self] state in
                guard let self, self.generation == gen else { return }
                if case .failed = state {
                    group.cancel()
                    if self.llmnrGroup === group {
                        self.llmnrGroup = nil
                    }
                }
            }
            group.start(queue: queue)
            llmnrGroup = group
        } catch {
            // Soft-fail.
        }
    }

    static func llmnrReply(for query: Data, hostName: String, ipv4: String) -> Data? {
        guard query.count >= 12 else { return nil }
        let flags = UInt16(query[2]) << 8 | UInt16(query[3])
        if (flags & 0x8000) != 0 { return nil }
        let qdcount = Int(query[4]) << 8 | Int(query[5])
        guard qdcount >= 1 else { return nil }

        var offset = 12
        var labels: [String] = []
        while offset < query.count {
            let len = Int(query[offset])
            if len == 0 {
                offset += 1
                break
            }
            guard len < 64, offset + 1 + len <= query.count else { return nil }
            let label = String(bytes: query[(offset + 1)..<(offset + 1 + len)], encoding: .utf8) ?? ""
            labels.append(label)
            offset += 1 + len
        }
        guard offset + 4 <= query.count else { return nil }
        let qtype = UInt16(query[offset]) << 8 | UInt16(query[offset + 1])
        offset += 4
        let qname = labels.joined(separator: ".")
        guard qname.caseInsensitiveCompare(hostName) == .orderedSame else { return nil }
        guard qtype == 1 || qtype == 255 else { return nil }

        let parts = ipv4Bytes(ipv4)
        guard parts.count == 4 else { return nil }

        var response = Data()
        response.append(query[0])
        response.append(query[1])
        response.append(contentsOf: [0x80, 0x00])
        response.append(contentsOf: [0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])
        response.append(query[12..<offset])
        response.append(contentsOf: [0xC0, 0x0C])
        response.append(contentsOf: [0x00, 0x01, 0x00, 0x01])
        response.append(contentsOf: [0x00, 0x00, 0x00, 0x1E])
        response.append(contentsOf: [0x00, 0x04])
        response.append(contentsOf: parts)
        return response
    }

    // MARK: - Helpers

    private func udpLinkLocalParameters() -> NWParameters {
        let params = NWParameters.udp
        params.allowLocalEndpointReuse = true
        params.includePeerToPeer = false
        if let ip = params.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options {
            ip.version = .v4
            ip.hopLimit = 1
        }
        return params
    }

    private static func ipv4Bytes(_ ip: String) -> [UInt8] {
        let parts = ip.split(separator: ".").compactMap { UInt8($0) }
        return parts.count == 4 ? parts : []
    }
}
