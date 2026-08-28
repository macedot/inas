// Copyright (C) 2026 Thiago Macedo
// SPDX-License-Identifier: AGPL-3.0-or-later

import Darwin
import Foundation
import Network

/// Windows name resolution and Network-neighborhood discovery.
///
/// Macs find the share via Bonjour `_smb._tcp` (see `BonjourAdvertiser`).
/// Windows Explorer lists computers with WS-Discovery (UDP 3702), then
/// fetches metadata over HTTP 5357, then connects to SMB on 445.
final class WindowsDiscovery: WindowsDiscovering {
    static let hostName = "iNAS"
    static let localName = "iNAS.local"
    private static let metadataPort: UInt16 = 5357
    private static let wsdPort: UInt16 = 3702
    private static let wsdGroup = "239.255.255.250"
    private static let llmnrPort: UInt16 = 5355
    private static let llmnrGroup = "224.0.0.252"
    private static let anonymousTo = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"

    private let queue = DispatchQueue(label: "app.inas.discovery")
    private var session: Session?
    /// WiFi-flap resilience: discovery sockets bind the share-start IP; if
    /// the interface address changes (DHCP renew, network drop), rebuild the
    /// session so responders keep answering.
    private var lastAdvertisedIP: String?
    private var advertisedPort: UInt16 = 0
    private var pathMonitor: NWPathMonitor?

    /// Per-peer token bucket for UDP Probe/Resolve and LLMNR replies.
    /// 5 tokens/s, burst of 3, at most 32 tracked addresses.
    struct ReplyBudget {
        struct Bucket {
            var tokens: Double
            var lastRefill: Date
        }

        var table: [String: Bucket] = [:]
        let rate = 5.0
        let burst = 3.0
        let maxIPs = 32

        mutating func allow(ip: String, now: Date) -> Bool {
            prune(reserving: ip)
            var bucket = table[ip] ?? Bucket(tokens: burst, lastRefill: now)
            let elapsed = now.timeIntervalSince(bucket.lastRefill)
            bucket.tokens = min(burst, bucket.tokens + elapsed * rate)
            bucket.lastRefill = now
            if bucket.tokens >= 1 {
                bucket.tokens -= 1
                table[ip] = bucket
                return true
            }
            table[ip] = bucket
            return false
        }

        mutating func prune(reserving ip: String) {
            if table[ip] != nil { return }
            guard table.count >= maxIPs else { return }
            if let oldest = table.min(by: { $0.value.lastRefill < $1.value.lastRefill })?.key {
                table.removeValue(forKey: oldest)
            }
        }
    }

    private final class Session {
        let advertisedIP: String
        let advertisedPort: UInt16
        let instanceId: String
        let endpointUUID: UUID
        var messageNumber: UInt32 = 0
        var replyBudget = ReplyBudget()
        var wsdFD: Int32 = -1
        var llmnrFD: Int32 = -1
        var wsdSource: DispatchSourceRead?
        var llmnrSource: DispatchSourceRead?
        var helloTimer: DispatchSourceTimer?
        var metadataListener: NWListener?
        var mdnsService: DNSServiceRef?

        init(ip: String, port: UInt16) {
            advertisedIP = ip
            advertisedPort = port
            instanceId = String(Int(Date().timeIntervalSince1970))
            endpointUUID = UUID()
        }

        func invalidate() {
            helloTimer?.cancel()
            helloTimer = nil
            wsdSource?.cancel()
            wsdSource = nil
            llmnrSource?.cancel()
            llmnrSource = nil
            wsdFD = -1
            llmnrFD = -1
            metadataListener?.cancel()
            metadataListener = nil
            if let mdnsService {
                DNSServiceRefDeallocate(mdnsService)
            }
            mdnsService = nil
        }
    }

    func start(ip: String, port: UInt16) {
        queue.async { [self] in
            stopLocked()
            lastAdvertisedIP = ip
            advertisedPort = port
            startPathMonitor()
            let next = Session(ip: ip, port: port)
            session = next
            startMDNSHostname(next)
            startWSD(next)
            startLLMNR(next)
            startMetadataHTTP(next)
            sendHelloBurst(next)
            startHelloTimer(next)
        }
    }

    private func startPathMonitor() {
        guard pathMonitor == nil else { return }
        let monitor = NWPathMonitor()
        pathMonitor = monitor
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            self.queue.async { [weak self] in
                guard let self, let currentIP = Self.primaryIPv4(on: path) else { return }
                let port = self.advertisedPort
                guard port != 0, currentIP != self.lastAdvertisedIP else {
                    return
                }
                self.lastAdvertisedIP = currentIP
                let next = Session(ip: currentIP, port: port)
                self.stopLocked()
                self.session = next
                self.startMDNSHostname(next)
                self.startWSD(next)
                self.startLLMNR(next)
                self.startMetadataHTTP(next)
                self.sendHelloBurst(next)
                self.startHelloTimer(next)
            }
        }
        monitor.start(queue: queue)
    }

    /// Best-effort primary IPv4 of the current default path.
    private static func primaryIPv4(on path: NWPath) -> String? {
        guard path.status == .satisfied, let iface = path.availableInterfaces.first else {
            return nil
        }
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return nil }
        defer { freeifaddrs(ifaddr) }
        var result: String?
        var ptr: UnsafeMutablePointer<ifaddrs>? = first
        while let curPtr = ptr {
            let cur = curPtr.pointee
            defer { ptr = cur.ifa_next }
            guard let sa = cur.ifa_addr, let name0 = cur.ifa_name,
                  String(cString: name0) == iface.name,
                  sa.pointee.sa_family == UInt8(AF_INET) else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(sa, socklen_t(MemoryLayout<sockaddr_in>.size), &host,
                           socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                let ip = String(cString: host)
                if !ip.hasPrefix("169.254.") { // ignore self-assigned
                    result = ip
                    break
                }
            }
        }
        return result
    }

    func stop() {
        queue.async { [self] in
            stopLocked()
            pathMonitor?.cancel()
            pathMonitor = nil
            lastAdvertisedIP = nil
            advertisedPort = 0
        }
    }

    private func stopLocked() {
        guard let current = session else { return }
        sendWSDMulticast(wsdHelloOrBye(action: "Bye", session: current), session: current)
        current.invalidate()
        session = nil
    }

    private func isCurrent(_ s: Session) -> Bool {
        session === s
    }

    // MARK: - mDNS A record (`iNAS.local`)

    private func startMDNSHostname(_ session: Session) {
        let parts = Self.ipv4Bytes(session.advertisedIP)
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
        session.mdnsService = connected
    }

    // MARK: - WS-Discovery (UDP 3702)

    private func startWSD(_ session: Session) {
        let fd = session.advertisedIP.withCString { ipPtr in
            Self.wsdGroup.withCString { grpPtr in
                inas_udp_open(ipPtr, Self.wsdPort, grpPtr, 1)
            }
        }
        guard fd >= 0 else { return }
        session.wsdFD = fd
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler { [weak self] in
            guard let self, self.isCurrent(session) else { return }
            self.drainWSD(session, fd: fd)
        }
        source.setCancelHandler {
            inas_udp_close(fd)
            session.wsdFD = -1
        }
        source.resume()
        session.wsdSource = source
    }

    private func drainWSD(_ session: Session, fd: Int32) {
        guard isCurrent(session) else { return }
        var buf = [UInt8](repeating: 0, count: 32 * 1024)
        var srcIP = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        var srcPort: UInt16 = 0
        while true {
            let n = buf.withUnsafeMutableBytes { raw -> Int32 in
                guard let base = raw.baseAddress else { return 0 }
                return inas_udp_recvfrom(fd, base, Int32(raw.count), &srcIP, Int32(srcIP.count), &srcPort)
            }
            if n <= 0 { break }
            let data = Data(buf.prefix(Int(n)))
            let ip = String(cString: srcIP)
            handleWSD(data, from: ip, port: srcPort, session: session)
        }
    }

    private func handleWSD(_ data: Data, from ip: String, port: UInt16, session: Session) {
        guard isCurrent(session), let xml = String(data: data, encoding: .utf8) else { return }
        let action = Self.wsdAction(xml)
        let isProbe = action.hasSuffix("/Probe") && !action.hasSuffix("/ProbeMatches")
        let isResolve = action.hasSuffix("/Resolve") && !action.hasSuffix("/ResolveMatches")
        guard isProbe || isResolve else { return }
        guard session.replyBudget.allow(ip: ip, now: Date()) else { return }
        let relates = Self.uuidFromXML(xml, tag: "MessageID") ?? "urn:uuid:\(UUID().uuidString.lowercased())"
        if isProbe {
            sendWSDUnicast(wsdProbeMatch(relatesTo: relates, session: session), to: ip, port: port, session: session)
            return
        }
        sendWSDUnicast(wsdResolveMatch(relatesTo: relates, session: session), to: ip, port: port, session: session)
    }

    private func sendHelloBurst(_ session: Session) {
        let xml = wsdHelloOrBye(action: "Hello", session: session)
        sendWSDMulticast(xml, session: session)
        let delays: [Double] = [0.08, 0.2, 0.45]
        for delay in delays {
            queue.asyncAfter(deadline: .now() + delay) { [weak self] in
                guard let self, self.isCurrent(session) else { return }
                self.sendWSDMulticast(xml, session: session)
            }
        }
    }

    private func startHelloTimer(_ session: Session) {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 15, repeating: 20)
        timer.setEventHandler { [weak self] in
            guard let self, self.isCurrent(session) else { return }
            self.sendWSDMulticast(self.wsdHelloOrBye(action: "Hello", session: session), session: session)
        }
        timer.resume()
        session.helloTimer = timer
    }

    private func sendWSDMulticast(_ xml: String, session: Session) {
        sendWSDUnicast(xml, to: Self.wsdGroup, port: Self.wsdPort, session: session)
        if let bcast = Self.subnetBroadcast(for: session.advertisedIP) {
            sendWSDUnicast(xml, to: bcast, port: Self.wsdPort, session: session)
        }
    }

    private func sendWSDUnicast(_ xml: String, to ip: String, port: UInt16, session: Session) {
        guard session.wsdFD >= 0, let data = xml.data(using: .utf8) else { return }
        data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            ip.withCString { ipPtr in
                _ = inas_udp_sendto(session.wsdFD, ipPtr, port, base, Int32(data.count))
            }
        }
    }

    private func nextMessageNumber(_ session: Session) -> UInt32 {
        session.messageNumber += 1
        return session.messageNumber
    }

    private func xaddrs(_ session: Session) -> String {
        "http://\(session.advertisedIP):\(Self.metadataPort)/\(session.endpointUUID.uuidString.lowercased())"
    }

    private var computerName: String {
        "\(Self.hostName.uppercased())/Workgroup:WORKGROUP"
    }

    static func xmlEscaped(_ value: String) -> String {
        WSDMessageBuilder.xmlEscaped(value)
    }

    static func wsdAction(_ xml: String) -> String {
        WSDMessageBuilder.soapAction(xml)
    }

    private func wsdHelloOrBye(action: String, session: Session) -> String {
        let msgID = "urn:uuid:\(UUID().uuidString.lowercased())"
        let n = nextMessageNumber(session)
        let types = action == "Bye" ? "" : """
        <wsd:Types>wsdp:Device pub:Computer</wsd:Types>
        <wsd:XAddrs>\(xaddrs(session))</wsd:XAddrs>
        <wsd:MetadataVersion>1</wsd:MetadataVersion>
        """
        return """
        <?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof" xmlns:pub="http://schemas.microsoft.com/windows/pub/2005/07" xmlns:pnpx="http://schemas.microsoft.com/windows/pnpx/2005/10">
          <soap:Header>
            <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
            <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/\(action)</wsa:Action>
            <wsa:MessageID>\(msgID)</wsa:MessageID>
            <wsd:AppSequence InstanceId="\(session.instanceId)" SequenceId="urn:uuid:\(session.endpointUUID.uuidString.lowercased())" MessageNumber="\(n)"/>
          </soap:Header>
          <soap:Body>
            <wsd:\(action)>
              <wsa:EndpointReference><wsa:Address>urn:uuid:\(session.endpointUUID.uuidString.lowercased())</wsa:Address></wsa:EndpointReference>
              \(types)
            </wsd:\(action)>
          </soap:Body>
        </soap:Envelope>
        """
    }

    private func wsdProbeMatch(relatesTo: String, session: Session) -> String {
        wsdMatch(kind: "Probe", relatesTo: relatesTo, includeXAddrs: true, session: session)
    }

    private func wsdResolveMatch(relatesTo: String, session: Session) -> String {
        wsdMatch(kind: "Resolve", relatesTo: relatesTo, includeXAddrs: true, session: session)
    }

    private func wsdMatch(kind: String, relatesTo: String, includeXAddrs: Bool, session: Session) -> String {
        let msgID = "urn:uuid:\(UUID().uuidString.lowercased())"
        let n = nextMessageNumber(session)
        let uuid = session.endpointUUID.uuidString.lowercased()
        let xaddr = includeXAddrs ? "<wsd:XAddrs>\(xaddrs(session))</wsd:XAddrs>" : ""
        return """
        <?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof" xmlns:pub="http://schemas.microsoft.com/windows/pub/2005/07" xmlns:pnpx="http://schemas.microsoft.com/windows/pnpx/2005/10">
          <soap:Header>
            <wsa:To>\(Self.anonymousTo)</wsa:To>
            <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/\(kind)Matches</wsa:Action>
            <wsa:MessageID>\(msgID)</wsa:MessageID>
            <wsa:RelatesTo>\(Self.xmlEscaped(relatesTo))</wsa:RelatesTo>
            <wsd:AppSequence InstanceId="\(session.instanceId)" SequenceId="urn:uuid:\(uuid)" MessageNumber="\(n)"/>
          </soap:Header>
          <soap:Body>
            <wsd:\(kind)Matches>
              <wsd:\(kind)Match>
                <wsa:EndpointReference><wsa:Address>urn:uuid:\(uuid)</wsa:Address></wsa:EndpointReference>
                <wsd:Types>wsdp:Device pub:Computer</wsd:Types>
                \(xaddr)
                <wsd:MetadataVersion>1</wsd:MetadataVersion>
              </wsd:\(kind)Match>
            </wsd:\(kind)Matches>
          </soap:Body>
        </soap:Envelope>
        """
    }

    private func wsdGetResponse(relatesTo: String, session: Session) -> String {
        let msgID = "urn:uuid:\(UUID().uuidString.lowercased())"
        let uuid = session.endpointUUID.uuidString.lowercased()
        let name = Self.hostName
        return """
        <?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof" xmlns:wsx="http://schemas.xmlsoap.org/ws/2004/09/mex" xmlns:pub="http://schemas.microsoft.com/windows/pub/2005/07" xmlns:pnpx="http://schemas.microsoft.com/windows/pnpx/2005/10">
          <soap:Header>
            <wsa:To>\(Self.anonymousTo)</wsa:To>
            <wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse</wsa:Action>
            <wsa:MessageID>\(msgID)</wsa:MessageID>
            <wsa:RelatesTo>\(Self.xmlEscaped(relatesTo))</wsa:RelatesTo>
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
                  <pnpx:DeviceCategory>Computers</pnpx:DeviceCategory>
                </wsdp:ThisModel>
              </wsx:MetadataSection>
              <wsx:MetadataSection Dialect="http://schemas.xmlsoap.org/ws/2006/02/devprof/Relationship">
                <wsdp:Relationship Type="http://schemas.xmlsoap.org/ws/2006/02/devprof/host">
                  <wsdp:Host>
                    <wsa:EndpointReference><wsa:Address>urn:uuid:\(uuid)</wsa:Address></wsa:EndpointReference>
                    <wsdp:Types>pub:Computer</wsdp:Types>
                    <wsdp:ServiceId>urn:uuid:\(uuid)</wsdp:ServiceId>
                    <pub:Computer>\(computerName)</pub:Computer>
                  </wsdp:Host>
                </wsdp:Relationship>
              </wsx:MetadataSection>
            </wsx:Metadata>
          </soap:Body>
        </soap:Envelope>
        """
    }

    static func uuidFromXML(_ xml: String, tag: String) -> String? {
        WSDMessageBuilder.uuidFromXML(xml, tag: tag)
    }

    // MARK: - WSD metadata HTTP (TCP 5357)

    private func startMetadataHTTP(_ session: Session) {
        do {
            let params = NWParameters.tcp
            params.allowLocalEndpointReuse = true
            params.includePeerToPeer = false
            if let addr = IPv4Address(session.advertisedIP) {
                params.requiredLocalEndpoint = .hostPort(
                    host: .ipv4(addr),
                    port: NWEndpoint.Port(rawValue: Self.metadataPort)!
                )
            }
            let listener = try NWListener(using: params, on: NWEndpoint.Port(rawValue: Self.metadataPort)!)
            listener.newConnectionHandler = { [weak self] connection in
                guard let self, self.isCurrent(session) else {
                    connection.cancel()
                    return
                }
                self.handleMetadataConnection(connection, session: session)
            }
            listener.stateUpdateHandler = { [weak self] state in
                guard let self, self.isCurrent(session) else { return }
                if case .failed = state {
                    listener.cancel()
                    if session.metadataListener === listener {
                        session.metadataListener = nil
                    }
                }
            }
            listener.start(queue: queue)
            session.metadataListener = listener
        } catch {
            // Soft-fail.
        }
    }

    private func handleMetadataConnection(_ connection: NWConnection, session: Session) {
        connection.start(queue: queue)
        receiveHTTP(connection, accumulated: Data(), session: session)
    }

    private func receiveHTTP(_ connection: NWConnection, accumulated: Data, session: Session) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] content, _, isComplete, error in
            guard let self, self.isCurrent(session) else {
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
            if Self.httpRequestComplete(buffer) {
                let request = String(data: buffer, encoding: .utf8) ?? ""
                let relates = Self.uuidFromXML(request, tag: "MessageID") ?? "urn:uuid:\(UUID().uuidString.lowercased())"
                self.sendMetadataResponse(on: connection, relatesTo: relates, session: session)
                return
            }
            if isComplete || buffer.count > 64 * 1024 {
                connection.cancel()
                return
            }
            self.receiveHTTP(connection, accumulated: buffer, session: session)
        }
    }

    static func httpRequestComplete(_ data: Data) -> Bool {
        WSDMessageBuilder.httpRequestComplete(data)
    }

    private func sendMetadataResponse(on connection: NWConnection, relatesTo: String, session: Session) {
        let xml = wsdGetResponse(relatesTo: relatesTo, session: session)
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

    // MARK: - LLMNR (UDP 5355)

    private func startLLMNR(_ session: Session) {
        let fd = session.advertisedIP.withCString { ipPtr in
            Self.llmnrGroup.withCString { grpPtr in
                inas_udp_open(ipPtr, Self.llmnrPort, grpPtr, 1)
            }
        }
        guard fd >= 0 else { return }
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler { [weak self] in
            guard let self, self.isCurrent(session) else { return }
            self.drainLLMNR(session, fd: fd)
        }
        source.setCancelHandler {
            inas_udp_close(fd)
        }
        source.resume()
        session.llmnrSource = source
        session.llmnrFD = fd
    }

    private func drainLLMNR(_ session: Session, fd: Int32) {
        guard isCurrent(session) else { return }
        var buf = [UInt8](repeating: 0, count: 4096)
        var srcIP = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        var srcPort: UInt16 = 0
        while true {
            let n = buf.withUnsafeMutableBytes { raw -> Int32 in
                guard let base = raw.baseAddress else { return 0 }
                return inas_udp_recvfrom(fd, base, Int32(raw.count), &srcIP, Int32(srcIP.count), &srcPort)
            }
            if n <= 0 { break }
            let query = Data(buf.prefix(Int(n)))
            guard let reply = Self.llmnrReply(for: query, hostName: Self.hostName, ipv4: session.advertisedIP) else { continue }
            let ip = String(cString: srcIP)
            guard session.replyBudget.allow(ip: ip, now: Date()) else { continue }
            reply.withUnsafeBytes { raw in
                guard let base = raw.baseAddress else { return }
                ip.withCString { ipPtr in
                    _ = inas_udp_sendto(fd, ipPtr, srcPort, base, Int32(reply.count))
                }
            }
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

    private static func ipv4Bytes(_ ip: String) -> [UInt8] {
        let parts = ip.split(separator: ".").compactMap { UInt8($0) }
        return parts.count == 4 ? parts : []
    }

    static func subnetBroadcast(for ip: String) -> String? {
        let parts = ipv4Bytes(ip)
        guard parts.count == 4 else { return nil }
        return "\(parts[0]).\(parts[1]).\(parts[2]).255"
    }
}
