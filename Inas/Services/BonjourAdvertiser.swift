import Foundation
import Network

final class BonjourAdvertiser {
    private var listener: NWListener?

    func start(port: UInt16) {
        stop()
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return }
        do {
            let listener = try NWListener(using: .tcp, on: nwPort)
            listener.service = NWListener.Service(name: "iNAS", type: "_smb._tcp")
            // We already bind SMB ourselves; this registration is discovery-only.
            // Using a dedicated listener on the same port can fail, so advertise via
            // NetService instead.
            listener.cancel()
        } catch {
            // Fall through to NetService.
        }
        netService = NetService(domain: "local.", type: "_smb._tcp.", name: "iNAS", port: Int32(port))
        netService?.includesPeerToPeer = false
        netService?.publish()
    }

    func stop() {
        netService?.stop()
        netService = nil
        listener?.cancel()
        listener = nil
    }

    private var netService: NetService?
}
