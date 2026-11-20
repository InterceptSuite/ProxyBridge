import Foundation
import HevSocks5Tunnel

/// Wrapper around hev-socks5-tunnel, the packet stack. It reads the tun device and sends every flow as a
/// SOCKS5 request to the local router.
enum HevTunnel {
    // values of SYSPROTO_CONTROL and UTUN_OPT_IFNAME, which the iOS SDK does not expose
    private static let controlProtocol: Int32 = 2
    private static let utunInterfaceNameOption: Int32 = 2

    /// hev blocks until `stop` is called, so it gets its own thread.
    static func start(tunFd: Int32, socksPort: UInt16, mtu: Int) {
        let config = """
        tunnel:
          mtu: \(mtu)
        socks5:
          address: 127.0.0.1
          port: \(socksPort)
          udp: 'udp'
        misc:
          task-stack-size: 20480
        """
        let bytes = Array(config.utf8)
        Thread.detachNewThread {
            bytes.withUnsafeBufferPointer { buffer in
                _ = hev_socks5_tunnel_main_from_str(buffer.baseAddress, UInt32(buffer.count), tunFd)
            }
        }
    }

    static func stop() {
        hev_socks5_tunnel_quit()
    }

    /// The system does not hand over the tun file descriptor, so find the socket that belongs to a utun interface.
    static func tunnelFileDescriptor() -> Int32? {
        var name = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        for fd in Int32(0)...1024 {
            var length = socklen_t(name.count)
            if getsockopt(fd, controlProtocol, utunInterfaceNameOption, &name, &length) == 0,
               String(cString: name).hasPrefix("utun") {
                return fd
            }
        }
        return nil
    }
}
