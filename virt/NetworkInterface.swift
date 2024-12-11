// See the corresponding blog post for details:
// https://amodm.com/blog/2024/07/03/running-a-linux-router-on-macos

import Foundation

// xnu is a custom module that I created to expose the relevant C structs
// that the kernel expects, as those structs are not part of the userspace
// API. This module contains C-bridge headers if-fake.h and if-bridge.h
// which are also shown in this gist.
//import xnu

struct NetworkInterface {
    let name: String
    let mac: ether_addr_t
    let ips: [String]
    let type: UInt32
    let flags: UInt32
    var isBridge: Bool {
        return type == UInt(IFT_BRIDGE)
    }
    var isLoopback: Bool {
        return flags & UInt32(IFF_LOOPBACK) != 0
    }
    var isFakeEth: Bool {
        return name.starts(with: "feth") // TODO: figure out type?
    }
    var up: Bool {
        return flags & UInt32(IFF_UP) != 0
    }

    func changeStatus(up: Bool) throws {
        try Self.changeStatus(name: name, up: up)
    }

    /// - Returns: all network interfaces currently configured on this system.
    static var all: [NetworkInterface] {
        var ifap: UnsafeMutablePointer<ifaddrs>? = nil
        guard getifaddrs(&ifap) == 0 else {
            fatalError("getifaddrs() failed: \(String(cString: strerror(errno)))")
        }
        defer { freeifaddrs(ifap) }
        var interfaces = [NetworkInterface]()
        try! withControlSocket { ctl in
            for ifa in sequence(first: ifap, next: { $0?.pointee.ifa_next }) {
                if let ifa = ifa?.pointee {
                    let ifname = String(cString: ifa.ifa_name)
                    let flags = ifa.ifa_flags
                    var ips = [String]()
                    var mac = ether_addr_t()
                    switch Int32(ifa.ifa_addr.pointee.sa_family) {
                        case AF_LINK:
                            var addr = ifa.ifa_addr.withMemoryRebound(to: sockaddr_dl.self, capacity: 1) { $0.pointee }
                            mac = withUnsafeMutableBytes(of: &addr.sdl_data) { ptr in
                                ptr.baseAddress!.advanced(by: Int(addr.sdl_nlen)).assumingMemoryBound(to: ether_addr_t.self).pointee
                            }
                        case AF_INET:
                            var addr = ifa.ifa_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                            var ip = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                            inet_ntop(AF_INET, &addr.sin_addr, &ip, socklen_t(INET_ADDRSTRLEN))
                            ips.append(String(cString: ip))
                        case AF_INET6:
                            var addr = ifa.ifa_addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
                            var ip = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                            inet_ntop(AF_INET6, &addr.sin6_addr, &ip, socklen_t(INET6_ADDRSTRLEN))
                            ips.append(String(cString: ip))
                        default:
                            continue
                    }
                    var ifr = ifreq()
                    memset(&ifr, 0, MemoryLayout<ifreq>.size)
                    ifname.copyTo(&ifr.ifr_name)
                    guard ioctl(ctl, IfIoctl.SIOCFIFTYPE, &ifr) == 0 else {
                        fatalError("\(ifname):ioctl(SIOCFIFTYPE): \(String(cString: strerror(errno)))")
                    }
                    let type = ifr.ifr_ifru.ifru_functional_type
                    interfaces.append(NetworkInterface(name: ifname, mac: mac, ips: ips, type: type, flags: flags))
                }
            }
        }
        return interfaces
    }

    private static func withControlSocket<T>(_ family: Int32 = AF_LOCAL, _ body: (Int32) throws -> T) throws -> T {
        let sock = socket(AF_LOCAL, SOCK_DGRAM, 0)
        guard sock >= 0 else {
            throw RVMError.sycallError("control:socket()")
        }
        defer { close(sock) }
        return try body(sock)
    }

    /// Creates a fake eth interface, and peers with `peer` (if provided).
    /// - Parameter peer: the peer to connect to
    /// - Returns: the name of the fake eth interface that was created.
    static func createFakeEth(peer: String? = nil) throws -> String {
        let allFakeEths = Set(all.filter { $0.isFakeEth }.map { $0.name })
        for i in 0..<128 {
            let name = "feth\(i)"
            if !allFakeEths.contains(name) {
                var ifr = ifreq()
                memset(&ifr, 0, MemoryLayout.size(ofValue: ifr))
                name.copyTo(&ifr.ifr_name)
                ifr.ifr_ifru.ifru_flags = Int16(IFF_UP | IFF_RUNNING)
                // create
                try withControlSocket { ctl in
                    guard ioctl(ctl, IfIoctl.SIOCIFCREATE2, &ifr) == 0 else {
                        throw RVMError.sycallError("feth:create() in createFakeEth")
                    }
                    if peer != nil {
                        // from https://opensource.apple.com/source/network_cmds/network_cmds-606.40.2/ifconfig.tproj/iffake.c.auto.html
                        var iffr = if_fake_request()
                        memset(&iffr, 0, MemoryLayout.size(ofValue: iffr))
                        peer!.copyTo(&iffr.iffr_u.iffru_peer_name)
                        var ifd = ifdrv()
                        memset(&ifd, 0, MemoryLayout.size(ofValue: ifd))
                        name.copyTo(&ifd.ifd_name)
                        ifd.ifd_cmd = UInt(IF_FAKE_S_CMD_SET_PEER)
                        withUnsafeMutablePointer(to: &iffr) { ifd.ifd_data = UnsafeMutableRawPointer($0) }
                        ifd.ifd_len = MemoryLayout.size(ofValue: iffr)
                        guard ioctl(ctl, IfIoctl.SIOCSDRVSPEC, &ifd) == 0 else {
                            throw RVMError.sycallError("feth:ioctl(set-peer)")
                        }
                    }
                }
                return name
            }
        }
        throw RVMError.illegalState("feth:create(): out of options")
    }

    /// Deletes the network interface with the given name.
    /// - Parameter name: the name of the network interface to delete.
    static func deleteInterface(_ name: String) throws {
        var ifr = ifreq()
        memset(&ifr, 0, MemoryLayout.size(ofValue: ifr))
        name.copyTo(&ifr.ifr_name)
        try withControlSocket { ctl in
            guard ioctl(ctl, IfIoctl.SIOCIFDESTROY, &ifr) == 0 else {
                throw RVMError.sycallError("\(name):ioctl(SIOCIFDESTROY)")
            }
        }
    }

    /// Creates a pair of fake eth interfaces, and peers them together.
    /// - Returns: the names of the two fake eth interfaces that were created.
    static func createFakeEthPair() throws -> (String, String) {
        let feth1 = try createFakeEth()
        let feth2 = try createFakeEth(peer: feth1)
        try changeStatus(name: feth1, up: true)
        try changeStatus(name: feth2, up: true)
        return (feth1, feth2)
    }

    /// Change the status of the network interface with the given name.
    /// - Parameters:
    ///  - name: the name of the network interface
    ///  - up: whether to bring the interface up or down
    /// - Throws: an error if the operation fails
    static func changeStatus(name: String, up: Bool) throws {
        var ifr = ifreq()
        memset(&ifr, 0, MemoryLayout.size(ofValue: ifr))
        name.copyTo(&ifr.ifr_name)
        try NetworkInterface.withControlSocket(AF_INET) { ctl in
            guard ioctl(ctl, IfIoctl.SIOCGIFFLAGS, &ifr) == 0 else {
                throw RVMError.sycallError("\(name):ioctl(SIOCGIFFLAGS)")
            }
            let oldFlag = Int32(ifr.ifr_ifru.ifru_flags) & 0xffff
            var newFlag = oldFlag
            if up {
                newFlag |= Int32(IFF_UP | IFF_RUNNING)
            } else {
                newFlag &= ~Int32(IFF_UP | IFF_RUNNING)
            }
            if oldFlag != newFlag {
                ifr.ifr_ifru.ifru_flags = Int16(bitPattern: UInt16(newFlag & 0xffff))
                guard ioctl(ctl, IfIoctl.SIOCSIFFLAGS, &ifr) >= 0 else {
                    throw RVMError.sycallError("\(name):ioctl(SIOCSIFFLAGS)")
                }
            }
        }
    }

    /// Adds `ifc` to the network bridge `bridge`.
    /// - Parameters:
    ///   - ifc: the network interface to add to the bridge.
    ///   - bridge: the network bridge.
    static func addInterfaceToBridge(_ ifc: String, to bridge: String) throws {
        var req = ifbreq()
        memset(&req, 0, MemoryLayout.size(ofValue: req))
        ifc.copyTo(&req.ifbr_ifsname)
        var ifd = ifdrv()
        memset(&ifd, 0, MemoryLayout.size(ofValue: ifd))
        bridge.copyTo(&ifd.ifd_name)
        ifd.ifd_cmd = 0 // BRDGADD: https://opensource.apple.com/source/xnu/xnu-7195.81.3/bsd/net/if_bridgevar.h.auto.html
        withUnsafeMutablePointer(to: &req) { ifd.ifd_data = UnsafeMutableRawPointer($0) }
        ifd.ifd_len = MemoryLayout.size(ofValue: req)
        try withControlSocket { ctl in
            guard ioctl(ctl, IfIoctl.SIOCSDRVSPEC, &ifd) == 0 else {
                throw RVMError.sycallError("bridge(\(bridge)):add-if(\(ifc))")
            }
        }
    }

    /// Ensures that `member` is a member of the `bridge` network interface.
    /// - Returns: `true` if the member was added, `false` if it was already a member.
    static func ensureBridgeMembership(bridge: String, member: String) throws -> Bool {
        var req = ifbreq()
        memset(&req, 0, MemoryLayout.size(ofValue: req))
        member.copyTo(&req.ifbr_ifsname)
        var ifd = ifdrv()
        memset(&ifd, 0, MemoryLayout.size(ofValue: ifd))
        bridge.copyTo(&ifd.ifd_name)
        ifd.ifd_cmd = 2 // BRDGGIFFLGS: https://opensource.apple.com/source/xnu/xnu-7195.81.3/bsd/net/if_bridgevar.h.auto.html
        withUnsafeMutablePointer(to: &req) { ifd.ifd_data = UnsafeMutableRawPointer($0) }
        ifd.ifd_len = MemoryLayout.size(ofValue: req)
        return try withControlSocket { ctl in
            if ioctl(ctl, IfIoctl.SIOCGDRVSPEC, &ifd) < 0 {
                if errno == ENOENT {
                    try addInterfaceToBridge(member, to: bridge)
                    return true
                } else {
                    throw RVMError.sycallError("bridge(\(bridge)):getifflags(\(member))")
                }
            }
            return false
        }
    }
}

func _IOC(_ dir: UInt32, _ g: Character, _ n: UInt, _ l: Int) -> UInt {
    return UInt(dir) | ((UInt(l) & UInt(IOCPARM_MASK)) << 16) | (UInt(g.asciiValue ?? 0) << 8) | n
}

func _IO(_ g: Character, _ n: UInt) -> UInt {
    return _IOC(IOC_VOID, g, n, 0)
}

func _IOW<T>(_ char: Character, _ nr: UInt, _ ctype: T.Type) -> UInt {
    return _IOC(IOC_IN, char, nr, MemoryLayout<T>.size)
}

func _IOR<T>(_ char: Character, _ nr: UInt, _ ctype: T.Type) -> UInt {
    return _IOC(IOC_OUT, char, nr, MemoryLayout<T>.size)
}

func _IOWR<T>(_ char: Character, _ nr: UInt, _ ctype: T.Type) -> UInt {
    return _IOC(IOC_INOUT, char, nr, MemoryLayout<T>.size)
}

enum IfIoctl {
    static let SIOCSIFFLAGS = _IOW("i", 16, ifreq.self)
    static let SIOCGIFFLAGS = _IOWR("i", 17, ifreq.self)
    static let SIOCGIFMEDIA = _IOWR("i", 56, ifmediareq.self)
    static let SIOCIFCREATE = _IOWR("i", 120, ifreq.self)
    static let SIOCIFDESTROY = _IOW("i", 121, ifreq.self)
    static let SIOCIFCREATE2 = _IOWR("i", 122, ifreq.self)
    static let SIOCSDRVSPEC = _IOW("i", 123, ifdrv.self)
    static let SIOCGDRVSPEC = _IOWR("i", 123, ifdrv.self)
    static let SIOCFIFTYPE = _IOWR("i", 159, ifreq.self)
}
