// See the corresponding blog post for details:
// https://amodm.com/blog/2024/07/03/running-a-linux-router-on-macos

import Darwin
import Foundation
import Virtualization

// we poll via kqeueues in this thread
final class NetworkSwitch: Thread {
    static var shared = NetworkSwitch()
//    static var logger: VMLogFacility = {
//        VMFileLogger.shared.newFacility("nwswitch")
//    }()

    private var sockDevs: [VSockDev] = []

    func newBridgePort(hostBridge: String, vMac: ether_addr_t) throws -> VZFileHandleNetworkDeviceAttachment {
        if isExecuting {
            throw RVMError.illegalState("cannot add port after switch has started")
        }

        let vsockDev = try VSockDev(hostBridge: hostBridge, vMac: vMac)
        sockDevs.append(vsockDev)
        return VZFileHandleNetworkDeviceAttachment(fileHandle: FileHandle(fileDescriptor: vsockDev.remoteSocket))
    }

    /// Checks every bridge port and ensures that the bridge contains our interface.
    func ensureBridgeMembership() {
        for dev in sockDevs {
            if dev.isBridge {
                do {
                    if try NetworkInterface.ensureBridgeMembership(bridge: dev.hostInterface, member: dev.fethBridgeSide) {
//                        NetworkSwitch.logger.info("readded \(dev.fethBridgeSide) to bridge \(dev.hostInterface)")
                        perror("readded \(dev.fethBridgeSide) to bridge \(dev.hostInterface)")
                    }
                } catch {
//                    NetworkSwitch.logger.error("\(error)")
                    perror("\(error)")
                }
            }
        }
    }

    private static func kqChangeList(_ capacity: Int) -> UnsafeMutablePointer<kevent> {
        let ptr = UnsafeMutablePointer<kevent>.allocate(capacity: capacity)
        ptr.initialize(repeating: kevent(), count: capacity)
        return ptr
    }

    override func main() {
        NSLog("entering thread main()")
        if !sockDevs.isEmpty {
            defer {
                // close all sockets
                for dev in sockDevs {
                    dev.close()
                }
            }

            let kq = kqueue()
            if kq < 0 {
                fatalError("kqueue() failed: \(String(cString: strerror(errno)))")
            }
            defer { close(kq) }

            let kqs = KQSockets(sockDevs)
            while !isCancelled {
                if kqs.onEvent(kq) < 0 {
                    if errno == EINTR || errno == EAGAIN {
                        continue
                    }
//                    NetworkSwitch.logger.error("onEvent() failed: \(String(cString: strerror(errno)))")
                    perror("onEvent() failed: \(String(cString: strerror(errno)))")
                }
            }

            // cleanup
            for dev in sockDevs {
                dev.close()
            }
        }
        NSLog("leaving thread main()")
    }

    func cancelAndJoin(_ pollTimeNanos: UInt64 = 100_000_000) async throws {
        cancel()
        while !isFinished {
            try await Task.sleep(nanoseconds: pollTimeNanos)
        }
    }
}

private struct VSockDev {
    let hostInterface: String
    let vMac: ether_addr_t
    let vmSocket: Int32
    let remoteSocket: Int32
    let bpfSocket: Int32
    let ndrvSocket: Int32
    let bpfBufferSize: Int
    let bpfReadBuffer: UnsafeMutableRawBufferPointer
    let bpfFilter: [bpf_insn]
    let fethBridgeSide: String
    let fethVmSide: String
    let isBridge: Bool

    var bpfStats: bpf_stat {
        var stats = bpf_stat()
        return ioctl(bpfSocket, BpfIoctl.BIOCGSTATS, &stats) == 0 ? stats : bpf_stat(bs_recv: 0, bs_drop: 0)
    }

    init(hostBridge: String, vMac: ether_addr_t) throws {
        self.hostInterface = hostBridge
        self.isBridge = NetworkInterface.all.first(where: { $0.name == hostBridge })?.isBridge ?? false
        self.vMac = vMac

        (fethBridgeSide, fethVmSide) = isBridge ? try NetworkInterface.createFakeEthPair() : (hostBridge, hostBridge)

        var socketPair: (Int32, Int32) = (0, 0)
        withUnsafePointer(to: &socketPair) {
            let ptr = UnsafeMutableRawPointer(mutating: $0).bindMemory(to: Int32.self, capacity: 2)
            guard socketpair(PF_LOCAL, SOCK_DGRAM, 0, ptr) == 0 else {
                fatalError("socketpair() failed: \(String(cString: strerror(errno)))")
            }
        }

        (vmSocket, remoteSocket) = socketPair
        // set buffer size
        var size = 1024 * 1024 * 8
        setsockopt(vmSocket, SOL_SOCKET, SO_SNDBUF, &size, socklen_t(MemoryLayout<Int>.size))
        setsockopt(vmSocket, SOL_SOCKET, SO_RCVBUF, &size, socklen_t(MemoryLayout<Int>.size))
        setsockopt(remoteSocket, SOL_SOCKET, SO_SNDBUF, &size, socklen_t(MemoryLayout<Int>.size))
        setsockopt(remoteSocket, SOL_SOCKET, SO_RCVBUF, &size, socklen_t(MemoryLayout<Int>.size))

        self.bpfBufferSize = Int(BPF_MAXBUFSIZE)
        self.bpfReadBuffer = UnsafeMutableRawBufferPointer.allocate(byteCount: bpfBufferSize, alignment: 16)

        let vmacTop2 = UInt32(vMac.octet.0) << 8 | UInt32(vMac.octet.1)
        let vmacBottom4 = UInt32(vMac.octet.2) << 24 | UInt32(vMac.octet.3) << 16 | UInt32(vMac.octet.4) << 8 | UInt32(vMac.octet.5)
        self.bpfFilter = [
            // [0] the following 4 statements do `ether dst host <vMac>`
            bpf_insn(code: CUnsignedShort(BPF_LD | BPF_W | BPF_ABS), jt: 0, jf: 0, k: 2), // ld dst_host_ether[2..<6]
            bpf_insn(code: CUnsignedShort(BPF_JMP | BPF_JEQ | BPF_K), jt: 0, jf: 2, k: vmacBottom4), // if == vMac[2..<6], proceed to next else skip-2
            bpf_insn(code: CUnsignedShort(BPF_LD | BPF_H | BPF_ABS), jt: 0, jf: 0, k: 0), // ldh dst_host_ether[0..<2] (msb 2 bytes)
            bpf_insn(code: CUnsignedShort(BPF_JMP | BPF_JEQ | BPF_K), jt: 3, jf: 4, k: vmacTop2), // if == vMac[0..<2], skip-3 (true) else skip-4 (false)
            // [4] the following 3 statements do `ether dst broadcast`
            bpf_insn(code: CUnsignedShort(BPF_JMP | BPF_JEQ | BPF_K), jt: 0, jf: 3, k: 0xffffffff), // if == 0xffffffff (broadcast), next else skip-3 (false)
            bpf_insn(code: CUnsignedShort(BPF_LD | BPF_H | BPF_ABS), jt: 0, jf: 0, k: 2), // ld dst_host_ether[2..<6]
            bpf_insn(code: CUnsignedShort(BPF_JMP | BPF_JEQ | BPF_K), jt: 0, jf: 1, k: 0xffff), // if == 0xffff (broadcast), next (true) else skip-1 (false)
            // [7] return true (capture max packet size)
            bpf_insn(code: CUnsignedShort(BPF_RET | BPF_K), jt: 0, jf: 0, k: UInt32(self.bpfBufferSize)),
            // [8] return false
            bpf_insn(code: CUnsignedShort(BPF_RET | BPF_K), jt: 0, jf: 0, k: 0), // ret false
        ]

        self.ndrvSocket = Self.ndrvSocket(fethVmSide)
        self.bpfSocket = Self.bpfSocket(fethVmSide, self.bpfBufferSize, self.bpfFilter)
    }

    /// Route traffic between host and vm, depending upon the `event`
    func routeTraffic(_ event: kevent64_s) -> Bool {
        let fd = Int32(event.ident)
        if fd == vmSocket {
            vmToHost(event)
        } else if fd == bpfSocket {
            hostToVM(event)
        } else {
            return false
        }
        return true
    }

    /// Route traffic from host to VM by reading from bpfSocket and writing to vmSocket.
    func hostToVM(_ event: kevent64_s) {
        var numPackets = 0, wlen = 0, wlenActual = 0
        let buffer = bpfReadBuffer.baseAddress!
        let len = read(bpfSocket, buffer, bpfBufferSize)
        if len > 0 {
            let endPtr = buffer.advanced(by: len)
            var pktPtr = buffer.assumingMemoryBound(to: bpf_hdr.self)
            while pktPtr < endPtr {
                // for each packet
                let hdr = pktPtr.pointee
                let nextPktPtr = UnsafeMutableRawPointer(pktPtr).advanced(by: Int(hdr.bh_caplen) + Int(hdr.bh_hdrlen))
                if hdr.bh_caplen > 0 {
                    if nextPktPtr > endPtr {
//                        NetworkSwitch.logger.error("\(hostInterface)-h2g: nextPktPtr out of bounds: \(nextPktPtr) > \(endPtr). current pktPtr=\(pktPtr) hdr=\(hdr)", throttleKey: "h2g-next-oob")
                        perror("\(hostInterface)-h2g: nextPktPtr out of bounds: \(nextPktPtr) > \(endPtr). current pktPtr=\(pktPtr) hdr=\(hdr)")
                    }
                    let hdr = pktPtr.pointee
                    let dataPtr = UnsafeMutableRawPointer(mutating: pktPtr).advanced(by: Int(hdr.bh_hdrlen))
                    let writeLen = write(vmSocket, dataPtr, Int(hdr.bh_caplen))
                    numPackets += 1
                    wlen += Int(hdr.bh_caplen)
                    wlenActual += writeLen
                    if writeLen < 0 {
//                        NetworkSwitch.logger.error("\(hostInterface)-h2g: write() failed: \(String(cString: strerror(errno)))", throttleKey: "h2g-writ-fail")
                        perror("\(hostInterface)-h2g: write() failed: \(String(cString: strerror(errno)))")
                    } else if writeLen != Int(hdr.bh_caplen) {
//                        NetworkSwitch.logger.error("\(hostInterface)-h2g: write() failed: partial write", throttleKey: "h2g-writ-partial")
                        perror("\(hostInterface)-h2g: write() failed: partial write")
                    }
                }
                pktPtr = nextPktPtr.alignedUp(toMultipleOf: BPF_ALIGNMENT).assumingMemoryBound(to: bpf_hdr.self)
            }
        } else if len == 0 {
//            NetworkSwitch.logger.error("\(hostInterface)-h2g: EOF", throttleKey: "h2g-eof")
            perror("\(hostInterface)-h2g: EOF")
        } else if errno != EAGAIN && errno != EINTR {
//            NetworkSwitch.logger.error("\(hostInterface)-h2g: read() failed: \(String(cString: strerror(errno)))", throttleKey: "h2g-read-fail")
            perror("\(hostInterface)-h2g: read() failed: \(String(cString: strerror(errno)))")
        }
    }

    /// Send traffic from VM to host by reading from vmSocket and writing to ndrv socket.
    func vmToHost(_ event: kevent64_s, onlyOne: Bool = true) {
        let availableLen = min(bpfReadBuffer.count, Int(event.data))
        let basePtr = bpfReadBuffer.baseAddress!
        var offset = 0
        while offset < availableLen {
            let n = read(vmSocket, basePtr, availableLen - offset)
            if n > 0 {
                let len = write(ndrvSocket, basePtr, n)
                if len != n {
                    if len < 0 {
//                        NetworkSwitch.logger.error("\(hostInterface)-g2h: write() failed: \(String(cString: strerror(errno)))", throttleKey: "g2h-writ-fail")
                        perror("\(hostInterface)-g2h: write() failed: \(String(cString: strerror(errno)))")
                    } else if errno != EAGAIN && errno != EINTR {
//                        NetworkSwitch.logger.error("\(hostInterface)-g2h: write() failed: partial write", throttleKey: "g2h-writ-partial")
                        perror("\(hostInterface)-g2h: write() failed: partial write")
                    }
                    break
                }
                offset += n
                if onlyOne {
                    break
                }
            } else {
                if n == 0 {
//                    NetworkSwitch.logger.error("\(hostInterface)-g2h: EOF", throttleKey: "g2h-eof")
                    perror("\(hostInterface)-g2h: EOF")
                } else if errno != EAGAIN && errno != EINTR {
//                    NetworkSwitch.logger.error("\(hostInterface)-g2h: read() failed: \(String(cString: strerror(errno))): e=\(event)", throttleKey: "g2h-read-fail")
                    perror("\(hostInterface)-g2h: read() failed: \(String(cString: strerror(errno))): e=\(event)")
                }
                break
            }
        }
    }

    static func bpfSocket(_ ifc: String, _ buffSize: Int, _ bpfFilter: [bpf_insn]) -> Int32 {
        // TODO: modify sysctl debug.bpf_maxbufsize and use that size
        for i in 1..<256 {
            let dev = "/dev/bpf\(i)"
            let fd = open(dev, O_RDONLY)
            if fd >= 0 {
                // set buffer size
                var arg = buffSize
                guard ioctl(fd, BpfIoctl.BIOCSBLEN, &arg) == 0 else {
                    fatalError("bpf \(dev) ioctl(BIOCSBLEN) failed for \(ifc): \(String(cString: strerror(errno)))")
                }
                // set immediate mode to true
                arg = 1
                guard ioctl(fd, BpfIoctl.BIOCIMMEDIATE, &arg) == 0 else {
                    fatalError("bpf ioctl(BIOCIMMEDIATE) failed for \(ifc): \(String(cString: strerror(errno)))")
                }
                // see only received packets, not generated locally
                arg = 0
                guard ioctl(fd, BpfIoctl.BIOCSSEESENT, &arg) == 0 else {
                    fatalError("bpf ioctl(BIOCSSEESENT) failed for \(ifc): \(String(cString: strerror(errno)))")
                }
                // bind to interface
                var ifr = ifreq()
                memset(&ifr, 0, MemoryLayout<ifreq>.size)
                ifc.copyTo(&ifr.ifr_name)
                guard ioctl(fd, BpfIoctl.BIOCSETIF, &ifr) == 0 else {
                    fatalError("bpf ioctl(BIOCSETIF) failed for \(ifc): \(String(cString: strerror(errno)))")
                }
                arg = 1
                guard ioctl(fd, BpfIoctl.BIOCSHDRCMPLT, &arg) == 0 else {
                    fatalError("bpf ioctl(BIOCSHDRCMPLT) failed for \(ifc): \(String(cString: strerror(errno)))")
                }
                arg = 1
                guard ioctl(fd, BpfIoctl.BIOCPROMISC, &arg) == 0 else {
                    fatalError("bpf ioctl(BIOCPROMISC) failed for \(ifc): \(String(cString: strerror(errno)))")
                }
                // set filter
                var filter = bpf_program()
                filter.bf_len = UInt32(bpfFilter.count)
                filter.bf_insns = UnsafeMutablePointer<bpf_insn>.allocate(capacity: bpfFilter.count)
                for i in 0..<bpfFilter.count {
                    filter.bf_insns[i] = bpfFilter[i]
                }
                guard ioctl(fd, BpfIoctl.BIOCSETFNR, &filter) == 0 else {
                    fatalError("bpf ioctl(BIOCSETFNR) failed for \(ifc): \(String(cString: strerror(errno)))")
                }
                return fd
            }
        }
        fatalError("bpf open() failed for \(ifc): \(String(cString: strerror(errno)))")
    }

    static func ndrvSocket(_ ifc: String) -> Int32 {
        let fd = socket(PF_NDRV, SOCK_RAW, 0)
        guard fd >= 0 else {
            fatalError("ndrv socket() failed for \(ifc): \(String(cString: strerror(errno)))")
        }

        // bind to interface
        var nd = sockaddr_ndrv()
        nd.snd_len = UInt8(MemoryLayout<sockaddr_ndrv>.size)
        nd.snd_family = UInt8(AF_NDRV)
        ifc.copyTo(&nd.snd_name)

        withUnsafePointer(to: &nd) { nd_ptr in
            nd_ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { nd_ptr in
                if Darwin.bind(fd, nd_ptr, socklen_t(MemoryLayout<sockaddr_ndrv>.size)) != 0 {
                    fatalError("ndrv bind() failed for \(ifc): \(String(cString: strerror(errno)))")
                }
                if Darwin.connect(fd, nd_ptr, socklen_t(MemoryLayout<sockaddr_ndrv>.size)) != 0 {
                    fatalError("ndrv connect() failed for \(ifc): \(String(cString: strerror(errno)))")
                }
            }
        }
        return fd
    }

    func close() {
        Darwin.close(vmSocket)
        Darwin.close(remoteSocket)
        Darwin.close(bpfSocket)
        Darwin.close(ndrvSocket)
        if isBridge {
            try? NetworkInterface.deleteInterface(self.fethBridgeSide)
            try? NetworkInterface.deleteInterface(self.fethVmSide)
        }
    }
}

private struct KQSockets {
    private let ptr: UnsafeMutablePointer<kevent64_s>
    private let eventsPtr: UnsafeMutablePointer<kevent64_s>
    private let sockDevs: [VSockDev]

    init(_ sockDevs: [VSockDev]) {
        self.sockDevs = sockDevs
        let capacity = sockDevs.count * 2
        self.ptr = UnsafeMutablePointer<kevent64_s>.allocate(capacity: capacity)
        self.ptr.initialize(repeating: kevent64_s(), count: capacity)
        self.eventsPtr = UnsafeMutablePointer<kevent64_s>.allocate(capacity: capacity)
        self.eventsPtr.initialize(repeating: kevent64_s(), count: capacity)
        for i in 0..<sockDevs.count {
            guard Foundation.fcntl(sockDevs[i].vmSocket, F_SETFL, O_NONBLOCK) == 0 else {
                fatalError("fcntl() failed for \(sockDevs[i].hostInterface) vmSocket: \(String(cString: strerror(errno)))")
            }
            guard Foundation.fcntl(sockDevs[i].bpfSocket, F_SETFL, O_NONBLOCK) == 0 else {
                fatalError("fcntl() failed for \(sockDevs[i].hostInterface) bpfSocket: \(String(cString: strerror(errno)))")
            }
            self.ptr.advanced(by: 2*i).pointee = kevent64_s(
                ident: UInt64(sockDevs[i].vmSocket),
                filter: Int16(EVFILT_READ),
                flags: UInt16(EV_ADD | EV_ENABLE),
                fflags: 0,
                data: 0,
                udata: 0,
                ext: (0, 0)
            )
            self.ptr.advanced(by: 2*i+1).pointee = kevent64_s(
                ident: UInt64(sockDevs[i].bpfSocket),
                filter: Int16(EVFILT_READ),
                flags: UInt16(EV_ADD | EV_ENABLE),
                fflags: 0,
                data: 0,
                udata: 0,
                ext: (0, 0)
            )
        }
    }

    func onEvent(_ kq: Int32) -> Int {
        let timeoutMillis: Int = 1000
        let timeoutSecs = timeoutMillis / 1000
        let timeoutNanos = (timeoutMillis % 1000) * 1_000_000
        var timeout = timespec(tv_sec: timeoutSecs, tv_nsec: timeoutNanos)
        let len = sockDevs.count * 2
        let numEvents = Int(kevent64(kq, ptr, Int32(len), eventsPtr, Int32(len), 0, &timeout))
        if numEvents > 0 {
            eventLoop: for i in 0..<len {
                let evt = eventsPtr.advanced(by: i).pointee
                if evt.flags & UInt16(EV_ERROR) != 0 {
//                    NetworkSwitch.logger.error("evt-error: \(String(cString: strerror(Int32(evt.data))))", throttleKey: "kq-evt-error")
                    perror("evt-error: \(String(cString: strerror(Int32(evt.data))))")
                } else if evt.data > 0 {
                    let fd = Int32(evt.ident)
                    for j in 0..<sockDevs.count {
                        let dev = sockDevs[j]
                        if dev.vmSocket == fd {
                            dev.vmToHost(evt)
                            continue eventLoop
                        } else if dev.bpfSocket == fd {
                            dev.hostToVM(evt)
                            continue eventLoop
                        } else {
                            continue
                        }
                    }
//                    NetworkSwitch.logger.error("no route found for event: \(evt)", throttleKey: "kq-no-route")
                    perror("no route found for event: \(evt)")
                }
            }
        }
        return numEvents
    }
}

private let BPF_ALIGNMENT = MemoryLayout<Int32>.size

enum BpfIoctl {
    static let BIOCSBLEN = _IOWR("B", 102, CUnsignedInt.self)
    static let BIOCPROMISC = _IO("B", 105)
    static let BIOCSETIF = _IOW("B", 108, ifreq.self)
    static let BIOCGSTATS = _IOR("B", 111, bpf_stat.self)
    static let BIOCIMMEDIATE = _IOW("B", 112, CUnsignedInt.self)
    static let BIOCSHDRCMPLT = _IOW("B", 117, CUnsignedInt.self)
    static let BIOCSSEESENT = _IOW("B", 119, CUnsignedInt.self)
    static let BIOCSETFNR = _IOW("B", 126, bpf_program.self)
}
