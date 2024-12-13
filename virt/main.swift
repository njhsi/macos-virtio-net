//
//  main.swift
//  virt
//
//  Created by Alexander Pinske on 06.12.20.
//

import Virtualization

let verbose = CommandLine.arguments.contains("-v")

var macAddr:VZMACAddress
if let macAddressString = try? String(contentsOfFile: "/tmp/.virt.mac", encoding: .utf8),
   let macAddress = VZMACAddress(string: macAddressString.trimmingCharacters(in: .whitespacesAndNewlines)) {
    macAddr = macAddress
} else {
    let macAddressString = String("c2:6d:fd:60:10:2b")
    do {
        try macAddressString.write(toFile: "/tmp/.virt.mac", atomically: false, encoding: .utf8)
        if let macAddress = VZMACAddress(string: macAddressString) {
            macAddr = macAddress
        } else {
            fatalError("Virtual Machine Config Error")
        }
    } catch {
        fatalError("Virtual Machine Config Error: \(error)")
    }
}

let soPath = "/tmp/s.socket"
unlink(soPath)

let lengthOfPath = soPath.withCString { Int(strlen($0)) }
var addr = sockaddr_un()
addr.sun_family = sa_family_t(AF_UNIX)
_ = withUnsafeMutablePointer(to: &addr.sun_path.0) { ptr in
    soPath.withCString {
        strncpy(ptr, $0, lengthOfPath)
    }
}

//let unixSocket = Darwin.socket(AF_UNIX, SOCK_DGRAM, 0)
let unixSocket = Darwin.socket(PF_LOCAL, SOCK_DGRAM, 0)
try withUnsafePointer(to: &addr) {
    try $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        guard Darwin.bind(unixSocket, $0, UInt32(MemoryLayout<sockaddr_un>.stride)) != -1 else {
            throw RVMError.illegalState("cannot bind unix domain socket")
        }
    }
}

chmod(soPath, 0o777)
let vmac = macAddr.ethernetAddress
do {
    try NetworkSwitch.shared.newBridgePort(vmSock: unixSocket, hostBridge: "en0", vMac: vmac)
} catch {
    fatalError("Virtual Machine Config Bridger Error: \(error)")
}

NetworkSwitch.shared.start()

dispatchMain()
NSLog("done dispatchMain")
