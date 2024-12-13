//
//  main.swift
//  virt
//
//  Created by Alexander Pinske on 06.12.20.
//

import Virtualization

let usage = ".. -i en0 -s socket_file_path -a mac"

let ifEth : String
let filePathSocket : String
let macAddrRemote : VZMACAddress
let verbose = CommandLine.arguments.contains("-v")

if let i = CommandLine.arguments.firstIndex(of: "-i"), i < CommandLine.arguments.count{
    ifEth = CommandLine.arguments[i+1]
} else {
    ifEth = ""
    fatalError(usage)
}
if let i = CommandLine.arguments.firstIndex(of: "-s"), i < CommandLine.arguments.count{
    filePathSocket = CommandLine.arguments[i+1]
} else {
    filePathSocket = ""
    fatalError(usage)
}
if let i = CommandLine.arguments.firstIndex(of: "-a"), i < CommandLine.arguments.count,
   let mac = VZMACAddress(string: CommandLine.arguments[i+1]) {
    macAddrRemote = mac
} else {
    macAddrRemote = VZMACAddress.randomLocallyAdministered()
    NSLog(usage)
}
NSLog("info: ethernet=\(ifEth), socket=\(filePathSocket), mac=\(macAddrRemote)")

unlink(filePathSocket)
let lengthOfPath = filePathSocket.withCString { Int(strlen($0)) }
var addr = sockaddr_un()
addr.sun_family = sa_family_t(AF_UNIX)
_ = withUnsafeMutablePointer(to: &addr.sun_path.0) { ptr in
    filePathSocket.withCString {
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

chmod(filePathSocket, 0o777)
let vmac = macAddrRemote.ethernetAddress
do {
    try NetworkSwitch.shared.newBridgePort(vmSock: unixSocket, hostBridge: ifEth, vMac: vmac)
} catch {
    fatalError("newBridgePort Error: \(error)")
}

NetworkSwitch.shared.start()

signal(SIGINT, SIG_IGN)
let sigintSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: DispatchQueue.main)
sigintSource.setEventHandler {
    exit(-1)
}
sigintSource.resume()

dispatchMain()
