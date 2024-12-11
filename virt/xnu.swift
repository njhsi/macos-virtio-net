//
//  xnu.swift
//  virt
//
//  Created by nj0 on 2024/12/9.
//
import Foundation

struct VMLogFacility {
    func info(_ s:String) {
        NSLog(s)
    }
    func error(_ s:String) {
        NSLog(s)
    }
    func error(_ s:String,throttleKey:String) {
        NSLog(s,throttleKey)
    }
}
struct VMFileLogger {
    static var shared = VMFileLogger()
    func newFacility(_: String) -> VMLogFacility {
        return VMLogFacility()
    }
}

extension String {
    
    func copyTo<T>(_ tuple: inout T) {
        
        let tupleSize = MemoryLayout.size(ofValue: tuple)
        
        let size = min(count, tupleSize)

        var cStr = utf8CString

        withUnsafeMutablePointer(to: &tuple) { (pTuple) in
            
            let pRawTuple = UnsafeMutableRawPointer(pTuple)
            
            withUnsafePointer(to: &cStr[0]) { (pString) in
                
                let pRawString = UnsafeRawPointer(pString)
                
                pRawTuple.copyMemory(from: pRawString, byteCount: size)
            }
        }
    }
}

public enum RVMError: Error {
    case sycallError(String)
    case illegalState(String)
}
extension RVMError {
    static func sycallErrorx(_:String) {
        
    }
}
