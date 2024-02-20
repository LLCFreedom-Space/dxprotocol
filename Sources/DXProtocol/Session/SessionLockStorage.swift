//
//  SessionLockStorage.swift
//  
//
//  Created by Andriy Vasyk on 19.02.2024.
//

import Foundation

final class SessionLockStorage {
    static let shared = SessionLockStorage()
    
    /// Internal queue allowing to sync access to storage with locks
    private let syncAccessQueue = DispatchQueue(label: "StorageAccessQueue")
    
    /// Container to store locks and associate them with corresponding protocol addresses
    private var storage: [ProtocolAddress: NSRecursiveLock] = [:]
    
    /// Returns a lock for corresponding protocol addresses
    /// - Parameter address: The protocol address that uniquely identifies session and lock for it
    /// - Returns: A lock allowing to sync access to the session
    func lock(for address: ProtocolAddress) -> NSRecursiveLock {
        self.syncAccessQueue.sync {
            var result: NSRecursiveLock
            if let lock = self.storage[address] {
                result = lock
            } else {
                result = NSRecursiveLock()
                self.storage[address] = result
            }
            return result
        }
    }
}
