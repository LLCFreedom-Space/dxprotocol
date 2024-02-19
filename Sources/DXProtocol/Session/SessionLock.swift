//
//  SessionLock.swift
//  
//
//  Created by Andriy Vasyk on 19.02.2024.
//

import Foundation

struct SessionLock {
    /// The underlying implementation of this session lock
    private var impl: NSRecursiveLock
    
    /// Initialises a new lock for session that corresponds to specified protocol address
    /// - Parameter address: The protocol address that uniquely identifies session
    init(address: ProtocolAddress) {
        self.impl = SessionLockStorage.shared.lock(for: address)
    }
    
    // MARK: - Interface
    
    /// Blocks a thread’s execution until the lock can be acquired.
    func lock() {
        self.impl.lock()
    }
    
    /// Relinquishes a previously acquired lock.
    func unlock() {
        self.impl.unlock()
    }
}
