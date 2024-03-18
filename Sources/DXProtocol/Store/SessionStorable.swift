// DXProtocol
// Copyright (C) 2022  FREEDOM SPACE, LLC

//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as published
//  by the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Affero General Public License for more details.
//
//  You should have received a copy of the GNU Affero General Public License
//  along with this program.  If not, see <https://www.gnu.org/licenses/>.

//
//  SessionStorable.swift
//  DealogX
//
//  Created by Andriy Vasyk on 23.12.2022.
//

import Foundation

/// `SessionStorable` protocol declares a set of methods allowing to store
/// the sessions according to DX Protocol
public protocol SessionStorable: AnyObject {
    /// Attempts to acquire a lock on session, blocking an execution until the lock can be acquired
    /// - Parameter address: The address of the remote client the session is associated with
    /// - Throws: Throws if the operation failed to be performed
    func lockSession(for address: ProtocolAddress) throws
    
    /// Relinquishes a previously acquired lock on session
    /// - Parameter address: The address of the remote client the session is associated with
    func unlockSession(for address: ProtocolAddress)

    /// Returns a session for a given user's address.
    /// - Parameter address: The address of the remote client
    /// - Returns: The session, or nil if session does not exist
    /// - Throws: Throws if the operation failed to be performed
    func loadSession(for address: ProtocolAddress) throws -> Session?

    /// Returns all sessions for specified addresses
    /// - Parameter addresses: A list of addresses of the remote clients
    /// - Returns: A list of sessions
    /// - Throws: Throws if the operation failed to be performed
    func loadExistingSessions(for addresses: [ProtocolAddress]) throws -> [Session]

    /// Stores a session for a given user's address.
    /// - Parameter session: The session to store
    /// - Parameter address: The address of the remote client
    /// - Throws: Throws if the operation failed to be performed
    func storeSession(_ session: Session, for address: ProtocolAddress) throws
}
