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
//  PreKeyStorable.swift
//  DealogX
//
//  Created by Andriy Vasyk on 23.12.2022.
//

import Foundation

/// `PreKeyStorable` protocol declares a set of methods allowing to store
/// the one-time pre keys according to DX Protocol
public protocol PreKeyStorable: AnyObject {
    /// Returns a Pre Key pair for a given identifier.
    /// - Parameter id: The identifier of the pre key pair
    /// - Returns: The one-time pre key pair
    /// - Throws: Throws if the operation failed to be performed
    func loadPreKey(id: UUID) throws -> OneTimePreKeyPair

    /// Saves a one-time pre key pair for a given identifier.
    /// - Parameter record: The one-time pre key pair to store
    /// - Parameter id: The identifier of the pre key pair
    /// - Throws: Throws if the operation failed to be performed
    func storePreKey(_ record: OneTimePreKeyPair, id: UUID) throws

    /// Removes a pre key pair.
    /// - Parameter id: The identifier of the one-time pre key pair
    /// - Throws: Throws if the operation failed to be performed
    func removePreKey(id: UUID) throws

    /// Removes all one time pre key pairs from the store
    /// - Throws: Throws if the operation failed to be performed
    func removeAllPreKeys() throws
}
