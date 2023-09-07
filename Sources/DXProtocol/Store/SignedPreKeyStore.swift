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
//  SignedPreKeyStorable.swift
//  DealogX
//
//  Created by Andriy Vasyk on 23.12.2022.
//

import Foundation

/// `SignedPreKeyStorable` protocol declares a set of methods allowing to store
/// the signed pre keys according to DX Protocol
public protocol SignedPreKeyStorable: AnyObject {
    /// Returns a signed pre key pair for a given identifier.
    /// - Parameter id: The identifier of the signed pre key pair
    /// - Returns: The signed pre key pair
    /// - Throws: Throws if the operation failed to be performed
    func loadSignedPreKey(id: UUID) throws -> SignedPreKeyPair

    /// Stores a signed pre key pair for a given identifier.
    /// - Parameter record: The signed pre key pair
    /// - Parameter id: The identifier of the signed pre key pair
    /// - Throws: Throws if the operation failed to be performed
    func storeSignedPreKey(_ record: SignedPreKeyPair, id: UUID) throws

    /// Removes a signed pre key pair for a given identifier
    /// - Parameter id: The identifier of the signed pre key pair
    /// - Throws: Throws if the operation failed to be performed
    func removeSignedPreKey(id: UUID) throws

    /// Removes all signed pre key pairs from the store
    /// - Throws: Throws if the operation failed to be performed
    func removeAllSignedPreKeys() throws
}
