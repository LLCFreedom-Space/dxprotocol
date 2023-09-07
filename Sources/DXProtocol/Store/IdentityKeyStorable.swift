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
//  IdentityKeyStorable.swift
//  DealogX
//
//  Created by Andriy Vasyk on 06.12.2022.
//

import Foundation

/// `IdentityKeyStorable` protocol declares a set of methods allowing to store
/// the identity keys according to DX Protocol.
public protocol IdentityKeyStorable: AnyObject {
    /// Returns the identity key pair of current user. This key pair should be created only once at the first launch
    /// - Returns: The identity key pair of current user
    /// - Throws: Throws if the operation failed to be performed
    func identityKeyPair() throws -> IdentityKeyPair

    /// Returns registration identifier of current user
    func localRegistrationId() throws -> UUID

    /// Stores a remote user's identity key `IdentityKeyPublic`.
    /// - Parameter identity: The identity key as `IdentityKeyPublic`
    /// - Parameter address: The address of the remote user
    /// - Returns: `true` if updated existing identity , `false` if added new identity
    /// - Throws: Throws if the operation failed to be performed
    @discardableResult func saveIdentity(_ identity: IdentityKeyPublic,
                                         for address: ProtocolAddress) throws -> Bool

    /// Determines whether a remote user's identity is trusted.
    /// - Parameter identity: The identity key as `IdentityKeyPublic`
    /// - Parameter address: The address of the remote user
    /// - Parameter direction: `DirectionType`
    /// - Returns: `true` if trusted, `false` if not trusted
    func isTrustedIdentity(_ identity: IdentityKeyPublic,
                           for address: ProtocolAddress,
                           direction: DirectionType) throws -> Bool

    /// Returns the identity key as `IdentityKeyPublic` for the given user's address.
    /// - Parameter address: The address of the remote user
    /// - Returns: The identity key as `IdentityKeyPublic` for the address, or nil if not exists
    /// - Throws: Throws if the operation failed to be performed
    func identity(for address: ProtocolAddress) throws -> IdentityKeyPublic?
}
