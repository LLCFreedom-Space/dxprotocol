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
//  SignedPreKeyPair.swift
//  DealogX
//
//  Created by Andriy Vasyk on 07.12.2022.
//

import Foundation

/// A signed pre key is used as part of the `PreKeyBundle` bundle to start a new conversation.
/// The public key of the `SignedPreKeyPair` is signed with the `IdentityKey` of the initiator.
public struct SignedPreKeyPair: Codable {
    /// The identifier of the signed pre key pair
    public let id: UUID

    /// The date when the key pair was created
    public let date: Date

    /// The public key of the signed pre key pair
    public let publicKey: PublicKey

    /// The private key of the signed pre key pair
    public let privateKey: PrivateKey

    /// The signature of the public key
    public let signature: Data

    // MARK: - Initialisation

    /// Initialises a new random signed pre key pair
    /// - Parameter identityKeyPair: The identity key pair to be used to sign this signed pre key pair
    /// - Throws: Throws if the operation failed to be performed
    public init(identityKeyPair: IdentityKeyPair) throws {
        let pair = try KeyPair()
        let signature = try identityKeyPair.privateKey.signature(for: pair.publicKey.data)
        self.init(
                id: UUID(),
                date: Date(),
                publicKey: pair.publicKey,
                privateKey: pair.privateKey,
                signature: signature)
    }

    /// Initialises signed pre key from components
    /// - Parameter id: The identifier of the signed pre key pair
    /// - Parameter date: The date when the key pair was created
    /// - Parameter publicKey: The public key of the signed pre key pair
    /// - Parameter privateKey: The private key of the signed pre key pair
    /// - Parameter signature: The signature of the public key of the signed pre key pair
    public init(id: UUID, date: Date, publicKey: PublicKey, privateKey: PrivateKey, signature: Data) {
        self.id = id
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.date = date
        self.signature = signature
    }
}
