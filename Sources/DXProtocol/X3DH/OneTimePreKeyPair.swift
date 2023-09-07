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
//  OneTimePreKeyPair.swift
//  DealogX
//
//  Created by Andriy Vasyk on 07.12.2022.
//

import Foundation

/// One-Time PreKeys are used in a single X3DH protocol run.
/// "PreKeys" are so named because they are essentially protocol messages
/// which remote user publishes to the server prior to starting any conversations.
public struct OneTimePreKeyPair: Codable {
    /// The identifier of the one-time pre key pair
    public let id: UUID

    /// The public key of the one-time pre key pair
    public let publicKey: PublicKey

    /// The private key of the one-time pre key pair
    public let privateKey: PrivateKey

    // MARK: - Initialisation

    /// Initialises a new random one-time pre key pair
    /// - Throws: Throws if the operation failed to be performed
    public init() throws {
        let pair = try KeyPair()
        self.init(id: UUID(), publicKey: pair.publicKey, privateKey: pair.privateKey)
    }

    /// Initialises one-time pre key from existing public and private keys
    /// - Parameter id: The identifier of the one-time pre key pair
    /// - Parameter publicKey: The public key of the one-time pre key pair
    /// - Parameter privateKey: The private key of the one-time pre key pair
    public init(id: UUID, publicKey: PublicKey, privateKey: PrivateKey) {
        self.id = id
        self.publicKey = publicKey
        self.privateKey = privateKey
    }
}
