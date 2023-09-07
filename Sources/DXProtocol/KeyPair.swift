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
//  KeyPair.swift
//  DealogX
//
//  Created by Andriy Vasyk on 06.12.2022.
//

import Foundation

/// A pair of public and private key for cryptography
public struct KeyPair: Codable {
    /// The public part of the key pair
    public let publicKey: PublicKey

    /// The private part of the key pair
    public let privateKey: PrivateKey

    // MARK: - Initialisation

    /// Initialises a new random key pair
    /// - Throws: Throws if public key could be created from the random private key.
    public init() throws {
        let privateKey = PrivateKey()
        let publicKey = try privateKey.getAgreementPublicKey()
        self.init(publicKey: publicKey, privateKey: privateKey)
    }

    /// Initialises a key pair from existing public and private keys
    /// - Parameter publicKey: The public part of the key pair
    /// - Parameter privateKey: The private part of the key pair
    public init(publicKey: PublicKey, privateKey: PrivateKey) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }
}
