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
//  IdentityKeyPair.swift
//  DealogX
//
//  Created by Andriy Vasyk on 06.12.2022.
//

import Foundation

/// `IdentityKeyPair` is a representation of public and private identity keys of the DX Protocol
public struct IdentityKeyPair: Codable {
    /// The public part of the identity key pair which is suitable for key agreement operations
    public let publicKey: PublicKey

    /// The private part of the identity key pair
    public let privateKey: PrivateKey

    /// The public part of the identity key pair which is suitable for signing operations
    public let signingPublicKey: PublicKey

    // MARK: - Initialisation

    /// Initialises a new random identity key pair
    /// - Throws: Throws if public key could be created from the random private key.
    public init() throws {
        let privateKey = PrivateKey()
        let publicKey = try privateKey.getAgreementPublicKey()
        let signingKey = try privateKey.getSigningPublicKey()
        self.init(publicKey: publicKey, privateKey: privateKey, signingPublicKey: signingKey)
    }

    /// Initialises an identity key pair from existing public and private keys
    /// - Parameter publicKey: The public part of the identity key pair which is suitable for key agreement operations
    /// - Parameter privateKey: The private part of the identity key pair
    /// - Parameter signingPublicKey: Public part of the signing key
    public init(publicKey: PublicKey, privateKey: PrivateKey, signingPublicKey: PublicKey) {
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.signingPublicKey = signingPublicKey
    }

    // MARK: - Interface

    /// Public part of the identity which is suitable for key agreement operations
    public var identityKey: IdentityKeyPublic {
        return IdentityKeyPublic(publicKey: self.publicKey)
    }

    /// Public part of the signing key which is suitable for signature verification operations.
    ///
    /// This property returns the public part of the signing key, 
    /// which is suitable for signature verification operations. 
    /// The public part of the signing key can be used by other users to verify the signatures of this user.
    public var signingKey: SigningKeyPublic {
        return SigningKeyPublic(publicKey: self.signingPublicKey)
    }
}
