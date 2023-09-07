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
//  SignedPreKeyPublic.swift
//  DealogX
//
//  Created by Andriy Vasyk on 06.12.2022.
//

import Foundation

/// A signed pre key is used as part of the `PreKeyBundle` bundle to start a new conversation.
/// The public key of the `KeyPair` is signed with the `IdentityKey` of the initiator.
public struct SignedPreKeyPublic {
    /// The identifier of the signed pre key
    public let id: UUID

    /// The signature of the public key of the signed pre key
    public let signature: Data

    /// The public part of the signed pre key pair. Underlying implementation of this signed pre key
    public let publicKey: PublicKey

    /// The public key bytes of the signed pre key
    public var data: Data {
        return self.publicKey.data
    }

    /// The type of the public key of the signed pre key
    public var type: CryptoType {
        return self.publicKey.type
    }

    // MARK: - Initialisation

    /// Initialises signed pre key from components that are part of existing signed pre key pair
    /// See  documentation of `SignedPreKeyPair` for more info
    /// - Parameter id: The identifier of the signed pre key
    /// - Parameter publicKey: The public part of the signed pre key pair
    /// - Parameter signature: The signature of the public key of the signed pre key pair
    public init(id: UUID = UUID(), publicKey: PublicKey, signature: Data) {
        self.id = id
        self.signature = signature
        self.publicKey = publicKey
    }

    /// Initialises signed pre key with existing signed pre key pair
    /// See  documentation of `SignedPreKeyPair` for more info
    /// - Parameter signedPreKeyPair: The signed pre key pair containing all necessary info for initialization signed pre key
    public init(signedPreKeyPair: SignedPreKeyPair) {
        self.init(
                id: signedPreKeyPair.id,
                publicKey: signedPreKeyPair.publicKey,
                signature: signedPreKeyPair.signature)
    }
}

/// A public key for a signed pre-key.
///
/// This struct represents a public key for a signed pre-key. 
/// Signed pre-keys are used to establish a secure connection with a peer without having to exchange long-term keys.
extension SignedPreKeyPublic: Codable {
    /// The keys used to decode and encode a `SignedPreKeyPublic` instance.
    public enum Keys: String, CodingKey {
        case clientKeyId = "client_key_id"
        case key
        case signature
    }

    /// Initializes a new `SignedPreKeyPublic` instance from a decoder.
    ///
    /// - Parameter decoder: The decoder to read from.
    ///
    /// - Throws: An error if the decoder cannot decode the data.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: Keys.self)

        self.id = try container.decode(UUID.self, forKey: .clientKeyId)

        self.publicKey = try container.decode(PublicKey.self, forKey: .key)

        let base64String = try container.decode(String.self, forKey: .signature)
        guard let signature = Data(base64Encoded: base64String) else {
            throw DXError.invalidKeyData("Failed to decode public pre key signature")
        }

        self.signature = signature
    }

    /// Encodes the `SignedPreKeyPublic` instance to an encoder.
    ///
    /// - Parameter encoder: The encoder to write to.
    ///
    /// - Throws: An error if the encoder cannot encode the data.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: Keys.self)

        try container.encode(self.id, forKey: .clientKeyId)
        try container.encode(self.publicKey, forKey: .key)

        let base64String = self.signature.base64EncodedString()
        try container.encode(base64String, forKey: .signature)
    }
}
