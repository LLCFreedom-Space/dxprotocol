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
//  OneTimePreKeyPublic.swift
//  DealogX
//
//  Created by Andriy Vasyk on 06.12.2022.
//

import Foundation

/// One-Time PreKeys are used in a single X3DH protocol run.
/// "PreKeys" are so named because they are essentially protocol messages
/// which remote user publishes to the server prior to starting any conversations.
public struct OneTimePreKeyPublic {
    /// The identifier of the one-time pre key
    public let id: UUID

    /// The public part of the one-time pre key pair. Underlying implementation of this signed pre key
    public let publicKey: PublicKey

    /// The public key bytes of the one-time pre key
    public var data: Data {
        return self.publicKey.data
    }

    /// The type of the public key of the one-time pre key
    public var type: CryptoType {
        return self.publicKey.type
    }

    // MARK: - Initialisation

    /// Initialises one-time pre key from components that are part of existing one-time pre key pair
    /// See  documentation of `OneTimePreKeyPair` for more info
    /// - Parameter id: The identifier of the one-time pre key
    /// - Parameter publicKey: The public part of the one-time pre key pair
    public init(id: UUID = UUID(), publicKey: PublicKey) {
        self.id = id
        self.publicKey = publicKey
    }

    /// Initialises one-time pre key with existing one-time pre key pair
    /// See  documentation of `OneTimePreKeyPair` for more info
    /// - Parameter oneTimePreKeyPair: The one-time pre key pair containing all necessary info for initialization
    public init(oneTimePreKeyPair: OneTimePreKeyPair) {
        self.init(
                id: oneTimePreKeyPair.id,
                publicKey: oneTimePreKeyPair.publicKey)
    }
}

extension OneTimePreKeyPublic: Codable {
    /// The keys used to decode and encode a `OneTimePreKeyPublic` instance
    public enum Keys: String, CodingKey {
        case clientKeyId = "client_key_id"
        case key
    }

    /// Initializes a new `OneTimePreKeyPublic` instance from a decoder.
    ///
    /// - Parameter decoder: The decoder to read from.
    ///
    /// - Throws: An error if the decoder cannot decode the data.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: Keys.self)
        self.id = try container.decode(UUID.self, forKey: .clientKeyId)
        self.publicKey = try container.decode(PublicKey.self, forKey: .key)
    }

    /// Encodes the `OneTimePreKeyPublic` instance to an encoder.
    ///
    /// - Parameter encoder: The encoder to write to.
    ///
    /// - Throws: An error if the encoder cannot encode the data.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: Keys.self)
        try container.encode(self.id, forKey: .clientKeyId)
        try container.encode(self.publicKey, forKey: .key)
    }
}
