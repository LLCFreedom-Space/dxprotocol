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
//  PublicKey.swift
//  DealogX
//
//  Created by Andriy Vasyk on 06.12.2022.
//

import Foundation

/// `PublicKey` is a representation of public part for any `KeyPair`
public struct PublicKey {
    /// The raw representation of this public key as a `Data`
    public let data: Data

    /// The type of this public key
    public let type: CryptoType

    // MARK: - Initialisation

    /// Initialises a new public key.
    /// - Parameter data: The 32-bytes representation of the public key.
    /// - Parameter type: The type of this key
    /// - Throws: `DXError` errors
    public init(data: Data, type: CryptoType = .curve25519) throws {
        if type == .curve25519, data.count != DXProtocolConstants.curve25519KeyLength {
            throw DXError.invalidKeyDataLength("Invalid key length: \(data.count)")
        }

        self.data = data
        self.type = type
    }
}

/// A public key that can be used for encryption and verification.
///
/// The PublicKey struct represents a public key that can be used for encryption and verification. 
/// The public key is encoded as a Data object.
extension PublicKey: Equatable {
    /// Conform `PublicKey` to `Equatable` protocol
    /// - Parameters:
    ///   - lhs: `PublicKey`
    ///   - rhs: `PublicKey`
    /// - Returns: `Bool`
    public static func == (lhs: PublicKey, rhs: PublicKey) -> Bool {
        return lhs.data == rhs.data
    }
}

extension PublicKey: Codable {
    /// The keys used to decode and encode a `PublicKey` instance.
    public enum Keys: String, CodingKey {
        case data
        case type
    }

    /// Initializes a new `PublicKey` instance from a decoder.
    ///
    /// - Parameter decoder: The decoder to read from.
    ///
    /// - Throws: An error if the decoder cannot decode the data.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: Keys.self)

        let base64String = try container.decode(String.self, forKey: .data)
        guard let data = Data(base64Encoded: base64String) else {
            throw DXError.invalidKeyData("Failed to decode public pre key")
        }

        guard data.count == DXProtocolConstants.curve25519KeyLength else {
            throw DXError.invalidKeyDataLength("Invalid key length: \(data.count)")
        }

        let type = try container.decode(CryptoType.self, forKey: .type)
        guard type == .curve25519 else {
            throw DXError.invalidType("Invalid key type")
        }

        self.data = data
        self.type = type
    }

    /// Encodes the `PublicKey` instance to an encoder.
    ///
    /// - Parameter encoder: The encoder to write to.
    ///
    /// - Throws: An error if the encoder cannot encode the data.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: Keys.self)

        try container.encode(self.type, forKey: .type)

        let base64String = self.data.base64EncodedString()
        try container.encode(base64String, forKey: .data)
    }
}
