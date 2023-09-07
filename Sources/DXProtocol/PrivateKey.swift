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
//  PrivateKey.swift
//  DealogX
//
//  Created by Andriy Vasyk on 06.12.2022.
//

import Foundation

/// `PrivateKey` is a representation of private part for any `KeyPair`
public struct PrivateKey: Equatable {
    /// The raw representation of this private key as a `Data`
    let data: Data

    /// The type of this private key
    let type: CryptoType

    // MARK: - Initialisation

    /// Initialises a new private key.
    /// - Parameter data: The raw representation of the private key. 32-bytes for Curve25519
    /// - Parameter type: The type of this key
    /// - Throws: `DXError` errors
    public init(data: Data, type: CryptoType = .curve25519) throws {
        if type == .curve25519, data.count != DXProtocolConstants.curve25519KeyLength {
            throw DXError.invalidKeyDataLength("Invalid key length: \(data.count)")
        }

        self.data = data
        self.type = type
    }

    /// Initialises a new random private key.
    public init() {
        self.data = CryptoService.shared.generatePrivateKeyRawData()
        self.type = .curve25519
    }

    // MARK: - Interface

    /// Returns the corresponding agreement public key for this private key
    /// - Throws: Throws if the operation failed to be performed
    public func getAgreementPublicKey() throws -> PublicKey {
        let data = try CryptoService.shared.publicAgreementKeyDataFor(privateKeyData: self.data)
        return try PublicKey(data: data, type: self.type)
    }

    /// Returns the corresponding signing public key for this private key
    /// - Throws: Throws if the operation failed to be performed
    public func getSigningPublicKey() throws -> PublicKey {
        let data = try CryptoService.shared.publicSigningKeyDataFor(privateKeyData: self.data)
        return try PublicKey(data: data, type: self.type)
    }

    /// Returns the shared agreement between this private key and the specified public key.
    /// - Parameter other: The public key from the other remote user
    /// - Throws: `Error` errors
    /// - Returns: The shared agreement data
    public func calculateKeyAgreement(with other: PublicKey) throws -> Data {
        return try CryptoService.shared.performKeyAgreement(of: self.data, with: other.data)
    }

    /// Returns a signature for the specified data
    /// - Parameter data: The data to sign
    /// - Returns: The signature for the data
    /// - Throws: Throws if the operation failed to be performed
    public func signature(for data: Data) throws -> Data {
        return try CryptoService.shared.signature(for: data, with: self.data)
    }

    // MARK: - Equatable

    /// Conform `PrivateKey` to `Equatable` protocol
    /// - Parameters:
    ///   - lhs: `PrivateKey`
    ///   - rhs: `PrivateKey`
    /// - Returns: `Bool`
    public static func == (lhs: PrivateKey, rhs: PrivateKey) -> Bool {
        return lhs.data == rhs.data
    }
}

/// A private key that can be used for encryption and decryption.
///
/// The PrivateKey struct represents a private key that can be used for encryption and decryption. 
/// The private key is encoded as a Data object.
extension PrivateKey: Codable {
    /// The keys used to decode and encode a `PrivateKey` instance.
    public enum Keys: String, CodingKey {
        case data
        case type
    }

    /// Initializes a new `PrivateKey` instance from a decoder.
    ///
    /// - Parameter decoder: The decoder to read from.
    ///
    /// - Throws: An error if the decoder cannot decode the data.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: Keys.self)
        let data = try container.decode(Data.self, forKey: .data)
        let type = try container.decode(CryptoType.self, forKey: .type)
        try self.init(data: data, type: type)
    }

    /// Encodes the `PrivateKey` instance to an encoder.
    ///
    /// - Parameter encoder: The encoder to write to.
    ///
    /// - Throws: An error if the encoder cannot encode the data.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: Keys.self)
        try container.encode(self.type, forKey: .type)
        try container.encode(self.data, forKey: .data)
    }
}
