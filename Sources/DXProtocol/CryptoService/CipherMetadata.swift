// DXProtocol
// Copyright (C) 2023  FREEDOM SPACE, LLC

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
//  CipherMetadata.swift
//  DealogX
//
//  Created by Andriy Vasyk on 01.03.2023.
//

import Foundation
import CryptoKit

/// A struct that contains the metadata for a ciphertext.
///
/// The `CipherMetadata` struct contains the symmetric key, MAC key,
/// and digest of a ciphertext.
/// The symmetric key is used to encrypt the ciphertext,
/// the MAC key is used to calculate the MAC of the ciphertext,
/// and the digest is used to verify the integrity of the ciphertext.
public struct CipherMetadata: Codable {
    /// The raw representation of symmetric key used to encrypt attachment as a `Data`.
    /// The length of the key is 32 bytes - 256 bits
    public let key: Data

    /// The raw representation of the key to be used to calculate the MAC
    /// The length of the key is 32 bytes - 256 bits
    public let macKey: Data

    /// The raw representation of symmetric key used to encrypt attachment as a `Data`
    /// SHA256 algorithm is used to create digest
    public let digest: Data

    /// Initializes a `CipherMetadata` struct with the given symmetric key, MAC key, and digest.
    ///
    /// - Parameters:
    ///     - key: The symmetric key to use to encrypt the ciphertext.
    ///     - macKey: The key to use to calculate the MAC.
    ///     - digest: The digest of the ciphertext.
    public init(key: SymmetricKey, macKey: SymmetricKey, digest: SHA256.Digest) {
        self.key = key.withUnsafeBytes { Data($0) }
        self.macKey = macKey.withUnsafeBytes { Data($0) }
        self.digest = Data(digest)
    }

    /// Initializes a `CipherMetadata` struct with the given key, MAC key, and digest.
    ///
    /// - Parameters:
    ///     - key: The key to use to encrypt the ciphertext.
    ///     - macKey: The key to use to calculate the MAC.
    ///     - digest: The digest of the ciphertext.
    public init(key: Data, macKey: Data, digest: Data) {
        self.key = key
        self.macKey = macKey
        self.digest = digest
    }

    /// The coding keys for the `CipherMetadata` struct.
    public enum Keys: String, CodingKey {
        case key
        case macKey = "mac_key"
        case digest
    }

    /// Initializes a `CipherMetadata` struct from a decoder.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: `DXError.invalidKeyDataLength` if the cipher key or MAC key lengths are invalid.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: Keys.self)

        let cipherKey = try container.decode(Data.self, forKey: .key)
        guard cipherKey.count == DXProtocolConstants.cipherKeyLength else {
            throw DXError.invalidKeyDataLength("Invalid cipher key length: \(cipherKey.count)")
        }

        let macKey = try container.decode(Data.self, forKey: .macKey)
        guard macKey.count == DXProtocolConstants.macKeyLength else {
            throw DXError.invalidKeyDataLength("Invalid mac key length: \(macKey.count)")
        }

        self.key = cipherKey
        self.macKey = macKey
        self.digest = try container.decode(Data.self, forKey: .digest)
    }

    /// Encodes the `CipherMetadata` struct to a encoder.
    ///
    /// - Parameter encoder: The encoder to write to.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: Keys.self)
        try container.encode(self.key, forKey: .key)
        try container.encode(self.macKey, forKey: .macKey)
        try container.encode(self.digest, forKey: .digest)
    }
}
