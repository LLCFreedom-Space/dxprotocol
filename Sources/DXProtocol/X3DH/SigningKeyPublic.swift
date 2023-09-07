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
//  SigningKeyPublic.swift
//  DealogX
//
//  Created by Andriy Vasyk on 02.01.2023.
//

import Foundation

/// The public part of the user's `IdentityKeyPair` identity c
public struct SigningKeyPublic: Codable, Equatable {
    /// The underlying implementation of this signing key
    public let publicKey: PublicKey

    // MARK: - Initialization

    /// Initializes signing key with public part of existing identity key pair
    /// See  documentation of `IdentityKeyPair` for more info
    /// - Parameter publicKey: The public signing part of the identity key pair
    public init(publicKey: PublicKey) {
        self.publicKey = publicKey
    }

    // MARK: - Interface

    /// Verifies that the signature corresponds to the signed data.
    /// - Parameter signature: The 64-bytes signature to verify
    /// - Parameter digest: The digest that was signed
    /// - Returns: True if the signature is valid. False otherwise
    /// - Throws: Throws if the operation failed to be performed
    public func verifySignature(_ signature: Data, for digest: Data) throws -> Bool {
        guard self.publicKey.type == .curve25519 else {
            throw DXError.invalidKey("Currently only Curve25519 keys are supported")
        }

        return try CryptoService.shared.isValidSignature(
                signature,
                for: digest,
                publicKey: self.publicKey.data)
    }

    // MARK: - Equatable

    /// Conform `SigningKeyPublic` to `Equatable` protocol
    /// - Parameters:
    ///   - lhs: `SigningKeyPublic`
    ///   - rhs: `SigningKeyPublic`
    /// - Returns: `Bool`
    public static func == (lhs: SigningKeyPublic, rhs: SigningKeyPublic) -> Bool {
        return lhs.publicKey == rhs.publicKey
    }

    // MARK: - Codable
    /// The keys used to decode and encode a `SigningKeyPublic` instance
    public enum CodingKeys: String, CodingKey {
        case publicKey = "key"
    }
}
