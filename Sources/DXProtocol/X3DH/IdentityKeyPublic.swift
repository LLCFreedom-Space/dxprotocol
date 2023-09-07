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
//  IdentityKeyPublic.swift
//  DealogX
//
//  Created by Andriy Vasyk on 06.12.2022.
//

import Foundation

/// The public part of the user's `IdentityKeyPair` identity which is suitable for key agreement operations
public struct IdentityKeyPublic: Codable, Equatable {
    /// The public part of the identity key pair. Underlying implementation of this identity key
    public let publicKey: PublicKey

    /// The raw representation of this identity key as a `Data`
    public var data: Data {
        return self.publicKey.data
    }

    /// The type of this identity key
    public var type: CryptoType {
        return self.publicKey.type
    }

    // MARK: - Initialisation

    /// Initialises identity key with public part of existing identity key pair
    /// See  documentation of `IdentityKeyPair` for more info
    /// - Parameter publicKey: The public part of the identity key pair
    public init(publicKey: PublicKey) {
        self.publicKey = publicKey
    }

    // MARK: - Equatable

    /// Conform `IdentityKeyPublic` to `Equatable` protocol
    /// - Parameters:
    ///   - lhs: `IdentityKeyPublic`
    ///   - rhs: `IdentityKeyPublic`
    /// - Returns: `Bool`
    public static func == (lhs: IdentityKeyPublic, rhs: IdentityKeyPublic) -> Bool {
        return lhs.publicKey == rhs.publicKey
    }

    // MARK: - Codable

    /// The coding keys for encoding and decoding a `IdentityKeyPublic`.
    public enum CodingKeys: String, CodingKey {
        case publicKey = "key"
    }
}
