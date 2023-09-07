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
//  PublicPreKeysBundle.swift
//  DealogX
//
//  Created by Andriy Vasyk on 30.12.2022.
//

import Foundation

/// A typealias for PublicPreKeysBundle.
///
/// This typealias is used to refer to a PublicPreKeysBundle instance 
/// when it is used as a request parameter to the publishPreKeys method.
public typealias PublishPreKeysRequest = PublicPreKeysBundle

/// Use `PublicPreKeysBundle` to publish public keys of current user during registration
public struct PublicPreKeysBundle: Codable {
    /// Public part of the identity key pair which is suitable for key agreement operations
    public let identityKey: IdentityKeyPublic

    /// Public part of the identity key pair which is suitable for signing operations
    public let signingKey: SigningKeyPublic

    /// The public signed pre key that is currently used by the user
    public let signedPreKey: SignedPreKeyPublic

    /// The list of one time pre keys
    public let oneTimePreKeys: [OneTimePreKeyPublic]

    /// Initializes a new `PublicPreKeysBundle` instance.
    ///
    /// - Parameters:
    ///     - identityKey: The public part of the identity key pair.
    ///     - signingKey: The public part of the signing key pair.
    ///     - signedPreKey: The public signed pre key.
    ///     - oneTimePreKeys: The list of one time pre keys.
    public init(
            identityKey: IdentityKeyPublic,
            signingKey: SigningKeyPublic,
            signedPreKey: SignedPreKeyPublic,
            oneTimePreKeys: [OneTimePreKeyPublic] = []
    ) {
        self.identityKey = identityKey
        self.signingKey = signingKey
        self.signedPreKey = signedPreKey
        self.oneTimePreKeys = oneTimePreKeys
    }

    /// The keys used to decode and encode a `PublicPreKeysBundle` instance.
    public enum CodingKeys: String, CodingKey {
        case identityKey = "identity_key"
        case signingKey = "signing_key"
        case signedPreKey = "signed_pre_key"
        case oneTimePreKeys = "one_time_pre_keys"
    }
}
