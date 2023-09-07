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
//  PreKeyBundle.swift
//  DealogX
//
//  Created by Andriy Vasyk on 06.12.2022.
//

import Foundation

/// Pre Key bundles are used to initiate new conversations with remote users
public struct PreKeyBundle {
    /// The identity key of the remote user which is suitable for key agreement operations
    public let identityKey: IdentityKeyPublic

    /// The signing key of the remote user which is suitable for signing operations
    public let signingKey: SigningKeyPublic

    /// The identifier that is assigned to the remote user during registration
    public let registrationId: UUID

    /// The device identifier of the remote user
    public let deviceId: UUID

    /// The public signed pre key that is currently used by remote user
    public let signedPreKey: SignedPreKeyPublic

    /// The one time pre key, if a pre key is present
    public let oneTimePreKey: OneTimePreKeyPublic?

    ///
    public init(
            identityKey: IdentityKeyPublic,
            signingKey: SigningKeyPublic,
            registrationId: UUID,
            deviceId: UUID,
            signedPreKey: SignedPreKeyPublic,
            oneTimePreKey: OneTimePreKeyPublic? = nil
    ) {
        self.identityKey = identityKey
        self.signingKey = signingKey
        self.registrationId = registrationId
        self.deviceId = deviceId
        self.signedPreKey = signedPreKey
        self.oneTimePreKey = oneTimePreKey
    }
}

/// A bundle of pre-keys for a user.
///
/// This struct represents a bundle of pre-keys for a user. 
/// Pre-keys are used to establish a secure connection with a peer without having to exchange long-term keys.
extension PreKeyBundle: Codable {
    /// The keys used to decode and encode a `PreKeyBundle` instance.
    public enum Keys: String, CodingKey {
        case identityKey = "identity_key"
        case signingKey = "signing_key"
        case userId = "user_id"
        case deviceId = "device_id"
        case signedPreKey = "signed_pre_key"
        case oneTimePreKey = "one_time_pre_key"
    }

    /// Initializes a new `PreKeyBundle` instance from a decoder.
    ///
    /// - Parameter decoder: The decoder to read from.
    ///
    /// - Throws: An error if the decoder cannot decode the data.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: Keys.self)
        self.identityKey = try container.decode(IdentityKeyPublic.self, forKey: .identityKey)
        self.signingKey = try container.decode(SigningKeyPublic.self, forKey: .signingKey)
        self.registrationId = try container.decode(UUID.self, forKey: .userId)
        self.deviceId = try container.decode(UUID.self, forKey: .deviceId)
        self.signedPreKey = try container.decode(SignedPreKeyPublic.self, forKey: .signedPreKey)
        self.oneTimePreKey = try container.decodeIfPresent(OneTimePreKeyPublic.self, forKey: .oneTimePreKey)
    }

    /// Encodes the `PreKeyBundle` instance to an encoder.
    ///
    /// - Parameter encoder: The encoder to write to.
    ///
    /// - Throws: An error if the encoder cannot encode the data.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: Keys.self)
        try container.encode(self.identityKey, forKey: .identityKey)
        try container.encode(self.signingKey, forKey: .signingKey)
        try container.encode(self.registrationId, forKey: .userId)
        try container.encode(self.deviceId, forKey: .deviceId)
        try container.encode(self.signedPreKey, forKey: .signedPreKey)
        try container.encode(self.oneTimePreKey, forKey: .oneTimePreKey)
    }
}
