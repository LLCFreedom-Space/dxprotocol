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
//  PreKeySecureMessage.swift
//  DealogX
//
//  Created by Andriy Vasyk on 09.12.2022.
//

import Foundation
import SwiftProtobuf

/// `PreKeySecureMessage` is  a special type of message that must be used to establish a new session.
public struct PreKeySecureMessage {
    /// A version of the message structure
    let messageVersion: UInt8

    /// Registration identifier of the sender
    let registrationId: UUID?

    /// The identifier of the one time pre key from `PreKeyBundle` of remote user
    let oneTimePreKeyId: UUID?

    /// The identifier of signed pre key from `PreKeyBundle` of remote user
    let signedPreKeyId: UUID

    /// The public base key used to establish session (EKa)
    let senderBaseKey: PublicKey

    /// The public identity key of the sender
    let senderIdentityKey: IdentityKeyPublic

    /// The message as `SecureMessage`included in the pre key message
    let secureMessage: SecureMessage

    /// The data representation of the message. Contains a serialized data that contains
    /// all necessary info needed for establishing new session and decrypting of included `SecureMessage`
    let serialized: Data

    // MARK: - Initialization

    /// Initializes `PreKeySecureMessage` with data that contains all necessary info
    /// - Parameter data: Previously serialized data that contains all necessary info needed for initialization
    /// - Throws: Throws if the operation failed to be performed
    public init(data: Data) throws {
        if data.isEmpty {
            throw DXError.invalidMessage("PreKey data is too short \(data.count)")
        }

        let messageVersion = data[0] >> 4
        if messageVersion < DXProtocolConstants.cipertextMessageCurrentVersion {
            throw DXError.legacyCiphertextVersion("PreKey: legacy ciphertext version \(messageVersion)")
        }
        if messageVersion > DXProtocolConstants.cipertextMessageCurrentVersion {
            throw DXError.unrecognizedMessageVersion("PreKey: unrecognized version \(messageVersion)")
        }

        let protoSerializedData = data[1 ..< data.count]
        let proto = try PreKeySecureMessageProto(serializedData: protoSerializedData)

        // This code is not covered by tests
        guard let signedPreKeyId = UUID(uuidString: proto.signedPreKeyID) else {
            throw DXError.invalidMessage("Signed preKey identifier is invalid \(proto.signedPreKeyID)")
        }

        self.messageVersion = messageVersion
        self.registrationId = UUID(uuidString: proto.registrationID)
        self.oneTimePreKeyId = UUID(uuidString: proto.oneTimePreKeyID)
        self.signedPreKeyId = signedPreKeyId
        self.senderBaseKey = try PublicKey(data: proto.baseKey)
        self.senderIdentityKey = IdentityKeyPublic(publicKey: try PublicKey(data: proto.identityKey))
        self.secureMessage = try SecureMessage(data: proto.message)

        self.serialized = data
    }

    /// Initialises a new pre key message
    /// - Parameter messageVersion: A version of the message structure
    /// - Parameter registrationId: Registration identifier of the sender
    /// - Parameter oneTimePreKeyId: The identifier of the one time pre key from `PreKeyBundle` of remote user
    /// - Parameter signedPreKeyId: The id of signed pre key from `PreKeyBundle` of remote user
    /// - Parameter senderBaseKey: The public base key used to establish session (EKa)
    /// - Parameter senderIdentityKey: The identity key of the sender
    /// - Parameter secureMessage: The message as `SecureMessage`included in the pre key message
    public init(messageVersion: UInt8,
                registrationId: UUID?,
                oneTimePreKeyId: UUID?,
                signedPreKeyId: UUID,
                senderBaseKey: PublicKey,
                senderIdentityKey: IdentityKeyPublic,
                secureMessage: SecureMessage) throws {
        self.messageVersion = messageVersion
        self.registrationId = registrationId
        self.oneTimePreKeyId = oneTimePreKeyId
        self.signedPreKeyId = signedPreKeyId
        self.senderBaseKey = senderBaseKey
        self.senderIdentityKey = senderIdentityKey
        self.secureMessage = secureMessage

        var proto = PreKeySecureMessageProto()
        proto.signedPreKeyID = signedPreKeyId.uuidString
        proto.baseKey = senderBaseKey.data
        proto.identityKey = senderIdentityKey.data
        proto.message = secureMessage.serialized
        if let id = registrationId {
            proto.registrationID = id.uuidString
        }
        if let id = oneTimePreKeyId {
            proto.oneTimePreKeyID = id.uuidString
        }

        var serialized = [UInt8]()
        let data = try proto.serializedData()

        let capacity = 1 + data.count
        serialized.reserveCapacity(capacity)

        let versionByte = ((messageVersion & 0xF) << 4) | DXProtocolConstants.cipertextMessageCurrentVersion
        serialized.append(versionByte)
        serialized.append(contentsOf: Array(data))
        self.serialized = Data(serialized)
    }
}

/// Equatable protocol implementation for `PreKeySecureMessage` struct.
///
/// Two `PreKeySecureMessage` structs are considered equal if they have the same:
///
/// - messageVersion
/// - registrationId
/// - oneTimePreKeyId
/// - signedPreKeyId
/// - senderBaseKey
/// - senderIdentityKey
/// - secureMessage
extension PreKeySecureMessage: Equatable {
    /// Conform `PreKeySecureMessage` to `Equatable` protocol
    /// - Parameters:
    ///   - lhs: `PreKeySecureMessage`
    ///   - rhs: `PreKeySecureMessage`
    /// - Returns: `Bool`
    public static func == (lhs: PreKeySecureMessage, rhs: PreKeySecureMessage) -> Bool {
        lhs.messageVersion == rhs.messageVersion &&
                lhs.registrationId == rhs.registrationId &&
                lhs.oneTimePreKeyId == rhs.oneTimePreKeyId &&
                lhs.signedPreKeyId == rhs.signedPreKeyId &&
                lhs.senderBaseKey == rhs.senderBaseKey &&
                lhs.senderIdentityKey == rhs.senderIdentityKey &&
                lhs.secureMessage == rhs.secureMessage
    }
}
