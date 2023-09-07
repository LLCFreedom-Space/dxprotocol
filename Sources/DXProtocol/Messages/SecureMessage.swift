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
//  SecureMessage.swift
//  DealogX
//
//  Created by Andriy Vasyk on 09.12.2022.
//

import Foundation

///  A `SecureMessage` represents generic encrypted message in session which is already established.
public struct SecureMessage {
    /// A version of the message structure
    let messageVersion: UInt8

    /// The public key of the ratchet key pair from sending chain
    let senderRatchetKey: PublicKey

    /// The index of the current ratchet step
    let counter: UInt32

    /// The index of the previous ratchet step
    let previousCounter: UInt32

    /// The data containing encrypted information
    let encrypted: Data

    /// The MAC of this message
    let mac: Data

    /// Data that contains all necessary info needed for decryption this message
    let serialized: Data

    // MARK: - Initialization

    /// Initializes `SecureMessage` with data that contains all necessary info
    /// - Parameter data: Previously serialized data that contains all necessary info needed for initialization
    /// - Throws: Throws if the operation failed to be performed
    init(data: Data) throws {
        if data.count < DXProtocolConstants.macLength + 1 {
            throw DXError.invalidMessage("Data is too short \(data.count)")
        }

        let messageVersion = data[0] >> 4
        if messageVersion < DXProtocolConstants.cipertextMessageCurrentVersion {
            throw DXError.legacyCiphertextVersion("Found legacy ciphertext version \(messageVersion)")
        }
        if messageVersion > DXProtocolConstants.cipertextMessageCurrentVersion {
            throw DXError.unrecognizedMessageVersion("Unrecognized ciphertext version \(messageVersion)")
        }

        let startMacBytesIndex = data.count - DXProtocolConstants.macLength
        let mac = data[startMacBytesIndex ..< data.count]
        let protoSerializedData = data[1 ..< startMacBytesIndex]
        let proto = try SecureMessageProto(serializedData: protoSerializedData)

        self.messageVersion = messageVersion
        self.senderRatchetKey = try PublicKey(data: proto.ratchetKey)
        self.counter = proto.counter
        self.previousCounter = proto.previousCounter
        self.encrypted = proto.ciphertext
        self.mac = mac

        self.serialized = data
    }

    /// Initialises `SecureMessage` with all necessary data needed for encryption
    /// - Parameter messageVersion: A version of the message structure
    /// - Parameter macKey: The key to be used to calculate the MAC
    /// - Parameter senderRatchetKey: The public part of the ratchet key pair from sending chain
    /// - Parameter counter: The index of the current ratchet step
    /// - Parameter previousCounter: The index of the previous ratchet step
    /// - Parameter encrypted: The data containing encrypted information
    /// - Parameter senderIdentityKey: The identity key of the sender which is used to calculate MAC
    /// - Parameter receiverIdentityKey: The identity key of the receiver which is used to calculate MAC
    /// - Throws: Throws if the operation failed to be performed
    init(messageVersion: UInt8,
         macKey: Data,
         senderRatchetKey: PublicKey,
         counter: UInt32,
         previousCounter: UInt32,
         encrypted: Data,
         senderIdentityKey: IdentityKeyPublic,
         receiverIdentityKey: IdentityKeyPublic) throws {
        self.messageVersion = messageVersion
        self.senderRatchetKey = senderRatchetKey
        self.counter = counter
        self.previousCounter = previousCounter
        self.encrypted = encrypted

        var proto = SecureMessageProto()
        proto.ratchetKey = senderRatchetKey.data
        proto.counter = counter
        proto.previousCounter = previousCounter
        proto.ciphertext = encrypted

        var serialized: [UInt8] = []
        let data = try proto.serializedData()

        let capacity = 1 + data.count + DXProtocolConstants.macLength
        serialized.reserveCapacity(capacity)

        let versionByte = ((messageVersion & 0xF) << 4) | DXProtocolConstants.cipertextMessageCurrentVersion
        serialized.append(versionByte)
        serialized.append(contentsOf: Array(data))

        let mac = try Self.computeMac(
                senderIdentityKey: senderIdentityKey,
                receiverIdentityKey: receiverIdentityKey,
                macKey: macKey,
                message: Data(serialized))
        serialized.append(contentsOf: mac)

        self.serialized = Data(serialized)
        self.mac = mac
    }

    // MARK: - Interface

    /// Verifies the MAC of this message.
    /// - Parameter senderIdentityKey: The identity key of the sender
    /// - Parameter receiverIdentityKey: The identity key of the receiver
    /// - Parameter macKey: The key to be used to calculate the MAC
    /// - Throws: Throws if the operation failed to be performed
    /// - Returns: True if the message is authentic. False otherwise
    func verifyMac(senderIdentityKey: IdentityKeyPublic,
                   receiverIdentityKey: IdentityKeyPublic,
                   macKey: Data) throws -> Bool {
        let startMacBytesIndex = self.serialized.count - DXProtocolConstants.macLength
        let message = self.serialized[0..<startMacBytesIndex]

        // MAC we calculated using our local keys
        let ourMac = try Self.computeMac(
                senderIdentityKey: senderIdentityKey,
                receiverIdentityKey: receiverIdentityKey,
                macKey: macKey,
                message: message)

        // MAC we got from serialized data of received message
        let theirMac = self.serialized[startMacBytesIndex..<self.serialized.count]

        let result = (ourMac == theirMac)
        return result
    }

    // MARK: - Private

    /// Calculates and returns the MAC of the message. The length of the result must be equal to `Constants.macLength`
    /// - Parameter senderIdentityKey: The identity key of the sender
    /// - Parameter receiverIdentityKey: The identity key of the receiver
    /// - Parameter macKey: The key to be used to calculate the MAC
    /// - Parameter message: The serialized message to calculate the MAC for
    /// - Throws: Throws if the operation failed to be performed.
    /// - Returns: The MAC of the message
    static func computeMac(senderIdentityKey: IdentityKeyPublic,
                           receiverIdentityKey: IdentityKeyPublic,
                           macKey: Data,
                           message: Data) throws -> Data {
        guard macKey.count == DXProtocolConstants.macKeyLength else {
            throw DXError.invalidKey("Invalid length of macKey")
        }

        let data = senderIdentityKey.data + receiverIdentityKey.data + message
        let fullMacData = CryptoService.shared.hmacSHA256(for: data, with: macKey)

        return fullMacData[0 ..< DXProtocolConstants.macLength]
    }
}

/// Equatable protocol implementation for `SecureMessage` struct.
///
/// Two `SecureMessage` structs are considered equal if they have the same:
///
/// - messageVersion
/// - senderRatchetKey
/// - counter
/// - previousCounter
/// - encrypted
/// - mac
extension SecureMessage: Equatable {
    /// Conform `SecureMessage` to `Equatable` protocol
    /// - Parameters:
    ///   - lhs: `SecureMessage`
    ///   - rhs: `SecureMessage`
    /// - Returns: `Bool`
    public static func == (lhs: SecureMessage, rhs: SecureMessage) -> Bool {
        lhs.messageVersion == rhs.messageVersion &&
                lhs.senderRatchetKey == rhs.senderRatchetKey &&
                lhs.counter == rhs.counter &&
                lhs.previousCounter == rhs.previousCounter &&
                lhs.encrypted == rhs.encrypted &&
                lhs.mac == rhs.mac
    }
}
