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
//  DXError.swift
//  DealogX
//
//  Created by Andriy Vasyk on 06.12.2022.
//

import Foundation

/// An enum that represents errors that can occur in the DataX Cryptography library.
///
/// The DXError enum is used to report errors that occur during the encryption, decryption,
/// and signing of messages.
public enum DXError: Error, Equatable {
    /// The operation is not in a valid state.
    case invalidState(String)
    /// An internal error occurred.
    case internalError(String)
    /// A required parameter is null.
    case nullParameter(String)
    /// An invalid argument was passed to the function.
    case invalidArgument(String)
    /// The data is not of the expected type.
    case invalidType(String)
    /// The UTF-8 string is invalid.
    case invalidUtf8String(String)
    /// A Protobuf error occurred.
    case protobufError(String)
    /// The ciphertext version is not supported.
    case legacyCiphertextVersion(String)
    /// The ciphertext version is unknown.
    case unknownCiphertextVersion(String)
    /// The message version is unrecognized.
    case unrecognizedMessageVersion(String)
    /// The key data length is invalid.
    case invalidKeyDataLength(String)
    /// The key data is invalid.
    case invalidKeyData(String)
    /// The message is invalid.
    case invalidMessage(String)
    /// The key is invalid.
    case invalidKey(String)
    /// The signature is invalid.
    case invalidSignature(String)
    /// The fingerprint version does not match the message version.
    case fingerprintVersionMismatch(String)
    /// An error occurred while parsing the fingerprint.
    case fingerprintParsingError(String)
    /// The sender tried to send a message to itself using a sealed sender key.
    case sealedSenderSelfSend(String)
    /// The identity of the sender is not trusted.
    case untrustedIdentity(String)
    /// The key identifier is invalid.
    case invalidKeyIdentifier(String)
    /// The session was not found.
    case sessionNotFound(String)
    /// The session is invalid.
    case invalidSession(String)
    /// The sender key session is invalid for the given distribution ID.
    case invalidSenderKeySession(distributionId: UUID, message: String)
    /// The message has already been sent.
    case duplicatedMessage(String)
    /// The MAC verification failed.
    case messageVerificationFailed(String)
    /// An error occurred in a callback.
    case callbackError(String)
    /// An unknown error occurred.
    case unknown(UInt32, String)
}
