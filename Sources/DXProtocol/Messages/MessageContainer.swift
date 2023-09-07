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
//  MessageContainer.swift
//  DealogX
//
//  Created by Andriy Vasyk on 09.12.2022.
//

import Foundation

///  A `MessageContainer` represents a container for encrypted messages with concrete types
public enum MessageContainer {
    /// Represents generic message for the session which is already established
    case secureMessage(SecureMessage)

    /// Represents a PreKey message which is used to establish a new session
    case preKeySecureMessage(PreKeySecureMessage)
}

/// A struct that can contain either a secure message or a pre-key secure message.
///
/// The MessageContainer struct can contain either a secure message or a pre-key secure message.
/// The secure message is encrypted using the ratchet keys,
/// and the pre-key secure message is encrypted using the pre-key ratchet keys.
extension MessageContainer: Codable {
    /// The different types of messages that can be encoded and decoded using the CodingKey protocol.
    ///
    /// - secureMessage: A secure message, which is encrypted using the ratchet keys.
    /// - preKeySecureMessage: A pre-key secure message, which is encrypted using the pre-key ratchet keys.
    public enum Keys: String, CodingKey {
        case secureMessage
        case preKeySecureMessage
    }

    /// Initializes a `MessageContainer` struct from a decoder.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: `DXError.invalidMessage` if the message type is invalid.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: Keys.self)

        if let base64String = try? container.decode(String.self, forKey: .secureMessage) {
            guard let data = Data(base64Encoded: base64String) else {
                throw DXError.invalidMessage("Failed to create message data from base64 string")
            }

            let message = try SecureMessage(data: data)
            self = .secureMessage(message)
        } else if let base64String = try? container.decode(String.self, forKey: .preKeySecureMessage) {
            guard let data = Data(base64Encoded: base64String) else {
                throw DXError.invalidMessage("Failed to create pre key data from base64 string")
            }

            let message = try PreKeySecureMessage(data: data)
            self = .preKeySecureMessage(message)
        } else {
            throw DXError.invalidMessage("Unexpected type of message container")
        }
    }

    /// Encodes the `MessageContainer` struct to a encoder.
    ///
    /// - Parameter encoder: The encoder to write to.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: Keys.self)

        switch self {
        case .secureMessage(let message):
            let base64String = message.serialized.base64EncodedString()
            try container.encode(base64String, forKey: .secureMessage)
        case .preKeySecureMessage(let preKeyMessage):
            let base64String = preKeyMessage.serialized.base64EncodedString()
            try container.encode(base64String, forKey: .preKeySecureMessage)
        }
    }
}
