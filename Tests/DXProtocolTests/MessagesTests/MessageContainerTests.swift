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
//  MessageContainerTests.swift
//  DealogXTests
//
//  Created by Andriy Vasyk on 10.01.2023.
//

import Foundation
import XCTest
@testable import DXProtocol

final class MessageContainerTests: XCTestCase {
    func testSerializeDeserializeSecureMessage() throws {
        let aliceRatchetKey = try KeyPair().publicKey
        let aliceIdentityKey = IdentityKeyPublic(publicKey: try KeyPair().publicKey)
        let bobIdentityKey = IdentityKeyPublic(publicKey: try KeyPair().publicKey)
        let macKeyData = Data([
            0xce, 0x41, 0x35, 0xc2, 0x19, 0xb1, 0xdb, 0xe2, 0xfa, 0x66, 0x6d, 0xdf, 0xb3, 0x9a, 0x7e,
            0x46, 0x7b, 0xd8, 0x33, 0xf9, 0xcf, 0x30, 0xd9, 0x9d, 0x96, 0x0e, 0xe7, 0x38, 0x07, 0x25,
            0xa7, 0xf1
        ])

        let encrypted = Data("DXProtocolMessageContainer".utf8)

        let message = try SecureMessage(
                messageVersion: DXProtocolConstants.cipertextMessageCurrentVersion,
                macKey: macKeyData,
                senderRatchetKey: aliceRatchetKey,
                counter: 3,
                previousCounter: 2,
                encrypted: encrypted,
                senderIdentityKey: aliceIdentityKey,
                receiverIdentityKey: bobIdentityKey)
        let container = MessageContainer.secureMessage(message)
        let data = try JSONEncoder().encode(container)

        let decoded = try JSONDecoder().decode(MessageContainer.self, from: data)
        if case .secureMessage(let content) = decoded {
            XCTAssertEqual(content, message)
        } else {
            XCTFail("Failed to decode message container with secure message")
        }
    }

    func testSerializeSecureMessageInvalidMessage() throws {
        let json = """
                   {"secureMessage":"not_valid"}
                   """.utf8

        do {
            let result = try JSONDecoder().decode(MessageContainer.self, from: Data(json))
            XCTFail("Should be failed: \(result)")
        } catch DXError.invalidMessage {
            return
        } catch {
            XCTFail("Invalid error type:\(error)")
        }
    }

    func testSerializeDeserializePreKeySecureMessage() throws {
        let aliceRatchetKey = try KeyPair().publicKey
        let aliceBaseKey = try KeyPair().publicKey
        let aliceIdentityKey = IdentityKeyPublic(publicKey: try KeyPair().publicKey)
        let bobIdentityKey = IdentityKeyPublic(publicKey: try KeyPair().publicKey)
        let macKeyData = Data([
            0xce, 0x41, 0x35, 0xc2, 0x19, 0xb1, 0xdb, 0xe2, 0xfa, 0x66, 0x6d, 0xdf, 0xb3, 0x9a, 0x7e,
            0x46, 0x7b, 0xd8, 0x33, 0xf9, 0xcf, 0x30, 0xd9, 0x9d, 0x96, 0x0e, 0xe7, 0x38, 0x07, 0x25,
            0xa7, 0xf1
        ])

        let registrationId = UUID()
        let oneTimePreKeyId = UUID()
        let signedPreKeyId = UUID()

        guard let encrypted = "DXProtocolSecureMessage".data(using: .utf8) else {
            fatalError("Failed to create data from string")
        }

        let secureMessage = try SecureMessage(
                messageVersion: DXProtocolConstants.cipertextMessageCurrentVersion,
                macKey: macKeyData,
                senderRatchetKey: aliceRatchetKey,
                counter: 3,
                previousCounter: 2,
                encrypted: encrypted,
                senderIdentityKey: aliceIdentityKey,
                receiverIdentityKey: bobIdentityKey)
        let message = try PreKeySecureMessage(
                messageVersion: DXProtocolConstants.cipertextMessageCurrentVersion,
                registrationId: registrationId,
                oneTimePreKeyId: oneTimePreKeyId,
                signedPreKeyId: signedPreKeyId,
                senderBaseKey: aliceBaseKey,
                senderIdentityKey: aliceIdentityKey,
                secureMessage: secureMessage)

        let container = MessageContainer.preKeySecureMessage(message)
        let data = try JSONEncoder().encode(container)

        let decoded = try JSONDecoder().decode(MessageContainer.self, from: data)
        if case .preKeySecureMessage(let content) = decoded {
            XCTAssertEqual(content, message)
        } else {
            XCTFail("Failed to decode message container with pre key message")
        }
    }

    func testSerializePreKeySecureMessageInvalidMessage() throws {
        let json = """
                   {"preKeySecureMessage":"not_valid"}
                   """.utf8

        do {
            let result = try JSONDecoder().decode(MessageContainer.self, from: Data(json))
            XCTFail("Should be failed: \(result)")
        } catch DXError.invalidMessage {
            return
        } catch {
            XCTFail("Invalid error type:\(error)")
        }
    }

    func testInitFromDecoderWithInvalidKey() throws {
        let json = """
                   {"invalidKey":"not_valid"}
                   """.utf8

        do {
            let result = try JSONDecoder().decode(MessageContainer.self, from: Data(json))
            XCTFail("Should be failed: \(result)")
        } catch DXError.invalidMessage {
            return
        } catch {
            XCTFail("Invalid error type:\(error)")
        }
    }
}
