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
//  PreKeySecureMessageTests.swift
//  DealogXTests
//
//  Created by Andriy Vasyk on 10.01.2023.
//

import Foundation
import XCTest
@testable import DXProtocol

final class PreKeySecureMessageTests: XCTestCase {
    func testSerializeDeserialize() throws {
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

        guard !message.serialized.isEmpty else {
            fatalError("Failed to serialise PreKeySecureMessage")
        }

        let deserialised = try PreKeySecureMessage(data: message.serialized)
        XCTAssertEqual(deserialised, message)
    }

    func testDataIsEmpty() throws {
        let data = Data()
        XCTAssertThrowsError(try PreKeySecureMessage(data: data)) { error in
            XCTAssertEqual(error as? DXError, DXError.invalidMessage("PreKey data is too short \(data.count)"))
        }
    }

    func testMessageVersionIsLessThanLegacyCiphertextVersion() throws {
        let data = Data([0b00001000, 0x00])
        XCTAssertThrowsError(try PreKeySecureMessage(data: data)) { error in
            XCTAssertEqual(error as? DXError, DXError.legacyCiphertextVersion("PreKey: legacy ciphertext version 0"))
        }
    }

    func testMessageVersionIsMoreThanLegacyCiphertextVersion() throws {
        let data = Data([0b10001000, 0x00])
        XCTAssertThrowsError(try PreKeySecureMessage(data: data)) { error in
            XCTAssertEqual(error as? DXError, DXError.unrecognizedMessageVersion("PreKey: unrecognized version 8"))
        }
    }
}
