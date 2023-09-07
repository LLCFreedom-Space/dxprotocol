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
//  MessagesProtobufTests.swift
//  
//
//  Created by Sergey Basin on 16.08.2023.
//

import Foundation
import XCTest
@testable import DXProtocol

final class MessagesProtobufTests: XCTestCase {
    func testSecureMessageProtoRatchetKey() {
        var sut = SecureMessageProto()
        XCTAssertTrue(sut.ratchetKey.isEmpty)
        XCTAssertFalse(sut.hasRatchetKey)

        sut.ratchetKey = Data(Array(repeating: 0x01, count: 8))
        XCTAssertFalse(sut.ratchetKey.isEmpty)
        XCTAssertTrue(sut.hasRatchetKey)

        sut.clearRatchetKey()
        XCTAssertTrue(sut.ratchetKey.isEmpty)
        XCTAssertFalse(sut.hasRatchetKey)
    }

    func testSecureMessageProtoCounter() {
        var sut = SecureMessageProto()
        XCTAssertEqual(sut.counter, 0)
        XCTAssertFalse(sut.hasCounter)

        let newValue: UInt32 = 1
        sut.counter = newValue
        XCTAssertEqual(sut.counter, newValue)
        XCTAssertTrue(sut.hasCounter)

        sut.clearCounter()
        XCTAssertEqual(sut.counter, 0)
        XCTAssertFalse(sut.hasCounter)
    }

    func testSecureMessageProtoPreviousCounter() {
        var sut = SecureMessageProto()
        XCTAssertEqual(sut.previousCounter, 0)
        XCTAssertFalse(sut.hasPreviousCounter)

        let newValue: UInt32 = 1
        sut.previousCounter = newValue
        XCTAssertEqual(sut.previousCounter, newValue)
        XCTAssertTrue(sut.hasPreviousCounter)

        sut.clearPreviousCounter()
        XCTAssertEqual(sut.previousCounter, 0)
        XCTAssertFalse(sut.hasPreviousCounter)
    }

    func testSecureMessageProtoCiphertext() {
        var sut = SecureMessageProto()
        XCTAssertTrue(sut.ciphertext.isEmpty)
        XCTAssertFalse(sut.hasCiphertext)

        sut.ciphertext = Data(Array(repeating: 0x01, count: 8))
        XCTAssertFalse(sut.ciphertext.isEmpty)
        XCTAssertTrue(sut.hasCiphertext)

        sut.clearCiphertext()
        XCTAssertTrue(sut.ciphertext.isEmpty)
        XCTAssertFalse(sut.hasCiphertext)
    }

    func testSecureMessageCompare() {
        var sut = SecureMessageProto()
        sut.ratchetKey = Data(UUID().uuidString.utf8)
        sut.counter = UInt32.random(in: 1...100)
        sut.previousCounter = UInt32.random(in: 1...100)
        sut.ciphertext = Data(UUID().uuidString.utf8)

        var sut2 = SecureMessageProto()
        sut2.ratchetKey = Data(UUID().uuidString.utf8)
        sut2.counter = UInt32.random(in: 1...100)
        sut2.previousCounter = UInt32.random(in: 1...100)
        sut2.ciphertext = Data(UUID().uuidString.utf8)

        XCTAssertEqual(sut, sut)
        XCTAssertNotEqual(sut, sut2)
    }

    func testPreKeySecureMessageProtoRegistrationID() {
        var sut = PreKeySecureMessageProto()
        XCTAssertTrue(sut.registrationID.isEmpty)
        XCTAssertFalse(sut.hasRegistrationID)

        let newValue = "newvalue"
        sut.registrationID = newValue
        XCTAssertEqual(sut.registrationID, newValue)
        XCTAssertTrue(sut.hasRegistrationID)

        sut.clearRegistrationID()
        XCTAssertTrue(sut.registrationID.isEmpty)
        XCTAssertFalse(sut.hasRegistrationID)
    }

    func testPreKeySecureMessageProtoOneTimePreKeyID() {
        var sut = PreKeySecureMessageProto()
        XCTAssertTrue(sut.oneTimePreKeyID.isEmpty)
        XCTAssertFalse(sut.hasOneTimePreKeyID)

        let newValue = "newvalue"
        sut.oneTimePreKeyID = newValue
        XCTAssertEqual(sut.oneTimePreKeyID, newValue)
        XCTAssertTrue(sut.hasOneTimePreKeyID)

        sut.clearOneTimePreKeyID()
        XCTAssertTrue(sut.oneTimePreKeyID.isEmpty)
        XCTAssertFalse(sut.hasOneTimePreKeyID)
    }

    func testPreKeySecureMessageProtoSignedPreKeyID() {
        var sut = PreKeySecureMessageProto()
        XCTAssertTrue(sut.signedPreKeyID.isEmpty)
        XCTAssertFalse(sut.hasSignedPreKeyID)

        let newValue = "newvalue"
        sut.signedPreKeyID = newValue
        XCTAssertEqual(sut.signedPreKeyID, newValue)
        XCTAssertTrue(sut.hasSignedPreKeyID)

        sut.clearSignedPreKeyID()
        XCTAssertTrue(sut.signedPreKeyID.isEmpty)
        XCTAssertFalse(sut.hasSignedPreKeyID)
    }

    func testPreKeySecureMessageProtoBaseKey() {
        var sut = PreKeySecureMessageProto()
        XCTAssertTrue(sut.baseKey.isEmpty)
        XCTAssertFalse(sut.hasBaseKey)

        sut.baseKey = Data(Array(repeating: 0x01, count: 8))
        XCTAssertFalse(sut.baseKey.isEmpty)
        XCTAssertTrue(sut.hasBaseKey)

        sut.clearBaseKey()
        XCTAssertTrue(sut.baseKey.isEmpty)
        XCTAssertFalse(sut.hasBaseKey)
    }

    func testPreKeySecureMessageProtoIdentityKey() {
        var sut = PreKeySecureMessageProto()
        XCTAssertTrue(sut.identityKey.isEmpty)
        XCTAssertFalse(sut.hasIdentityKey)

        sut.identityKey = Data(Array(repeating: 0x01, count: 8))
        XCTAssertFalse(sut.identityKey.isEmpty)
        XCTAssertTrue(sut.hasIdentityKey)

        sut.clearIdentityKey()
        XCTAssertTrue(sut.identityKey.isEmpty)
        XCTAssertFalse(sut.hasIdentityKey)
    }

    func testPreKeySecureMessageProtoMessage() {
        var sut = PreKeySecureMessageProto()
        XCTAssertTrue(sut.message.isEmpty)
        XCTAssertFalse(sut.hasMessage)

        sut.message = Data(Array(repeating: 0x01, count: 8))
        XCTAssertFalse(sut.message.isEmpty)
        XCTAssertTrue(sut.hasMessage)

        sut.clearMessage()
        XCTAssertTrue(sut.message.isEmpty)
        XCTAssertFalse(sut.hasMessage)
    }

    func testPreKeySecureMessageCompare() {
        var sut = PreKeySecureMessageProto()
        sut.registrationID = UUID().uuidString
        sut.oneTimePreKeyID = UUID().uuidString
        sut.signedPreKeyID = UUID().uuidString
        sut.baseKey = Data(UUID().uuidString.utf8)
        sut.identityKey = Data(UUID().uuidString.utf8)
        sut.message = Data(UUID().uuidString.utf8)

        var sut2 = PreKeySecureMessageProto()
        sut2.registrationID = UUID().uuidString
        sut2.oneTimePreKeyID = UUID().uuidString
        sut2.signedPreKeyID = UUID().uuidString
        sut2.baseKey = Data(UUID().uuidString.utf8)
        sut2.identityKey = Data(UUID().uuidString.utf8)
        sut2.message = Data(UUID().uuidString.utf8)

        XCTAssertEqual(sut, sut)
        XCTAssertNotEqual(sut, sut2)
    }
}
