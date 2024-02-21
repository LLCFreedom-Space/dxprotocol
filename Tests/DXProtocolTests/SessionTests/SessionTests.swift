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
//  SessionTests.swift
//  DealogXTests
//
//  Created by Mykhailo Bondarenko on 11.07.2023.
//

import XCTest

@testable import DXProtocol

// swiftlint:disable file_length
// swiftlint:disable type_body_length
// swiftlint:disable function_body_length
func XCTAssertPreKeyMessage(
        _ messageContainer: MessageContainer?,
        _ message: String = "",
        file: StaticString = #filePath,
        line: UInt = #line
) {
    if case .preKeySecureMessage = messageContainer {
    } else {
        XCTFail(message.isEmpty ? "Invalid type of message container" : message)
    }
}

func XCTAssertSecureMessage(
        _ messageContainer: MessageContainer?,
        _ message: String = "",
        file: StaticString = #filePath,
        line: UInt = #line
) {
    if case .secureMessage = messageContainer {
    } else {
        XCTFail(message.isEmpty ? "Invalid type of message container" : message)
    }
}

final class SessionTests: XCTestCase {
    func testInitializeSession() throws {
        let senderClient = try TestClient(userId: UUID())  // Alice
        let recipientClient = try TestClient(userId: UUID())  // Bob

        XCTAssertNoThrow(
                try initializeSession(
                        senderClient: senderClient,
                        recipientClient: recipientClient)
        )
    }

    func testInitializeSessionIdentityNotTrusted() throws {
        let senderClient = try TestClient(userId: UUID(), isClientIdentityTrusted: false)  // Alice
        let recipientClient = try TestClient(userId: UUID())  // Bob

        let recipientBundle = try self.setupKeysAndGetPreKeyBundle(for: recipientClient)

        do {
            let result = try Session.processPreKeyBundle(
                    recipientBundle,
                    for: recipientClient.protocolAddress,
                    sessionStore: senderClient.sessionStore,
                    identityStore: senderClient.identityKeyStore)
            XCTFail("Should be failed: \(result)")
        } catch DXError.untrustedIdentity {
            return
        } catch {
            XCTFail("Invalid error type: \(error)")
        }
    }

    func testInitializeSessionInvalidSignature() throws {
        let senderClient = try TestClient(userId: UUID())  // Alice

        let privateKey = PrivateKey()
        let publicKey = try privateKey.getAgreementPublicKey()
        let invalidSigningKey = publicKey
        let recipientClient = try TestClient(
                userId: UUID(),
                identityKeyPair: IdentityKeyPair(
                        publicKey: publicKey,
                        privateKey: privateKey,
                        signingPublicKey: invalidSigningKey)
        ) // Bob

        let recipientBundle = try self.setupKeysAndGetPreKeyBundle(for: recipientClient)

        do {
            let result = try Session.processPreKeyBundle(
                    recipientBundle,
                    for: recipientClient.protocolAddress,
                    sessionStore: senderClient.sessionStore,
                    identityStore: senderClient.identityKeyStore)
            XCTFail("Should be failed: \(result)")
        } catch DXError.invalidSignature {
            return
        } catch {
            XCTFail("Invalid error type: \(error)")
        }
    }

    func testInitializeSessionOptionalOneTimePreKey() throws {
        let senderClient = try TestClient(userId: UUID())  // Alice
        let recipientClient = try TestClient(userId: UUID())  // Bob
        let aliceAddress = senderClient.protocolAddress
        let bobAddress = recipientClient.protocolAddress

        // Generate identity information
        let bobIdentityKeyPair = try recipientClient.identityKeyStore.identityKeyPair()
        let bobRegistrationId = try recipientClient.identityKeyStore.localRegistrationId()

        // Generate signed pre key
        let bobSignedPreKeyPair = try SignedPreKeyPair(identityKeyPair: bobIdentityKeyPair)
        let bobSignedPreKeyPublic = SignedPreKeyPublic(signedPreKeyPair: bobSignedPreKeyPair)

        // Store signed pre key
        try recipientClient.signedPreKeyStore.storeSignedPreKey(
                bobSignedPreKeyPair,
                id: bobSignedPreKeyPair.id)

        let bobBundle = PreKeyBundle(
                identityKey: bobIdentityKeyPair.identityKey,
                signingKey: bobIdentityKeyPair.signingKey,
                registrationId: bobRegistrationId,
                deviceId: recipientClient.deviceId,
                signedPreKey: bobSignedPreKeyPublic,
                oneTimePreKey: nil)

        // Alice processes the bundle:
        try Session.processPreKeyBundle(
                bobBundle,
                for: bobAddress,
                sessionStore: senderClient.sessionStore,
                identityStore: senderClient.identityKeyStore)

        // Alice creates the first message (Pre Key message)
        let initialMessageData = try XCTUnwrap("Optional OneTime PreKey".data(using: .utf8))
        let aliceMessage = try Session.encrypt(
                data: initialMessageData,
                for: bobAddress,
                sessionStore: senderClient.sessionStore,
                identityStore: senderClient.identityKeyStore)

        // Bob decrypts the first message (Pre Key message) from Alice
        var result = try Session.decrypt(
                message: aliceMessage,
                from: aliceAddress,
                sessionStore: recipientClient.sessionStore,
                identityStore: recipientClient.identityKeyStore,
                preKeyStore: recipientClient.preKeyStore,
                signedPreKeyStore: recipientClient.signedPreKeyStore)
        XCTAssertEqual(result, initialMessageData)

        // Finally, Bob sends a message back to acknowledge the pre-key.
        let bobReplyData = try XCTUnwrap("Reply Optional OneTime PreKey".data(using: .utf8))
        let bobMessage = try Session.encrypt(
                data: bobReplyData,
                for: aliceAddress,
                sessionStore: recipientClient.sessionStore,
                identityStore: recipientClient.identityKeyStore)

        // Alice decrypts first message from Bob (with acknowledge of the pre-key)
        result = try Session.decrypt(
                message: bobMessage,
                from: bobAddress,
                sessionStore: senderClient.sessionStore,
                identityStore: senderClient.identityKeyStore,
                preKeyStore: senderClient.preKeyStore,
                signedPreKeyStore: senderClient.signedPreKeyStore)
        XCTAssertEqual(result, bobReplyData)
    }

    func testEncryptDecrypt() throws {
        let senderClient = try TestClient(userId: UUID())  // Alice
        let recipientClient = try TestClient(userId: UUID())  // Bob

        try initializeSession(senderClient: senderClient, recipientClient: recipientClient)

        // Second messages exchange

        // Alice sends the second message (may be after some time so load session from storage)
        let bobAddress = recipientClient.protocolAddress
        let secondMessageString = "Those who stands for nothing will fall for anything"
        let secondMessage = try Session.encrypt(
                data: try XCTUnwrap(secondMessageString.data(using: .utf8)),
                for: bobAddress,
                sessionStore: senderClient.sessionStore,
                identityStore: senderClient.identityKeyStore)

        // Bob decrypts the second message from Alice
        let decrypted = try Session.decrypt(
                message: secondMessage,
                from: senderClient.protocolAddress,
                sessionStore: recipientClient.sessionStore,
                identityStore: recipientClient.identityKeyStore,
                preKeyStore: recipientClient.preKeyStore,
                signedPreKeyStore: recipientClient.signedPreKeyStore)

        let decryptedMessageString = try XCTUnwrap(String(data: decrypted, encoding: .utf8))
        XCTAssertEqual(secondMessageString, decryptedMessageString)
    }
    // FIXME: - Need fix
    func testMultipleMessages() throws {
        let senderClient = try TestClient(userId: UUID())  // Alice
        let recipientClient = try TestClient(userId: UUID())  // Bob

        try initializeSession(senderClient: senderClient, recipientClient: recipientClient)

        // Actually test Multiple begins here

        // Alice sends the two messages in a row
        let bobAddress = recipientClient.protocolAddress
        let plaintext1 = "Those who stands for nothing will fall for anything"
        let cipherMessage1 = try Session.encrypt(
                data: try XCTUnwrap(plaintext1.data(using: .utf8)),
                for: bobAddress,
                sessionStore: senderClient.sessionStore,
                identityStore: senderClient.identityKeyStore)

        let plaintext2 = "Do not despair when your enemy attacks you."
        let cipherMessage2 = try Session.encrypt(
                data: try XCTUnwrap(plaintext2.data(using: .utf8)),
                for: bobAddress,
                sessionStore: senderClient.sessionStore,
                identityStore: senderClient.identityKeyStore)

        // Bob decrypts these messages from Alice
        let aliceAddress = senderClient.protocolAddress
        let decrypted1 = try Session.decrypt(
                message: cipherMessage1,
                from: aliceAddress,
                sessionStore: recipientClient.sessionStore,
                identityStore: recipientClient.identityKeyStore,
                preKeyStore: recipientClient.preKeyStore,
                signedPreKeyStore: recipientClient.signedPreKeyStore)

        let decrypted2 = try Session.decrypt(
                message: cipherMessage2,
                from: aliceAddress,
                sessionStore: recipientClient.sessionStore,
                identityStore: recipientClient.identityKeyStore,
                preKeyStore: recipientClient.preKeyStore,
                signedPreKeyStore: recipientClient.signedPreKeyStore)

        let decryptedText1 = try XCTUnwrap(String(data: decrypted1, encoding: .utf8))
        XCTAssertEqual(plaintext1, decryptedText1)

        let decryptedText2 = try XCTUnwrap(String(data: decrypted2, encoding: .utf8))
        XCTAssertEqual(plaintext2, decryptedText2)
    }

    func testThreadSafeSimultaneousDecrypt() async throws {
        let senderClient = try TestClient(userId: UUID())  // Alice
        let recipientClient = try TestClient(userId: UUID())  // Bob
        let bobAddress = recipientClient.protocolAddress
        let aliceAddress = senderClient.protocolAddress

        try initializeSession(senderClient: senderClient, recipientClient: recipientClient)
        
        // Alice creates a set of messages
        let aliceMessageCount = 50
        var aliceMessages: [(Data, MessageContainer)] = []
        for index in 0..<aliceMessageCount {
            let data = try XCTUnwrap("From Alice \(index)".data(using: .utf8))
            let message = try Session.encrypt(
                            data: data,
                            for: bobAddress,
                            sessionStore: senderClient.sessionStore,
                            identityStore: senderClient.identityKeyStore)
            let item = (data, message)
            aliceMessages.append(item)
        }
        aliceMessages.shuffle()

        var tasks = [Task<(Data, Data), Error>]()
        for aliceMessage in aliceMessages {
            let task = Task {
                let decryptedMessage = try Session.decrypt(
                    message: aliceMessage.1,
                    from: aliceAddress,
                    sessionStore: recipientClient.sessionStore,
                    identityStore: recipientClient.identityKeyStore,
                    preKeyStore: recipientClient.preKeyStore,
                    signedPreKeyStore: recipientClient.signedPreKeyStore)
                let expectedMessage = aliceMessage.0
                return (decryptedMessage, expectedMessage)
            }
            tasks.append(task)
        }
        
        var results = [(decrypted: Data, expected: Data)]()
        for task in tasks {
            let result = try await task.value
            results.append(result)
        }

        for result in results {
            XCTAssertEqual(result.decrypted, result.expected)
        }
    }

    func testThreadSafeSimultaneousEncrypt() async throws {
        let senderClient = try TestClient(userId: UUID())  // Alice
        let recipientClient = try TestClient(userId: UUID())  // Bob
        let bobAddress = recipientClient.protocolAddress
        
        try initializeSession(senderClient: senderClient, recipientClient: recipientClient)
        
        // Actually test for Thread Safe begins here
        
        
        var tasks = [Task<(MessageContainer, Data), Error>]()
        for index in 0..<5 {
            let task = Task {
                let plaintext = "Message \(index)"
                let data = try XCTUnwrap(plaintext.data(using: .utf8))
                let encrypted = try Session.encrypt(
                    data: data,
                    for: bobAddress,
                    sessionStore: senderClient.sessionStore,
                    identityStore: senderClient.identityKeyStore)
                return (encrypted, data)
            }
            tasks.append(task)
        }
        
        var encryptResults = [(encrypted: MessageContainer, expected: Data)]()
        for task in tasks {
            let result = try await task.value
            encryptResults.append(result)
        }
        
        for result in encryptResults {
            let decrypted = try Session.decrypt(
                message: result.encrypted,
                from: senderClient.protocolAddress,
                sessionStore: recipientClient.sessionStore,
                identityStore: recipientClient.identityKeyStore,
                preKeyStore: recipientClient.preKeyStore,
                signedPreKeyStore: recipientClient.signedPreKeyStore)

            XCTAssertEqual(decrypted, result.expected)
        }
    }

    // FIXME: - Need fix
    func testOutOfOrder() throws {
        let senderClient = try TestClient(userId: UUID())  // Alice
        let recipientClient = try TestClient(userId: UUID())  // Bob

        try initializeSession(senderClient: senderClient, recipientClient: recipientClient)

        // Actually test Out Of Order begins here

        // Alice sends the messages
        let bobAddress = recipientClient.protocolAddress
        let plaintext1 = "Those who stands for nothing will fall for anything"
        let cipherMessage1 = try Session.encrypt(
                data: try XCTUnwrap(plaintext1.data(using: .utf8)),
                for: bobAddress,
                sessionStore: senderClient.sessionStore,
                identityStore: senderClient.identityKeyStore)

        let plaintext2 = "Do not despair when your enemy attacks you."
        let cipherMessage2 = try Session.encrypt(
                data: try XCTUnwrap(plaintext2.data(using: .utf8)),
                for: bobAddress,
                sessionStore: senderClient.sessionStore,
                identityStore: senderClient.identityKeyStore)

        // Bob decrypts second message first
        let aliceAddress = senderClient.protocolAddress
        let decrypted2 = try Session.decrypt(
                message: cipherMessage2,
                from: aliceAddress,
                sessionStore: recipientClient.sessionStore,
                identityStore: recipientClient.identityKeyStore,
                preKeyStore: recipientClient.preKeyStore,
                signedPreKeyStore: recipientClient.signedPreKeyStore)

        let decrypted1 = try Session.decrypt(
                message: cipherMessage1,
                from: aliceAddress,
                sessionStore: recipientClient.sessionStore,
                identityStore: recipientClient.identityKeyStore,
                preKeyStore: recipientClient.preKeyStore,
                signedPreKeyStore: recipientClient.signedPreKeyStore)

        let decryptedText1 = try XCTUnwrap(String(data: decrypted1, encoding: .utf8))
        XCTAssertEqual(plaintext1, decryptedText1)

        let decryptedText2 = try XCTUnwrap(String(data: decrypted2, encoding: .utf8))
        XCTAssertEqual(plaintext2, decryptedText2)
    }
    // FIXME: - Need fix
    func testMessageKeyLimit() throws {
        let senderClient = try TestClient(userId: UUID())  // Alice
        let recipientClient = try TestClient(userId: UUID())  // Bob
        let bobAddress = recipientClient.protocolAddress
        let aliceAddress = senderClient.protocolAddress

        try initializeSession(senderClient: senderClient, recipientClient: recipientClient)

        // Alice encrypts enough messages to hit messages keys maximum
        var messages = [MessageContainer]()
        let count = DXProtocolConstants.messageKeyMaximum + 10
        for index in 0..<count {
            let alicePlaintext = try XCTUnwrap("Foo \(index)".data(using: .utf8))
            let aliceMessage = try Session.encrypt(
                    data: alicePlaintext,
                    for: bobAddress,
                    sessionStore: senderClient.sessionStore,
                    identityStore: senderClient.identityKeyStore)
            messages.append(aliceMessage)
        }

        // Bob decrypts some message
        let decrypted1000 = try Session.decrypt(
                message: messages[999],
                from: aliceAddress,
                sessionStore: recipientClient.sessionStore,
                identityStore: recipientClient.identityKeyStore,
                preKeyStore: recipientClient.preKeyStore,
                signedPreKeyStore: recipientClient.signedPreKeyStore)
        let expected1000 = try XCTUnwrap("Foo \(999)".data(using: .utf8))
        XCTAssertEqual(decrypted1000, expected1000)

        // Bob decrypts last message.
        // This will clear 'message keys' for messages with indexes lower then 'count - messageKeyMaximum'
        let decryptedLast = try Session.decrypt(
                message: messages[count - 1],
                from: aliceAddress,
                sessionStore: recipientClient.sessionStore,
                identityStore: recipientClient.identityKeyStore,
                preKeyStore: recipientClient.preKeyStore,
                signedPreKeyStore: recipientClient.signedPreKeyStore)
        let expectedLast = try XCTUnwrap("Foo \(count - 1)".data(using: .utf8))
        XCTAssertEqual(decryptedLast, expectedLast)

        // Try decrypting message 0, which should fail
        do {
            _ = try Session.decrypt(
                    message: messages[0],
                    from: aliceAddress,
                    sessionStore: recipientClient.sessionStore,
                    identityStore: recipientClient.identityKeyStore,
                    preKeyStore: recipientClient.preKeyStore,
                    signedPreKeyStore: recipientClient.signedPreKeyStore)
            XCTFail("Should not decrypt message")
        } catch DXError.duplicatedMessage {
        } catch {
            XCTFail("Decryption failed with invalid error")
        }
    }

    func testChainJumpOverLimit() throws {
        let senderClient = try TestClient(userId: UUID())  // Alice
        let recipientClient = try TestClient(userId: UUID())  // Bob
        let bobAddress = recipientClient.protocolAddress
        let aliceAddress = senderClient.protocolAddress

        try initializeSession(senderClient: senderClient, recipientClient: recipientClient)

        // Alice encrypts enough messages to go past our limit
        for index in 0..<DXProtocolConstants.futureMessagesLimit + 1 {
            _ = try Session.encrypt(
                    data: try XCTUnwrap("Foo \(index)".data(using: .utf8)),
                    for: bobAddress,
                    sessionStore: senderClient.sessionStore,
                    identityStore: senderClient.identityKeyStore)
        }

        let aliceTooFarMessage = try Session.encrypt(
                data: try XCTUnwrap("Foo".data(using: .utf8)),
                for: bobAddress,
                sessionStore: senderClient.sessionStore,
                identityStore: senderClient.identityKeyStore)

        do {
            // Bob decrypts too far message
            _ = try Session.decrypt(
                    message: aliceTooFarMessage,
                    from: aliceAddress,
                    sessionStore: recipientClient.sessionStore,
                    identityStore: recipientClient.identityKeyStore,
                    preKeyStore: recipientClient.preKeyStore,
                    signedPreKeyStore: recipientClient.signedPreKeyStore)
            XCTFail("Should not decrypt message")
        } catch DXError.invalidMessage {
        } catch {
            XCTFail("Could not decrypt message")
        }
    }

    func testArchiveSession() throws {
        let senderClient = try TestClient(userId: UUID())  // Alice
        let recipientClient = try TestClient(userId: UUID())  // Bob

        try initializeSession(senderClient: senderClient, recipientClient: recipientClient)

        // Bob's protocol address
        let address = recipientClient.protocolAddress

        // Alice loads a session with Bob
        var session = try XCTUnwrap(try senderClient.sessionStore.loadSession(for: address))
        XCTAssertTrue(session.hasCurrentState())
        XCTAssertEqual(session.previousSessionStates.count, 0)

        session.archiveCurrentState()
        XCTAssertFalse(session.hasCurrentState())
        XCTAssertEqual(session.previousSessionStates.count, 1)

        // An extra call to archive shouldn't break anything
        session.archiveCurrentState()
        XCTAssertFalse(session.hasCurrentState())
        XCTAssertEqual(session.previousSessionStates.count, 1)
    }
    // FIXME: - Need fix
    func testBasicSessionInteraction() throws {
        let senderClient = try TestClient(userId: UUID())  // Alice
        let recipientClient = try TestClient(userId: UUID())  // Bob

        try initializeSession(senderClient: senderClient, recipientClient: recipientClient)

        let aliceClient = senderClient
        let bobClient = recipientClient

        // Alice creates a set of messages
        let aliceMessageCount = 50
        var aliceMessages: [(Data, MessageContainer)] = []
        for index in 0..<aliceMessageCount {
            let data = try XCTUnwrap("From Alice \(index)".data(using: .utf8))
            let message = try Session.encrypt(
                            data: data,
                            for: bobClient.protocolAddress,
                            sessionStore: aliceClient.sessionStore,
                            identityStore: aliceClient.identityKeyStore)
            let item = (data, message)
            aliceMessages.append(item)
        }
        aliceMessages.shuffle()

        // Bob decrypts some messages from Alice
        for index in 0..<(aliceMessageCount / 2) {
            let aliceCipherMessage = aliceMessages[index].1
            let result = try Session.decrypt(
                    message: aliceCipherMessage,
                    from: aliceClient.protocolAddress,
                    sessionStore: bobClient.sessionStore,
                    identityStore: bobClient.identityKeyStore,
                    preKeyStore: bobClient.preKeyStore,
                    signedPreKeyStore: bobClient.signedPreKeyStore)

            let aliceOriginalMessage = aliceMessages[index].0
            XCTAssertEqual(result, aliceOriginalMessage)
        }

        // Bob creates a set of messages
        let bobMessageCount = 50
        var bobMessages: [(Data, MessageContainer)] = []
        for index in 0..<bobMessageCount {
            let data = try XCTUnwrap("From Bob \(index)".data(using: .utf8))
            let message = try Session.encrypt(
                            data: data,
                            for: aliceClient.protocolAddress,
                            sessionStore: bobClient.sessionStore,
                            identityStore: bobClient.identityKeyStore)
            let item = (data, message)
            bobMessages.append(item)
        }
        bobMessages.shuffle()

        // Alice decrypts some messages from Bob
        for index in 0..<(bobMessageCount / 2) {
            let bobCipherMessage = bobMessages[index].1
            let result = try Session.decrypt(
                    message: bobCipherMessage,
                    from: bobClient.protocolAddress,
                    sessionStore: aliceClient.sessionStore,
                    identityStore: aliceClient.identityKeyStore,
                    preKeyStore: aliceClient.preKeyStore,
                    signedPreKeyStore: aliceClient.signedPreKeyStore)

            let bobOriginalMessage = bobMessages[index].0
            XCTAssertEqual(result, bobOriginalMessage)
        }

        // Bob decrypts rest of messages from Alice
        for index in (aliceMessageCount / 2)..<aliceMessageCount {
            let aliceCipherMessage = aliceMessages[index].1
            let result = try Session.decrypt(
                    message: aliceCipherMessage,
                    from: aliceClient.protocolAddress,
                    sessionStore: bobClient.sessionStore,
                    identityStore: bobClient.identityKeyStore,
                    preKeyStore: bobClient.preKeyStore,
                    signedPreKeyStore: bobClient.signedPreKeyStore)

            let aliceOriginalMessage = aliceMessages[index].0
            XCTAssertEqual(result, aliceOriginalMessage)
        }

        // Alice decrypts rest of messages from Bob
        for index in (bobMessageCount / 2)..<bobMessageCount {
            let bobCipherMessage = bobMessages[index].1
            let result = try Session.decrypt(
                    message: bobCipherMessage,
                    from: bobClient.protocolAddress,
                    sessionStore: aliceClient.sessionStore,
                    identityStore: aliceClient.identityKeyStore,
                    preKeyStore: aliceClient.preKeyStore,
                    signedPreKeyStore: aliceClient.signedPreKeyStore)

            let bobOriginalMessage = bobMessages[index].0
            XCTAssertEqual(result, bobOriginalMessage)
        }
    }
    // FIXME: - Need fix
    func testBasicPreKeysUpdate() throws {
        let senderClient = try TestClient(userId: UUID())  // Alice
        let recipientClient = try TestClient(userId: UUID())  // Bob

        try initializeSession(senderClient: senderClient, recipientClient: recipientClient)

        let aliceClient = senderClient
        let bobClient = recipientClient

        let aliceMessageData = try XCTUnwrap("Foo".data(using: .utf8))
        let aliceMessage = try Session.encrypt(
                data: aliceMessageData,
                for: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore)
        XCTAssertSecureMessage(aliceMessage)

        // Bob decrypts the message from Alice
        var result = try Session.decrypt(
                message: try XCTUnwrap(aliceMessage),
                from: aliceClient.protocolAddress,
                sessionStore: bobClient.sessionStore,
                identityStore: bobClient.identityKeyStore,
                preKeyStore: bobClient.preKeyStore,
                signedPreKeyStore: bobClient.signedPreKeyStore)
        XCTAssertEqual(result, aliceMessageData)

        let bobMessageData = try XCTUnwrap("Bar".data(using: .utf8))
        let bobMessage = try Session.encrypt(
                data: bobMessageData,
                for: aliceClient.protocolAddress,
                sessionStore: bobClient.sessionStore,
                identityStore: bobClient.identityKeyStore)
        XCTAssertSecureMessage(bobMessage)

        // Alice decrypts the message from Bob
        result = try Session.decrypt(
                message: try XCTUnwrap(bobMessage),
                from: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore,
                preKeyStore: aliceClient.preKeyStore,
                signedPreKeyStore: aliceClient.signedPreKeyStore)
        XCTAssertEqual(result, bobMessageData)

        // Alice sends messages to Bob. And Bob receives all of them
        for index in 0..<10 {
            let data = try XCTUnwrap("Alice to Bob message \(index)".data(using: .utf8))
            let aliceMessage = try Session.encrypt(
                    data: data,
                    for: bobClient.protocolAddress,
                    sessionStore: aliceClient.sessionStore,
                    identityStore: aliceClient.identityKeyStore)
            XCTAssertSecureMessage(aliceMessage)

            // Bob decrypts the message from Alice
            let result = try Session.decrypt(
                    message: try XCTUnwrap(aliceMessage),
                    from: aliceClient.protocolAddress,
                    sessionStore: bobClient.sessionStore,
                    identityStore: bobClient.identityKeyStore,
                    preKeyStore: bobClient.preKeyStore,
                    signedPreKeyStore: bobClient.signedPreKeyStore)
            XCTAssertEqual(result, data)
        }

        // Bob sends messages to Alice. And Alice receives all of them
        for index in 0..<10 {
            let data = try XCTUnwrap("Bob to Alice message \(index)".data(using: .utf8))
            let bobMessage = try Session.encrypt(
                    data: data,
                    for: aliceClient.protocolAddress,
                    sessionStore: bobClient.sessionStore,
                    identityStore: bobClient.identityKeyStore)

            XCTAssertSecureMessage(bobMessage)

            // Alice decrypts the message from Bob
            let result = try Session.decrypt(
                    message: try XCTUnwrap(bobMessage),
                    from: bobClient.protocolAddress,
                    sessionStore: aliceClient.sessionStore,
                    identityStore: aliceClient.identityKeyStore,
                    preKeyStore: aliceClient.preKeyStore,
                    signedPreKeyStore: aliceClient.signedPreKeyStore)
            XCTAssertEqual(result, data)
        }

        // Alice sends a set of messages that are delayed for some reason. Bob does not receive them
        var aliceDelayedMessages: [(Data, MessageContainer)] = []
        for index in 0..<10 {
            let data = try XCTUnwrap("Alice to Bob delayed \(index)".data(using: .utf8))
            let message = try Session.encrypt(
                            data: data,
                            for: bobClient.protocolAddress,
                            sessionStore: aliceClient.sessionStore,
                            identityStore: aliceClient.identityKeyStore)
            let item = (data, message)
            aliceDelayedMessages.append(item)
        }

        // Alice sends post-delayed messages to Bob. And these messages are received by Bob
        for index in 0..<10 {
            let data = try XCTUnwrap("Alice to Bob post delayed \(index)".data(using: .utf8))
            let aliceMessage = try Session.encrypt(
                    data: data,
                    for: bobClient.protocolAddress,
                    sessionStore: aliceClient.sessionStore,
                    identityStore: aliceClient.identityKeyStore)

            XCTAssertSecureMessage(aliceMessage)

            // Bob decrypts the message from Alice
            let result = try Session.decrypt(
                    message: try XCTUnwrap(aliceMessage),
                    from: aliceClient.protocolAddress,
                    sessionStore: bobClient.sessionStore,
                    identityStore: bobClient.identityKeyStore,
                    preKeyStore: bobClient.preKeyStore,
                    signedPreKeyStore: bobClient.signedPreKeyStore)
            XCTAssertEqual(result, data)
        }

        // Bob sends post-delayed to Alice. And these messages are received by Bob
        for index in 0..<10 {
            let data = try XCTUnwrap("Alice to Bob post delayed \(index)".data(using: .utf8))
            let bobMessage = try Session.encrypt(
                    data: data,
                    for: aliceClient.protocolAddress,
                    sessionStore: bobClient.sessionStore,
                    identityStore: bobClient.identityKeyStore)

            XCTAssertSecureMessage(bobMessage)

            // Alice decrypts the message from Bob
            let result = try Session.decrypt(
                    message: try XCTUnwrap(bobMessage),
                    from: bobClient.protocolAddress,
                    sessionStore: aliceClient.sessionStore,
                    identityStore: aliceClient.identityKeyStore,
                    preKeyStore: aliceClient.preKeyStore,
                    signedPreKeyStore: aliceClient.signedPreKeyStore)
            XCTAssertEqual(result, data)
        }

        // Finally Bob receives delayed messages from Alice
        for index in 0..<aliceDelayedMessages.count {
            let aliceDelayedCipherMessage = aliceDelayedMessages[index].1
            let result = try Session.decrypt(
                    message: aliceDelayedCipherMessage,
                    from: aliceClient.protocolAddress,
                    sessionStore: bobClient.sessionStore,
                    identityStore: bobClient.identityKeyStore,
                    preKeyStore: bobClient.preKeyStore,
                    signedPreKeyStore: bobClient.signedPreKeyStore)

            let aliceDelayedOriginalMessage = aliceDelayedMessages[index].0
            XCTAssertEqual(result, aliceDelayedOriginalMessage)
        }

        // Actually PreKey test starts here
        // Bob updates his pre keys
        let bobPreKeyBundle = try self.setupKeysAndGetPreKeyBundle(for: bobClient)

        // Alice processes the Bob's updated bundle
        try Session.processPreKeyBundle(
                bobPreKeyBundle,
                for: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore)

        // Alice send a message to Bob after processing Bob's updated pre keys bundle
        let aliceMessageDataAfterBobPreKeysUpdate = try XCTUnwrap("Foo Bar".data(using: .utf8))
        let aliceMessageAfterBobPreKeysUpdate = try Session.encrypt(
                data: aliceMessageDataAfterBobPreKeysUpdate,
                for: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore)
        XCTAssertPreKeyMessage(aliceMessageAfterBobPreKeysUpdate)

        // Bob decrypts a message from Alice
        result = try Session.decrypt(
                message: try XCTUnwrap(aliceMessageAfterBobPreKeysUpdate),
                from: aliceClient.protocolAddress,
                sessionStore: bobClient.sessionStore,
                identityStore: bobClient.identityKeyStore,
                preKeyStore: bobClient.preKeyStore,
                signedPreKeyStore: bobClient.signedPreKeyStore)
        XCTAssertEqual(result, aliceMessageDataAfterBobPreKeysUpdate)
    }
    // FIXME: - Need fix
    func testRepeatBundleMessage() throws {
        let senderClient = try TestClient(userId: UUID())  // Alice
        let recipientClient = try TestClient(userId: UUID())  // Bob

        let aliceClient = senderClient
        let bobClient = recipientClient
        let bobPreKeyBundle = try setupKeysAndGetPreKeyBundle(for: bobClient)

        // Alice processes the Bob's bundle
        try Session.processPreKeyBundle(
                bobPreKeyBundle,
                for: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore)

        // Alice creates repeated messages for Bob
        let initialAliceMessageData = try XCTUnwrap("Foo Bar".data(using: .utf8))
        let alicePreKeyMessage1 = try Session.encrypt(
                data: initialAliceMessageData,
                for: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore)
        XCTAssertPreKeyMessage(alicePreKeyMessage1)

        let alicePreKeyMessage2 = try Session.encrypt(
                data: initialAliceMessageData,
                for: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore)
        XCTAssertPreKeyMessage(alicePreKeyMessage2)

        // Bob decrypts the first pre key message from Alice
        var result = try Session.decrypt(
                message: alicePreKeyMessage1,
                from: aliceClient.protocolAddress,
                sessionStore: bobClient.sessionStore,
                identityStore: bobClient.identityKeyStore,
                preKeyStore: bobClient.preKeyStore,
                signedPreKeyStore: bobClient.signedPreKeyStore)
        XCTAssertEqual(result, initialAliceMessageData)

        // Bob sends the first message to Alice
        let bobFirstMessageData = try XCTUnwrap("Bar Foo".data(using: .utf8))
        let bobFirstMessage = try Session.encrypt(
                data: bobFirstMessageData,
                for: aliceClient.protocolAddress,
                sessionStore: bobClient.sessionStore,
                identityStore: bobClient.identityKeyStore)
        XCTAssertSecureMessage(bobFirstMessage)

        // Alice decrypts the first message from Bob
        result = try Session.decrypt(
                message: bobFirstMessage,
                from: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore,
                preKeyStore: aliceClient.preKeyStore,
                signedPreKeyStore: aliceClient.signedPreKeyStore)
        XCTAssertEqual(result, bobFirstMessageData)

        // Actually the test. Bob decrypts the second pre key message from Alice
        result = try Session.decrypt(
                message: alicePreKeyMessage2,
                from: aliceClient.protocolAddress,
                sessionStore: bobClient.sessionStore,
                identityStore: bobClient.identityKeyStore,
                preKeyStore: bobClient.preKeyStore,
                signedPreKeyStore: bobClient.signedPreKeyStore)
        XCTAssertEqual(result, initialAliceMessageData)

        // Bob sends further message to Alice
        let bobFurtherMessageData = try XCTUnwrap("Bar Bar".data(using: .utf8))
        let bobFurtherMessage = try Session.encrypt(
                data: bobFurtherMessageData,
                for: aliceClient.protocolAddress,
                sessionStore: bobClient.sessionStore,
                identityStore: bobClient.identityKeyStore)
        XCTAssertSecureMessage(bobFurtherMessage)

        // Alice decrypts further message from Bob
        result = try Session.decrypt(
                message: bobFurtherMessage,
                from: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore,
                preKeyStore: aliceClient.preKeyStore,
                signedPreKeyStore: aliceClient.signedPreKeyStore)
        XCTAssertEqual(result, bobFurtherMessageData)
    }

    func testBasicSimultaneousInitiate() throws {
        let senderClient = try TestClient(userId: UUID())  // Alice
        let recipientClient = try TestClient(userId: UUID())  // Bob

        let aliceClient = senderClient
        let alicePreKeyBundle = try setupKeysAndGetPreKeyBundle(for: aliceClient)

        let bobClient = recipientClient
        let bobPreKeyBundle = try setupKeysAndGetPreKeyBundle(for: bobClient)

        // Alice processes the Bob's bundle
        try Session.processPreKeyBundle(
                bobPreKeyBundle,
                for: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore)

        // Bob processes the Alice's bundle
        try Session.processPreKeyBundle(
                alicePreKeyBundle,
                for: aliceClient.protocolAddress,
                sessionStore: bobClient.sessionStore,
                identityStore: bobClient.identityKeyStore)

        // Alice creates the first message for Bob
        let initialAliceMessageData = try XCTUnwrap("Foo Bob".data(using: .utf8))
        let alicePreKeyMessage = try Session.encrypt(
                data: initialAliceMessageData,
                for: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore)
        XCTAssertPreKeyMessage(alicePreKeyMessage)

        // Bob creates the first message for Alice
        let initialBobMessageData = try XCTUnwrap("Bar Alice".data(using: .utf8))
        let bobPreKeyMessage = try Session.encrypt(
                data: initialBobMessageData,
                for: aliceClient.protocolAddress,
                sessionStore: bobClient.sessionStore,
                identityStore: bobClient.identityKeyStore)
        XCTAssertPreKeyMessage(bobPreKeyMessage)

        // Base keys must be different at this point
        XCTAssertFalse(try self.isClientsSessionBaseKeyEqual(aliceClient, bobClient))

        // Alice decrypts the first message from Bob
        var result = try Session.decrypt(
                message: bobPreKeyMessage,
                from: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore,
                preKeyStore: aliceClient.preKeyStore,
                signedPreKeyStore: aliceClient.signedPreKeyStore)
        XCTAssertEqual(result, initialBobMessageData)

        // Bob decrypts the first message from Alice
        result = try Session.decrypt(
                message: alicePreKeyMessage,
                from: aliceClient.protocolAddress,
                sessionStore: bobClient.sessionStore,
                identityStore: bobClient.identityKeyStore,
                preKeyStore: bobClient.preKeyStore,
                signedPreKeyStore: bobClient.signedPreKeyStore)
        XCTAssertEqual(result, initialAliceMessageData)

        // Base keys must be different at this point
        XCTAssertFalse(try self.isClientsSessionBaseKeyEqual(aliceClient, bobClient))

        // Alice sends further message to Bob
        let aliceFurtherMessageData = try XCTUnwrap("Bar Bar".data(using: .utf8))
        let aliceFurtherMessage = try Session.encrypt(
                data: aliceFurtherMessageData,
                for: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore)
        XCTAssertSecureMessage(aliceFurtherMessage)

        // Bob decrypts further message from Alice
        result = try Session.decrypt(
                message: aliceFurtherMessage,
                from: aliceClient.protocolAddress,
                sessionStore: bobClient.sessionStore,
                identityStore: bobClient.identityKeyStore,
                preKeyStore: bobClient.preKeyStore,
                signedPreKeyStore: bobClient.signedPreKeyStore)
        XCTAssertEqual(result, aliceFurtherMessageData)

        XCTAssertTrue(try self.isClientsSessionBaseKeyEqual(aliceClient, bobClient))

        // Bob sends further message to Alice
        let bobFurtherMessageData = try XCTUnwrap("Foo Foo".data(using: .utf8))
        let bobFurtherMessage = try Session.encrypt(
                data: bobFurtherMessageData,
                for: aliceClient.protocolAddress,
                sessionStore: bobClient.sessionStore,
                identityStore: bobClient.identityKeyStore)
        XCTAssertSecureMessage(bobFurtherMessage)

        // Alice decrypts further message from Bob
        result = try Session.decrypt(
                message: bobFurtherMessage,
                from: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore,
                preKeyStore: aliceClient.preKeyStore,
                signedPreKeyStore: aliceClient.signedPreKeyStore)
        XCTAssertEqual(result, bobFurtherMessageData)

        XCTAssertTrue(try self.isClientsSessionBaseKeyEqual(aliceClient, bobClient))
    }
    // FIXME: - Need fix
    func testSimultaneousInitiateLostPreKeyMessage() throws {
        let senderClient = try TestClient(userId: UUID())  // Alice
        let recipientClient = try TestClient(userId: UUID())  // Bob

        let aliceClient = senderClient
        let alicePreKeyBundle = try setupKeysAndGetPreKeyBundle(for: aliceClient)

        let bobClient = recipientClient
        let bobPreKeyBundle = try setupKeysAndGetPreKeyBundle(for: bobClient)

        // Alice processes the Bob's bundle
        try Session.processPreKeyBundle(
                bobPreKeyBundle,
                for: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore)

        // Bob processes the Alice's bundle
        try Session.processPreKeyBundle(
                alicePreKeyBundle,
                for: aliceClient.protocolAddress,
                sessionStore: bobClient.sessionStore,
                identityStore: bobClient.identityKeyStore)

        // Alice creates the first message for Bob
        let initialAliceMessageData = try XCTUnwrap("Foo Bob".data(using: .utf8))
        let alicePreKeyMessage = try Session.encrypt(
                data: initialAliceMessageData,
                for: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore)
        XCTAssertPreKeyMessage(alicePreKeyMessage)

        // Bob creates the first message for Alice
        // But this pre key message was lost for some reason (i.e. Alice did not receive it)
        let bobPreKeyMessage = try Session.encrypt(
                data: try XCTUnwrap("Bar Alice".data(using: .utf8)),
                for: aliceClient.protocolAddress,
                sessionStore: bobClient.sessionStore,
                identityStore: bobClient.identityKeyStore)
        XCTAssertPreKeyMessage(bobPreKeyMessage)

        XCTAssertFalse(try self.isClientsSessionBaseKeyEqual(aliceClient, bobClient))

        // Bob decrypts the first message from Alice
        var result = try Session.decrypt(
                message: alicePreKeyMessage,
                from: aliceClient.protocolAddress,
                sessionStore: bobClient.sessionStore,
                identityStore: bobClient.identityKeyStore,
                preKeyStore: bobClient.preKeyStore,
                signedPreKeyStore: bobClient.signedPreKeyStore)
        XCTAssertEqual(result, initialAliceMessageData)

        // Alice sends further message to Bob
        let aliceFurtherMessageData = try XCTUnwrap("Bar Bar".data(using: .utf8))
        let aliceFurtherMessage = try Session.encrypt(
                data: aliceFurtherMessageData,
                for: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore)
        XCTAssertPreKeyMessage(aliceFurtherMessage)

        // Bob decrypts further message from Alice
        result = try Session.decrypt(
                message: aliceFurtherMessage,
                from: aliceClient.protocolAddress,
                sessionStore: bobClient.sessionStore,
                identityStore: bobClient.identityKeyStore,
                preKeyStore: bobClient.preKeyStore,
                signedPreKeyStore: bobClient.signedPreKeyStore)
        XCTAssertEqual(result, aliceFurtherMessageData)

        XCTAssertTrue(try self.isClientsSessionBaseKeyEqual(aliceClient, bobClient))

        // Bob sends further message to Alice
        let bobFurtherMessageData = try XCTUnwrap("Foo Foo".data(using: .utf8))
        let bobFurtherMessage = try Session.encrypt(
                data: bobFurtherMessageData,
                for: aliceClient.protocolAddress,
                sessionStore: bobClient.sessionStore,
                identityStore: bobClient.identityKeyStore)
        XCTAssertSecureMessage(bobFurtherMessage)

        // Alice decrypts further message from Bob
        result = try Session.decrypt(
                message: bobFurtherMessage,
                from: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore,
                preKeyStore: aliceClient.preKeyStore,
                signedPreKeyStore: aliceClient.signedPreKeyStore)
        XCTAssertEqual(result, bobFurtherMessageData)

        XCTAssertTrue(try self.isClientsSessionBaseKeyEqual(aliceClient, bobClient))
    }

    func testSimultaneousInitiateLostSecureMessage() throws {
        let senderClient = try TestClient(userId: UUID())  // Alice
        let recipientClient = try TestClient(userId: UUID())  // Bob

        let aliceClient = senderClient
        let alicePreKeyBundle = try setupKeysAndGetPreKeyBundle(for: aliceClient)

        let bobClient = recipientClient
        let bobPreKeyBundle = try setupKeysAndGetPreKeyBundle(for: bobClient)

        // Alice processes the Bob's bundle
        try Session.processPreKeyBundle(
                bobPreKeyBundle,
                for: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore)

        // Bob processes the Alice's bundle
        try Session.processPreKeyBundle(
                alicePreKeyBundle,
                for: aliceClient.protocolAddress,
                sessionStore: bobClient.sessionStore,
                identityStore: bobClient.identityKeyStore)

        // Alice creates the first message for Bob
        let initialAliceMessageData = try XCTUnwrap("Bob first Msg".data(using: .utf8))
        let alicePreKeyMessage = try Session.encrypt(
                data: initialAliceMessageData,
                for: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore)
        XCTAssertPreKeyMessage(alicePreKeyMessage)

        // Bob creates the first message for Alice
        let initialBobMessageData = try XCTUnwrap("Alice first Msg".data(using: .utf8))
        let bobPreKeyMessage = try Session.encrypt(
                data: initialBobMessageData,
                for: aliceClient.protocolAddress,
                sessionStore: bobClient.sessionStore,
                identityStore: bobClient.identityKeyStore)
        XCTAssertPreKeyMessage(bobPreKeyMessage)

        // Base keys must be different at this point
        XCTAssertFalse(try self.isClientsSessionBaseKeyEqual(aliceClient, bobClient))

        // Alice decrypts the first message from Bob
        var result = try Session.decrypt(
                message: bobPreKeyMessage,
                from: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore,
                preKeyStore: aliceClient.preKeyStore,
                signedPreKeyStore: aliceClient.signedPreKeyStore)
        XCTAssertEqual(result, initialBobMessageData)

        // Bob decrypts the first message from Alice
        result = try Session.decrypt(
                message: alicePreKeyMessage,
                from: aliceClient.protocolAddress,
                sessionStore: bobClient.sessionStore,
                identityStore: bobClient.identityKeyStore,
                preKeyStore: bobClient.preKeyStore,
                signedPreKeyStore: bobClient.signedPreKeyStore)
        XCTAssertEqual(result, initialAliceMessageData)

        // Base keys must be different at this point
        XCTAssertFalse(try self.isClientsSessionBaseKeyEqual(aliceClient, bobClient))

        // Alice encrypts further message to Bob
        // But this secure message was lost for some reason (i.e. Bob did not receive/decrypt it)
        let aliceFurtherMessageData = try XCTUnwrap("Bar Bar".data(using: .utf8))
        let aliceFurtherMessage = try Session.encrypt(
                data: aliceFurtherMessageData,
                for: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore)
        XCTAssertSecureMessage(aliceFurtherMessage)

        // Bob sends further message to Alice
        let bobFurtherMessageData = try XCTUnwrap("Foo Foo".data(using: .utf8))
        let bobFurtherMessage = try Session.encrypt(
                data: bobFurtherMessageData,
                for: aliceClient.protocolAddress,
                sessionStore: bobClient.sessionStore,
                identityStore: bobClient.identityKeyStore)
        XCTAssertSecureMessage(bobFurtherMessage)

        // Alice decrypts further message from Bob
        result = try Session.decrypt(
                message: bobFurtherMessage,
                from: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore,
                preKeyStore: aliceClient.preKeyStore,
                signedPreKeyStore: aliceClient.signedPreKeyStore)
        XCTAssertEqual(result, bobFurtherMessageData)

        XCTAssertTrue(try self.isClientsSessionBaseKeyEqual(aliceClient, bobClient))
    }

    func testSimultaneousInitiateRepeatedMessages() throws {
        let aliceClient = try TestClient(userId: UUID())
        let bobClient = try TestClient(userId: UUID())
        XCTAssertNoThrow(
                try testSimultaneousInitiateRepeatedMessages(aliceClient: aliceClient, bobClient: bobClient))
    }

    func testSimultaneousInitiateWithLostPreKeyMessageAndRepeatedMessages() throws {
        let senderClient = try TestClient(userId: UUID())  // Alice
        let recipientClient = try TestClient(userId: UUID())  // Bob

        let aliceClient = senderClient
        let bobClient = recipientClient

        let bobPreKeyBundle = try setupKeysAndGetPreKeyBundle(for: bobClient)

        // Alice processes the Bob's bundle
        try Session.processPreKeyBundle(
                bobPreKeyBundle,
                for: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore)

        // Alice creates the message for Bob
        let lostMessageForBob = try Session.encrypt(
                data: try XCTUnwrap("Lost message for Bob".data(using: .utf8)),
                for: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore)
        XCTAssertPreKeyMessage(lostMessageForBob)

        XCTAssertNoThrow(
                try testSimultaneousInitiateRepeatedMessages(aliceClient: aliceClient, bobClient: bobClient))
    }

    func testSimultaneousInitiateRepeatedMessages(aliceClient: TestClient, bobClient: TestClient) throws {
        for index in 0..<15 {
            let alicePreKeyBundle = try setupKeysAndGetPreKeyBundle(for: aliceClient)
            let bobPreKeyBundle = try setupKeysAndGetPreKeyBundle(for: bobClient)

            // Alice processes the Bob's bundle
            try Session.processPreKeyBundle(
                    bobPreKeyBundle,
                    for: bobClient.protocolAddress,
                    sessionStore: aliceClient.sessionStore,
                    identityStore: aliceClient.identityKeyStore)

            // Bob processes the Alice's bundle
            try Session.processPreKeyBundle(
                    alicePreKeyBundle,
                    for: aliceClient.protocolAddress,
                    sessionStore: bobClient.sessionStore,
                    identityStore: bobClient.identityKeyStore)

            // Alice creates the message for Bob
            let aliceMessageData = try XCTUnwrap("Hi Bob \(index)".data(using: .utf8))
            let alicePreKeyMessage = try Session.encrypt(
                    data: aliceMessageData,
                    for: bobClient.protocolAddress,
                    sessionStore: aliceClient.sessionStore,
                    identityStore: aliceClient.identityKeyStore)
            XCTAssertPreKeyMessage(alicePreKeyMessage)

            // Bob creates the message for Alice
            let bobMessageData = try XCTUnwrap("Hi Alice \(index)".data(using: .utf8))
            let bobPreKeyMessage = try Session.encrypt(
                    data: bobMessageData,
                    for: aliceClient.protocolAddress,
                    sessionStore: bobClient.sessionStore,
                    identityStore: bobClient.identityKeyStore)
            XCTAssertPreKeyMessage(bobPreKeyMessage)

            XCTAssertFalse(try self.isClientsSessionBaseKeyEqual(aliceClient, bobClient))

            // Alice decrypts the message from Bob
            var result = try Session.decrypt(
                    message: bobPreKeyMessage,
                    from: bobClient.protocolAddress,
                    sessionStore: aliceClient.sessionStore,
                    identityStore: aliceClient.identityKeyStore,
                    preKeyStore: aliceClient.preKeyStore,
                    signedPreKeyStore: aliceClient.signedPreKeyStore)
            XCTAssertEqual(result, bobMessageData)

            // Bob decrypts the message from Alice
            result = try Session.decrypt(
                    message: alicePreKeyMessage,
                    from: aliceClient.protocolAddress,
                    sessionStore: bobClient.sessionStore,
                    identityStore: bobClient.identityKeyStore,
                    preKeyStore: bobClient.preKeyStore,
                    signedPreKeyStore: bobClient.signedPreKeyStore)
            XCTAssertEqual(result, aliceMessageData)

            XCTAssertFalse(try self.isClientsSessionBaseKeyEqual(aliceClient, bobClient))
        }

        for index in 0..<50 {
            // Alice creates the further messages for Bob
            let aliceMessageData = try XCTUnwrap("Foo Bob \(index)".data(using: .utf8))
            let aliceSecureMessage = try Session.encrypt(
                    data: aliceMessageData,
                    for: bobClient.protocolAddress,
                    sessionStore: aliceClient.sessionStore,
                    identityStore: aliceClient.identityKeyStore)
            XCTAssertSecureMessage(aliceSecureMessage)

            // Bob creates the further messages for Alice
            let bobMessageData = try XCTUnwrap("Bar Alice \(index)".data(using: .utf8))
            let bobSecureMessage = try Session.encrypt(
                    data: bobMessageData,
                    for: aliceClient.protocolAddress,
                    sessionStore: bobClient.sessionStore,
                    identityStore: bobClient.identityKeyStore)
            XCTAssertSecureMessage(bobSecureMessage)

            XCTAssertFalse(try self.isClientsSessionBaseKeyEqual(aliceClient, bobClient))

            // Alice decrypts further message from Bob
            var result = try Session.decrypt(
                    message: bobSecureMessage,
                    from: bobClient.protocolAddress,
                    sessionStore: aliceClient.sessionStore,
                    identityStore: aliceClient.identityKeyStore,
                    preKeyStore: aliceClient.preKeyStore,
                    signedPreKeyStore: aliceClient.signedPreKeyStore)
            XCTAssertEqual(result, bobMessageData)

            // Bob decrypts further message from Alice
            result = try Session.decrypt(
                    message: aliceSecureMessage,
                    from: aliceClient.protocolAddress,
                    sessionStore: bobClient.sessionStore,
                    identityStore: bobClient.identityKeyStore,
                    preKeyStore: bobClient.preKeyStore,
                    signedPreKeyStore: bobClient.signedPreKeyStore)
            XCTAssertEqual(result, aliceMessageData)

            XCTAssertFalse(try self.isClientsSessionBaseKeyEqual(aliceClient, bobClient))
        }

        let aliceMessageData = try XCTUnwrap("Foo Bar".data(using: .utf8))
        let aliceSecureMessage = try Session.encrypt(
                data: aliceMessageData,
                for: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore)
        XCTAssertSecureMessage(aliceSecureMessage)
        XCTAssertFalse(try self.isClientsSessionBaseKeyEqual(aliceClient, bobClient))

        let bobMessageData = try XCTUnwrap("Bar Foo".data(using: .utf8))
        let bobSecureMessage = try Session.encrypt(
                data: bobMessageData,
                for: aliceClient.protocolAddress,
                sessionStore: bobClient.sessionStore,
                identityStore: bobClient.identityKeyStore)
        XCTAssertSecureMessage(bobSecureMessage)

        let result = try Session.decrypt(
                message: bobSecureMessage,
                from: bobClient.protocolAddress,
                sessionStore: aliceClient.sessionStore,
                identityStore: aliceClient.identityKeyStore,
                preKeyStore: aliceClient.preKeyStore,
                signedPreKeyStore: aliceClient.signedPreKeyStore)
        XCTAssertEqual(result, bobMessageData)

        XCTAssertTrue(try self.isClientsSessionBaseKeyEqual(aliceClient, bobClient))
    }

    func testSessionEquatable() throws {
        let userId = UUID()
        let bobClient = try TestClient(userId: userId)
        let bob1Bundle = try self.setupKeysAndGetPreKeyBundle(for: bobClient)
        let session = try Session.processPreKeyBundle(
                bob1Bundle,
                for: bobClient.protocolAddress,
                sessionStore: bobClient.sessionStore,
                identityStore: bobClient.identityKeyStore
        )
        let bobAddress = bobClient.protocolAddress
        let loadSession = try bobClient.sessionStore.loadSession(for: bobAddress)
        XCTAssertEqual(loadSession, session)
    }
    
    func testEncryptWhenSessionNotExists() throws {
        let senderClient = try TestClient(userId: UUID())  // Alice
        let recipientClient = try TestClient(userId: UUID())  // Bob
        let invalidAddress = ProtocolAddress(userId: UUID(), deviceId: UUID())
        try initializeSession(senderClient: senderClient, recipientClient: recipientClient)

        do {
            let text = "Foo"
            let message = try Session.encrypt(
                data: try XCTUnwrap(text.data(using: .utf8)),
                for: invalidAddress,
                sessionStore: senderClient.sessionStore,
                identityStore: senderClient.identityKeyStore)
            XCTFail("Encrypt should fail: \(message)")
        } catch DXError.sessionNotFound {
            return
        } catch {
            XCTFail("Invalid error type: \(error)")
        }
    }
    
    func testDecryptWhenSessionNotExists() throws {
        let senderClient = try TestClient(userId: UUID())  // Alice
        let recipientClient = try TestClient(userId: UUID())  // Bob
        let invalidAddress = ProtocolAddress(userId: UUID(), deviceId: UUID())
        try initializeSession(senderClient: senderClient, recipientClient: recipientClient)

        let text = "Foo"
        let encryptedMessage = try Session.encrypt(
            data: try XCTUnwrap(text.data(using: .utf8)),
            for: recipientClient.protocolAddress,
            sessionStore: senderClient.sessionStore,
            identityStore: senderClient.identityKeyStore)

        do {
            let decryptedMessage = try Session.decrypt(
                    message: encryptedMessage,
                    from: invalidAddress,
                    sessionStore: recipientClient.sessionStore,
                    identityStore: recipientClient.identityKeyStore,
                    preKeyStore: recipientClient.preKeyStore,
                    signedPreKeyStore: recipientClient.signedPreKeyStore)
            XCTFail("Decrypt should fail: \(decryptedMessage)")
        } catch DXError.sessionNotFound {
            return
        } catch {
            XCTFail("Invalid error type: \(error)")
        }
    }
}

extension SessionTests {
    // MARK: - Utilities

    func isClientsSessionBaseKeyEqual(_ aliceClient: TestClient, _ bobClient: TestClient) throws -> Bool {
        let aliceSession = try XCTUnwrap(
                try aliceClient.sessionStore.loadSession(for: bobClient.protocolAddress))
        let bobSession = try XCTUnwrap(
                try bobClient.sessionStore.loadSession(for: aliceClient.protocolAddress))

        return aliceSession.state.aliceBaseKey == bobSession.state.aliceBaseKey
    }

    func setupKeysAndGetPreKeyBundle(for client: TestClient, isValidSignature: Bool = true) throws -> PreKeyBundle {
        // Generate identity information
        if isValidSignature { }
        let identityKeyPair = try client.identityKeyStore.identityKeyPair()
        let registrationId = try client.identityKeyStore.localRegistrationId()

        // Generate one-time pre key
        let oneTimePreKeyPair = try OneTimePreKeyPair()
        let oneTimePreKeyPublic = OneTimePreKeyPublic(oneTimePreKeyPair: oneTimePreKeyPair)

        // Store one-time pre key
        try client.preKeyStore.storePreKey(oneTimePreKeyPair, id: oneTimePreKeyPair.id)

        // Generate signed pre key
        let signedPreKeyPair = try SignedPreKeyPair(identityKeyPair: identityKeyPair)
        let signedPreKeyPublic = SignedPreKeyPublic(signedPreKeyPair: signedPreKeyPair)

        // Store signed pre key
        try client.signedPreKeyStore.storeSignedPreKey(signedPreKeyPair, id: signedPreKeyPair.id)

        let bundle = PreKeyBundle(
                identityKey: identityKeyPair.identityKey,
                signingKey: identityKeyPair.signingKey,
                registrationId: registrationId,
                deviceId: client.deviceId,
                signedPreKey: signedPreKeyPublic,
                oneTimePreKey: oneTimePreKeyPublic)
        return bundle
    }

    func initializeSession(senderClient: TestClient, recipientClient: TestClient) throws {
        let recipientBundle = try self.setupKeysAndGetPreKeyBundle(for: recipientClient)
        let aliceAddress = senderClient.protocolAddress
        let bobAddress = recipientClient.protocolAddress

        // Alice processes the bundle:
        try Session.processPreKeyBundle(
                recipientBundle,
                for: bobAddress,
                sessionStore: senderClient.sessionStore,
                identityStore: senderClient.identityKeyStore)

        // Alice creates the first message (Pre Key message)
        let initialMessageData = try XCTUnwrap("Bar".data(using: .utf8))
        let aliceMessage = try Session.encrypt(
                data: initialMessageData,
                for: bobAddress,
                sessionStore: senderClient.sessionStore,
                identityStore: senderClient.identityKeyStore)

        // Bob decrypts the first message (Pre Key message) from Alice
        var result = try Session.decrypt(
                message: aliceMessage,
                from: aliceAddress,
                sessionStore: recipientClient.sessionStore,
                identityStore: recipientClient.identityKeyStore,
                preKeyStore: recipientClient.preKeyStore,
                signedPreKeyStore: recipientClient.signedPreKeyStore)
        XCTAssertEqual(result, initialMessageData)

        // Finally, Bob sends a message back to acknowledge the pre-key.
        let bobReplyData = try XCTUnwrap("Foo".data(using: .utf8))
        let bobMessage = try Session.encrypt(
                data: bobReplyData,
                for: aliceAddress,
                sessionStore: recipientClient.sessionStore,
                identityStore: recipientClient.identityKeyStore)

        // Alice decrypts first message from Bob (with acknowledge of the pre-key)
        result = try Session.decrypt(
                message: bobMessage,
                from: bobAddress,
                sessionStore: senderClient.sessionStore,
                identityStore: senderClient.identityKeyStore,
                preKeyStore: senderClient.preKeyStore,
                signedPreKeyStore: senderClient.signedPreKeyStore)
        XCTAssertEqual(result, bobReplyData)
    }
}
// swiftlint:enable type_body_length
// swiftlint:enable function_body_length
// swiftlint:enable file_length
