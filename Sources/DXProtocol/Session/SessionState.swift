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
//  SessionState.swift
//  DealogX
//
//  Created by Andriy Vasyk on 08.12.2022.
//

import Foundation

// swiftlint: disable file_length
/// A session's state contains all necessary data needed for encryption/decryption of messages in conversation
struct SessionState: Codable {
    /// The current version of message structure
    let sessionVersion = DXProtocolConstants.cipertextMessageCurrentVersion

    /// The identity key of the local user
    let ourLocalIdentityPublic: IdentityKeyPublic

    /// The identity key of the remote user
    let theirRemoteIdentityPublic: IdentityKeyPublic

    /// The root key of this state
    var rootKey: RatchetRootKey

    /// The last counter in the previous sender chain
    var previousCounter: UInt32

    /// The chain used for encryption of outgoing messages. The sender chain of this state
    var senderChain: SenderChain

    /// The chains used for decryption of incoming messages. The receiver chains of the state.
    var receiverChains: [ReceiverChain]

    /// An info about pending Pre Key. See more in `PendingPreKey`
    var pendingPreKey: PendingPreKey?

    /// Registration identifier of remote user
    var remoteRegistrationId: UUID?

    /// Registration identifier of local user
    var localRegistrationId: UUID?

    /// The base key which is calculated by Alice during processing of Bob's pre key bundle
    var aliceBaseKey: PublicKey

    /// Indicates that this state of the session has been archived
    var archived = false

    /// The coding keys for encoding and decoding a `Session`.
    enum CodingKeys: String, CodingKey {
        /// The session version
        case sessionVersion

        /// The local identity public key
        case ourLocalIdentityPublic

        /// The remote identity public key
        case theirRemoteIdentityPublic

        /// The root key
        case rootKey

        /// The previous counter
        case previousCounter

        /// The sender chain
        case senderChain

        /// The receiver chains
        case receiverChains

        /// The pending pre-key
        case pendingPreKey

        /// The remote registration ID
        case remoteRegistrationId

        /// The local registration ID
        case localRegistrationId

        /// The Alice base key
        case aliceBaseKey

        /// Whether the session is archived
        case archived
    }

    // MARK: - Interface

    /// Sets the information about an unacknowledged pre-key message.
    ///
    /// This method is called when a pre-key message is received from the remote user. 
    /// The method stores the information about the pre-key message so that it can be acknowledged later.
    ///
    /// - Parameters:
    ///     - oneTimePreKeyId: The ID of the one-time pre-key that was used to encrypt the message.
    ///     - signedPreKeyId: The ID of the signed pre-key that was used to create the pre-key.
    ///     - baseKey: The base key of the pre-key.
    mutating func setUnacknowledgedPreKeyMessageInfo(
            oneTimePreKeyId: UUID?,
            signedPreKeyId: UUID,
            baseKey: PublicKey
    ) {
        self.pendingPreKey = PendingPreKey(
                oneTimePreKeyId: oneTimePreKeyId,
                signedPreKeyId: signedPreKeyId,
                baseKeyPublic: baseKey)
    }

    /// Returns the information about an unacknowledged pre-key message.
    ///
    /// This method returns the information about 
    /// the last pre-key message that was received from the remote user but not yet acknowledged.
    ///
    /// - Returns: The information about the pre-key message, 
    /// or nil if there is no unacknowledged pre-key message.
    func unacknowledgedPreKeyMessageInfo() -> PendingPreKey? {
        return self.pendingPreKey
    }

    /// Clears the information about an unacknowledged pre-key message.
    ///
    /// This method clears the information about 
    /// the last pre-key message that was received from the remote user but not yet acknowledged.
    mutating func clearUnacknowledgedPreKeyMessageInfo() {
        self.pendingPreKey = nil
    }

    // MARK: - Encrypt

    /// Encrypts data and returns a message container.
    ///
    /// This method encrypts the data using the ratchet keys for the session.
    ///
    /// - Parameters:
    ///     - data: The data to encrypt.
    ///     - sessionStore: The session store.
    ///     - identityStore: The identity store.
    ///
    /// - Returns: The encrypted message container.
    mutating func encrypt(
            data: Data,
            sessionStore: SessionStorable,
            identityStore: IdentityKeyStorable
    ) throws -> MessageContainer {
        let senderChainKey = self.senderChain.chainKey
        let messageKeys = try senderChainKey.messageKeys()
        let senderEphemeralKey = self.senderChain.ratchetKeyPair.publicKey

        // Source - https://developer.apple.com/forums/thread/687212
        var bytes: [UInt8] = []
        data.withUnsafeBytes { bytes.append(contentsOf: $0) }
        let key = [UInt8](messageKeys.cipherKey)
        let initializationVector = [UInt8](messageKeys.initializationVector)
        let encrypted = try CryptoService.shared.QCCAESPadCBCEncrypt(
                key: key,
                initializationVector: initializationVector,
                plaintext: bytes)

        let message = try SecureMessage(
                messageVersion: self.sessionVersion,
                macKey: messageKeys.macKey,
                senderRatchetKey: senderEphemeralKey,
                counter: senderChainKey.index,
                previousCounter: self.previousCounter,
                encrypted: Data(encrypted),
                senderIdentityKey: self.ourLocalIdentityPublic,
                receiverIdentityKey: self.theirRemoteIdentityPublic)

        let result: MessageContainer
        if let pendingPreKey = self.unacknowledgedPreKeyMessageInfo() {
            let senderIdentityKey = self.ourLocalIdentityPublic
            let preKey = try PreKeySecureMessage(
                    messageVersion: self.sessionVersion,
                    registrationId: self.localRegistrationId,
                    oneTimePreKeyId: pendingPreKey.oneTimePreKeyId,
                    signedPreKeyId: pendingPreKey.signedPreKeyId,
                    senderBaseKey: pendingPreKey.baseKeyPublic,
                    senderIdentityKey: senderIdentityKey,
                    secureMessage: message)
            result = .preKeySecureMessage(preKey)
        } else {
            result = .secureMessage(message)
        }

        self.senderChain.chainKey = senderChainKey.nextChainKey()

        return result
    }

    // MARK: - Decrypt

    /// Decrypts a message and returns the data.
    ///
    /// This method decrypts the message using the ratchet keys for the session.
    ///
    /// - Parameters:
    ///     - message: The message to decrypt.
    ///
    /// - Returns: The decrypted data.
    mutating func decryptMessage(_ message: SecureMessage) throws -> Data {
        guard message.messageVersion == self.sessionVersion else {
            throw DXError.unrecognizedMessageVersion("\(message.messageVersion)")
        }

        let theirEphemeralKey = message.senderRatchetKey
        let receiverChainKey = try self.getOrCreateReceiverChainKey(theirEphemeral: theirEphemeralKey)
        let messageKeys = try self.getOrCreateMessageKeys(
                theirEphemeralKey: theirEphemeralKey,
                chainKey: receiverChainKey,
                counter: message.counter)

        let theirIdentityKey = self.theirRemoteIdentityPublic
        let localIdentityKey = self.ourLocalIdentityPublic

        let isMacValid = try message.verifyMac(
                senderIdentityKey: theirIdentityKey,
                receiverIdentityKey: localIdentityKey,
                macKey: messageKeys.macKey)
        guard isMacValid else {
            throw DXError.messageVerificationFailed("MAC verification failed")
        }

        // Source - https://developer.apple.com/forums/thread/687212
        let key = [UInt8](messageKeys.cipherKey)
        let initializationVector = [UInt8](messageKeys.initializationVector)
        let cyphertext = [UInt8](message.encrypted)
        let result = try CryptoService.shared.QCCAESPadCBCDecrypt(
                key: key,
                initializationVector: initializationVector,
                cyphertext: cyphertext)

        self.clearUnacknowledgedPreKeyMessageInfo()

        return Data(result)
    }

    // MARK: - Private

    /// Gets the receiver chain key for the given ephemeral key, or creates a new one if it does not exist.
    ///
    /// This method gets the receiver chain key for the given ephemeral key. If the receiver chain key does not exist, it is created using the current root key and the sender's ephemeral key.
    ///
    /// - Parameters:
    ///     - theirEphemeral: The ephemeral key of the remote user.
    ///
    /// - Returns: The receiver chain key.
    mutating func getOrCreateReceiverChainKey(theirEphemeral: PublicKey) throws -> RatchetChainKey {
        if let chain = self.receiverChains.first(where: { $0.ratchetKey == theirEphemeral }) {
            return chain.chainKey
        }

        let rootKey = self.rootKey
        let ourEphemeralKeyPair = self.senderChain.ratchetKeyPair

        let (receiverRootKey, receiverChainKey) = try rootKey.createChain(
                theirRatchetKey: theirEphemeral,
                ourRatchetKey: ourEphemeralKeyPair.privateKey)

        let ourNewEphemeral = try KeyPair()
        let (senderRootKey, senderChainKey) = try receiverRootKey.createChain(
                theirRatchetKey: theirEphemeral,
                ourRatchetKey: ourNewEphemeral.privateKey)

        self.rootKey = senderRootKey

        let receiverChain = ReceiverChain(ratchetKey: theirEphemeral, chainKey: receiverChainKey)
        self.addReceiverChain(receiverChain)

        var previousIndex: UInt32 = 0
        let currentIndex = self.senderChain.chainKey.index
        if currentIndex > 0 {
            previousIndex = currentIndex - 1
        }

        self.previousCounter = previousIndex
        self.senderChain = SenderChain(ratchetKeyPair: ourNewEphemeral, chainKey: senderChainKey)

        return receiverChainKey
    }

    /// Gets the message keys for the given receiver chain key and counter, 
    /// or creates new ones if they do not exist.
    ///
    /// This method gets the message keys for the given receiver chain key and counter. 
    /// If the message keys do not exist, they are created using the receiver chain key.
    ///
    /// - Parameters:
    ///     - theirEphemeralKey: The ephemeral key of the remote user.
    ///     - chainKey: The receiver chain key.
    ///     - counter: The counter of the message.
    ///
    /// - Returns: The message keys.
    private mutating func getOrCreateMessageKeys(
            theirEphemeralKey: PublicKey,
            chainKey: RatchetChainKey,
            counter: UInt32
    ) throws -> RatchetMessageKeys {
        let chainIndex = chainKey.index
        if chainIndex > counter {
            guard
                    let result = try self.popMessageKeys(
                            senderEphemeralKey: theirEphemeralKey,
                            counter: counter)
            else {
                throw DXError.duplicatedMessage("Duplicate message for counter \(counter)")
            }

            return result
        } else {
            let limit = DXProtocolConstants.futureMessagesLimit
            if counter - chainIndex > limit {
                let error = "Exceeded future message limit \(limit) index \(chainIndex) counter \(counter)"
                throw DXError.invalidMessage(error)
            }

            var chainKeyVar = chainKey
            while chainKeyVar.index < counter {
                let messageKeys = try chainKeyVar.messageKeys()
                try self.setMessageKeys(messageKeys, for: theirEphemeralKey)
                chainKeyVar = chainKeyVar.nextChainKey()
            }

            let currentChainKey = chainKeyVar
            let nextChainKey = currentChainKey.nextChainKey()

            try self.setReceiverChainKey(nextChainKey, for: theirEphemeralKey)

            return try currentChainKey.messageKeys()
        }
    }

    /// Pops the message keys for the given counter from the receiver chain for the given ephemeral key.
    ///
    /// This method pops the message keys for the given counter from the receiver chain for the given ephemeral key. 
    /// If the message keys do not exist, nil is returned.
    ///
    /// - Parameters:
    ///     - senderEphemeralKey: The ephemeral key of the remote user.
    ///     - counter: The counter of the message.
    ///
    /// - Returns: The message keys, or nil if they do not exist.
    private mutating func popMessageKeys(
            senderEphemeralKey: PublicKey,
            counter: UInt32
    ) throws -> RatchetMessageKeys? {
        if let chainIndex = self.indexOfReceiverChain(for: senderEphemeralKey) {
            let chain = self.receiverChains[chainIndex]
            return chain.removeMessageKeys(with: counter)
        } else {
            // This code is not covered by tests
            throw DXError.invalidKey("No receiver chain to get message key")
        }
    }

    /// Sets the message keys for the given ephemeral key.
    ///
    /// This method sets the message keys for the given ephemeral key.
    ///
    /// - Parameters:
    ///     - keys: The message keys.
    ///     - senderEphemeralKey: The ephemeral key of the remote user.
    ///
    /// - Throws:
    ///     - `DXError.invalidKey`: If there is no receiver chain for the given ephemeral key.
    private mutating func setMessageKeys(
            _ keys: RatchetMessageKeys,
            for senderEphemeralKey: PublicKey
    ) throws {
        if let chainIndex = self.indexOfReceiverChain(for: senderEphemeralKey) {
            let chain = self.receiverChains[chainIndex]
            chain.pushMessageKeys(keys)
        } else {
            // This code is not covered by tests
            throw DXError.invalidKey("No receiver chain to set message key")
        }
    }

    /// Sets the receiver chain key for the given ephemeral key.
    ///
    /// This method sets the receiver chain key for the given ephemeral key.
    ///
    /// - Parameters:
    ///     - receiverChainKey: The receiver chain key.
    ///     - senderEphemeralKey: The ephemeral key of the remote user.
    ///
    /// - Throws:
    ///     - `DXError.invalidKey`: If there is no receiver chain for the given ephemeral key.
    private mutating func setReceiverChainKey(
            _ receiverChainKey: RatchetChainKey,
            for senderEphemeralKey: PublicKey
    ) throws {
        if let chainIndex = self.indexOfReceiverChain(for: senderEphemeralKey) {
            let chain = self.receiverChains[chainIndex]
            self.receiverChains[chainIndex] = ReceiverChain(
                    ratchetKey: chain.ratchetKey,
                    chainKey: receiverChainKey,
                    messageKeys: chain.messageKeys)
        } else {
            // This code is not covered by tests
            throw DXError.invalidKey("No receiver chain to set chain key")
        }
    }

    /// Adds a receiver chain.
    ///
    /// This method adds a receiver chain to the session. 
    /// If the number of receiver chains exceeds the maximum, the oldest chain is removed.
    ///
    /// - Parameter chain: The receiver chain to add.
    private mutating func addReceiverChain(_ chain: ReceiverChain) {
        self.receiverChains.append(chain)
        if self.receiverChains.count > DXProtocolConstants.maxReceiverChains {
            self.receiverChains.removeFirst()
        }
    }

    /// Finds the index of the receiver chain for the given ephemeral key.
    ///
    /// This method finds the index of the receiver chain for the given ephemeral key. 
    /// If no receiver chain is found, nil is returned.
    ///
    /// - Parameter senderEphemeralKey: The ephemeral key of the remote user.
    ///
    /// - Returns: The index of the receiver chain, or nil if no receiver chain is found.
    private func indexOfReceiverChain(for senderEphemeralKey: PublicKey) -> Int? {
        var chainIndex: Int?
        for index in self.receiverChains.indices {
            let chain = self.receiverChains[index]
            if chain.ratchetKey == senderEphemeralKey {
                chainIndex = index
                break
            }
        }
        return chainIndex
    }
}
// swiftlint: enable file_length
