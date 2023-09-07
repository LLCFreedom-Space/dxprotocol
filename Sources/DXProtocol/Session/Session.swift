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
//  Session.swift
//  DealogX
//
//  Created by Andriy Vasyk on 08.12.2022.
//

import Foundation

// swiftlint: disable file_length
/// A session that manages current and previous states `SessionState`
/// and allows to decrypt/encrypt messages in particular conversation
public struct Session: Codable {
    /// The current state of the session
    private(set) var state: SessionState

    /// A list of previous states of the session
    private(set) var previousSessionStates: [SessionState]

    /// The coding keys for encoding and decoding a `Session`.
    enum CodingKeys: String, CodingKey {
        /// The state of the session.
        case state
        /// The previous session states.
        case previousSessionStates
    }

    // MARK: - Interface

    // Processes a pre-key bundle from a remote user.
    ///
    /// This method verifies the signature of the pre-key bundle, generates a new session, and stores the session in the session store.
    ///
    /// - Parameters:
    ///     - bundle: The pre-key bundle from the remote user.
    ///     - address: The address of the remote user.
    ///     - sessionStore: The session store.
    ///     - identityStore: The identity store.
    ///
    /// - Returns: The new session.
    @discardableResult public static func processPreKeyBundle(_ bundle: PreKeyBundle,
                                                              for address: ProtocolAddress,
                                                              sessionStore: SessionStorable,
                                                              identityStore: IdentityKeyStorable) throws -> Self {
        // Public identity key of the remote user which is suitable for key agreement operations
        let theirIdentityKey = bundle.identityKey

        guard try identityStore.isTrustedIdentity(
                theirIdentityKey,
                for: address,
                direction: .sending) else {
            throw DXError.untrustedIdentity("Abort processing PreKey Bundle for untrusted identity")
        }

        // Public signing key of the remote user which is suitable for signing operations
        let theirSigningKey = bundle.signingKey

        // Alice verifies the PreKey signature and aborts the protocol if verification fails
        let theirSignedPreKeyPublic = bundle.signedPreKey

        guard try theirSigningKey.verifySignature(
                theirSignedPreKeyPublic.signature,
                for: theirSignedPreKeyPublic.data) else {
            throw DXError.invalidSignature("Failed to verify signature of Signed PreKey")
        }

        // IKa
        let ourIdentityKeyPair = try identityStore.identityKeyPair()

        // Alice then generates an ephemeral key pair with public key EKa
        let ourBaseKeyPair = try KeyPair()

        // Bob's signed pre-key from X3DH (SPKb) becomes the initial
        // Ratchet public key for Double Ratchet initialisation.
        let theirRatchetKey = theirSignedPreKeyPublic.publicKey

        var state = try SessionStateFactory.createAliceSessionState(
                aliceIdentityKeyPair: ourIdentityKeyPair,
                aliceBaseKeyPair: ourBaseKeyPair,
                bobIdentityKey: theirIdentityKey,
                bobSignedPreKeyPublic: theirSignedPreKeyPublic,
                bobOneTimePreKey: bundle.oneTimePreKey,
                bobRatchetKey: theirRatchetKey)

        state.setUnacknowledgedPreKeyMessageInfo(
                oneTimePreKeyId: bundle.oneTimePreKey?.id,
                signedPreKeyId: bundle.signedPreKey.id,
                baseKey: ourBaseKeyPair.publicKey)

        state.localRegistrationId = try identityStore.localRegistrationId()
        state.remoteRegistrationId = bundle.registrationId

        try identityStore.saveIdentity(theirIdentityKey, for: address)

        var session = try sessionStore.loadSession(for: address)
        if nil == session {
            session = Self(state: state)
        } else {
            session?.promoteState(state: state)
        }

        // This code is not covered by tests
        guard let session = session else {
            throw DXError.internalError("Failed to create session while processing PreKey Bundle")
        }

        try sessionStore.storeSession(session, for: address)

        return session
    }

    /// Processes a pre-key message from a remote user.
    ///
    /// This method creates a new session or updates an existing session if the message is from a known user.
    ///
    /// - Parameters:
    ///     - message: The pre-key message from the remote user.
    ///     - address: The address of the remote user.
    ///     - sessionStore: The session store.
    ///     - identityStore: The identity store.
    ///     - preKeyStore: The pre-key store.
    ///     - signedPreKeyStore: The signed pre-key store.
    ///
    /// - Returns: The new or updated session.
    private static func processPreKeyMessage(_ message: PreKeySecureMessage,
                                             from address: ProtocolAddress,
                                             sessionStore: SessionStorable,
                                             identityStore: IdentityKeyStorable,
                                             preKeyStore: PreKeyStorable,
                                             signedPreKeyStore: SignedPreKeyStorable) throws -> Self {
        let theirIdentityKey = message.senderIdentityKey

        // This code is not covered by tests
        guard try identityStore.isTrustedIdentity(
                theirIdentityKey,
                for: address,
                direction: .receiving) else {
            throw DXError.untrustedIdentity("Abort processing PreKey Message for untrusted identity")
        }

        let theirBaseKey = message.senderBaseKey
        let messageVersion = Int(message.messageVersion)
        var session = try sessionStore.loadSession(for: address)
        if let session = session, session.hasSessionState(with: theirBaseKey, version: messageVersion) {
            // We've already setup a session for this message
            return session
        }

        let signedPreKeyId = message.signedPreKeyId
        let ourSignedPreKeyPair = try signedPreKeyStore.loadSignedPreKey(id: signedPreKeyId)

        var ourOneTimePreKeyPair: OneTimePreKeyPair?
        if let id = message.oneTimePreKeyId {
            ourOneTimePreKeyPair = try preKeyStore.loadPreKey(id: id)
        }

        session?.archiveCurrentState()

        let ourIdentityKeyPair = try identityStore.identityKeyPair()

        // Bob's signed pre-key from X3DH (SPKb) becomes the initial
        // Ratchet public key for Double Ratchet initialisation.
        let ourRatchetKeyPair = KeyPair(
                publicKey: ourSignedPreKeyPair.publicKey,
                privateKey: ourSignedPreKeyPair.privateKey)

        var state = try SessionStateFactory.createBobSessionState(
                bobIdentityKeyPair: ourIdentityKeyPair,
                bobSignedPreKeyPair: ourSignedPreKeyPair,
                bobOneTimePreKeyPair: ourOneTimePreKeyPair,
                bobRatchetKeyPair: ourRatchetKeyPair,
                aliceIdentityKey: theirIdentityKey,
                aliceBaseKey: theirBaseKey)
        state.localRegistrationId = try identityStore.localRegistrationId()
        state.remoteRegistrationId = message.registrationId

        if nil == session {
            session = Self(state: state)
        } else {
            session?.promoteState(state: state)
        }

        // This code is not covered by tests
        guard let session = session else {
            throw DXError.internalError("Failed to create session while processing PreKey Bundle")
        }

        try identityStore.saveIdentity(theirIdentityKey, for: address)

        // We changed state of the session thus need to save changes
        try sessionStore.storeSession(session, for: address)

        return session
    }

    // MARK: - Encrypt

    /// Encrypts data and returns a message container.
    ///
    /// This method encrypts the data using the ratchet keys for the session.
    ///
    /// - Parameters:
    ///     - data: The data to encrypt.
    ///     - address: The address of the remote user.
    ///     - sessionStore: The session store.
    ///     - identityStore: The identity store.
    ///
    /// - Returns: The encrypted message container.
    public mutating func encrypt(data: Data,
                                 for address: ProtocolAddress,
                                 sessionStore: SessionStorable,
                                 identityStore: IdentityKeyStorable) throws -> MessageContainer {
        let result = try self.state.encrypt(
                data: data,
                sessionStore: sessionStore,
                identityStore: identityStore)
        try sessionStore.storeSession(self, for: address)

        return result
    }

    // MARK: - Decrypt

    /// Decrypts a message container and returns the data.
    ///
    /// This method decrypts the message container using the ratchet keys for the session.
    ///
    /// - Parameters:
    ///     - message: The message container to decrypt.
    ///     - address: The address of the remote user.
    ///     - sessionStore: The session store.
    ///     - identityStore: The identity store.
    ///     - preKeyStore: The pre-key store.
    ///     - signedPreKeyStore: The signed pre-key store.
    ///
    /// - Returns: The decrypted data.
    public static func decrypt(message: MessageContainer,
                               from address: ProtocolAddress,
                               sessionStore: SessionStorable,
                               identityStore: IdentityKeyStorable,
                               preKeyStore: PreKeyStorable,
                               signedPreKeyStore: SignedPreKeyStorable) throws -> Data {
        var result = Data()

        if case .secureMessage(let payload) = message {
            result = try self.decrypt(
                    secureMessage: payload,
                    from: address,
                    sessionStore: sessionStore,
                    identityStore: identityStore)
        }

        if case .preKeySecureMessage(let payload) = message {
            result = try self.decrypt(
                    preKeyMessage: payload,
                    from: address,
                    sessionStore: sessionStore,
                    identityStore: identityStore,
                    preKeyStore: preKeyStore,
                    signedPreKeyStore: signedPreKeyStore)
        }
        return result
    }

    // MARK: - Private

    /// Initialises a new fresh session with state `SessionState`
    /// - Parameter state: The state to initialise session with
    private init(state: SessionState) {
        self.state = state
        self.previousSessionStates = []
    }
}

extension Session {
    // MARK: Decryption

    /// Decrypts a pre-key message and returns the data.
    ///
    /// This method decrypts the pre-key message using the ratchet keys for the session.
    ///
    /// - Parameters:
    ///     - preKeyMessage: The pre-key message to decrypt.
    ///     - address: The address of the remote user.
    ///     - sessionStore: The session store.
    ///     - identityStore: The identity store.
    ///     - preKeyStore: The pre-key store.
    ///     - signedPreKeyStore: The signed pre-key store.
    ///
    /// - Returns: The decrypted data.
    private static func decrypt(preKeyMessage: PreKeySecureMessage,
                                from address: ProtocolAddress,
                                sessionStore: SessionStorable,
                                identityStore: IdentityKeyStorable,
                                preKeyStore: PreKeyStorable,
                                signedPreKeyStore: SignedPreKeyStorable) throws -> Data {
        var session = try self.processPreKeyMessage(
                preKeyMessage,
                from: address,
                sessionStore: sessionStore,
                identityStore: identityStore,
                preKeyStore: preKeyStore,
                signedPreKeyStore: signedPreKeyStore)
        // This is 'decrypt_message_with_record'
        let result = try session.decryptMessage(preKeyMessage.secureMessage)

        try sessionStore.storeSession(session, for: address)

        // Bob won't immediately erase anything, because he might be offline.
        // But as soon as he receives the message, he will erase his one-time pre-key.
        if let id = preKeyMessage.oneTimePreKeyId {
            try? preKeyStore.removePreKey(id: id)
        }

        return Data(result)
    }

    /// Decrypts a secure message and returns the data.
    ///
    /// This method decrypts the secure message using the ratchet keys for the session.
    ///
    /// - Parameters:
    ///     - secureMessage: The secure message to decrypt.
    ///     - address: The address of the remote user.
    ///     - sessionStore: The session store.
    ///     - identityStore: The identity store.
    ///
    /// - Returns: The decrypted data.
    private static func decrypt(secureMessage: SecureMessage,
                                from address: ProtocolAddress,
                                sessionStore: SessionStorable,
                                identityStore: IdentityKeyStorable) throws -> Data {
        // This code is not covered by tests
        guard var session = try sessionStore.loadSession(for: address) else {
            throw DXError.sessionNotFound("Failed to find session while decrypting message")
        }

        let theirIdentityKey = session.state.theirRemoteIdentityPublic

        // This code is not covered by tests
        guard try identityStore.isTrustedIdentity(
                theirIdentityKey,
                for: address,
                direction: .receiving) else {
            throw DXError.untrustedIdentity("Abort decrypting PreKeyMessage for untrusted identity")
        }

        // This is 'decrypt_message_with_record'
        let result = try session.decryptMessage(secureMessage)

        try sessionStore.storeSession(session, for: address)
        return Data(result)
    }

    /// Decrypts a message and returns the data.
    ///
    /// This method decrypts the message using the ratchet keys for the current session state. 
    /// If the message cannot be decrypted using the current session state, 
    /// the previous session states are tried in reverse chronological order.
    ///
    /// - Parameters:
    ///     - message: The message to decrypt.
    ///
    /// - Returns: The decrypted data.
    private mutating func decryptMessage(_ message: SecureMessage) throws -> Data {
        var result = Data()

        do {
            // We MUST discard changes of 'state' if decryption of message fails
            var state = self.state
            result = try state.decryptMessage(message)
            self.state = state
        } catch let error {
            if case DXError.duplicatedMessage = error {
                // This message has been already processed.
                // Do not try previous states to decrypt it
                throw error
            }
        }

        if result.isEmpty {
            let previousSessionStates = self.previousSessionStates
            for index in previousSessionStates.indices {
                var olderState = previousSessionStates[index]

                do {
                    result = try olderState.decryptMessage(message)
                    self.promotePreviousState(state: olderState, index: index)
                    break
                } catch let error {
                    // This code is not covered by tests
                    if case DXError.duplicatedMessage = error {
                        // This message has been already processed.
                        // Don't try other previous states to decrypt it
                        throw error
                    }
                }
            }
        }

        if result.isEmpty {
            throw DXError.invalidMessage("Failed to decrypt message")
        }
        return result
    }
}

extension Session {
    // MARK: States Management

    /// Checks if the session contains a state with specified base key
    /// - Parameter baseKey: The key `PublicKey` used for the session's state
    /// - Parameter version: The session version
    /// - Returns: True if session contains state for specified key. False otherwise
    func hasSessionState(with baseKey: PublicKey, version: Int) -> Bool {
        if self.state.aliceBaseKey == baseKey && self.state.sessionVersion == version {
            return true
        }

        return self.previousSessionStates.contains {
            $0.aliceBaseKey == baseKey && $0.sessionVersion == version
        }
    }

    /// Checks if the session contains active current state.
    /// - Returns: True if session contains active current state. False otherwise
    func hasCurrentState() -> Bool {
        return !self.state.archived
    }

    // TODO: - Add tests on error
    /// Archives the current active state. For example, this functionality might be used to manage stale devices
    mutating func archiveCurrentState() {
        guard !self.state.archived else {
            return
        }

        if self.previousSessionStates.count >= DXProtocolConstants.archivedStatesMaxLength {
            self.previousSessionStates.removeLast()
        }
        self.state.archived = true
        self.previousSessionStates.insert(self.state, at: 0)
    }

    /// Makes the specified state the currently active state of the session.
    /// This method must be used to promote newly created states to existing sessions
    /// - Parameter state: The new current state
    private mutating func promoteState(state: SessionState) {
        self.archiveCurrentState()

        self.state = state
        self.state.archived = false
    }

    /// Makes the specified previous state the currently active state of the session
    /// Removed that state from a list of previous states
    /// - Parameter state: The new current state
    /// - Parameter index: The state index
    private mutating func promotePreviousState(state: SessionState, index: Int) {
        if index >= 0, index < self.previousSessionStates.count {
            self.previousSessionStates.remove(at: index)

            self.promoteState(state: state)
        }
    }
}

extension Session: Equatable {
    /// Conform `Session` to `Equatable` protocol
    /// - Parameters:
    ///   - lhs: `Session`
    ///   - rhs: `Session`
    /// - Returns: `Bool`
    public static func == (lhs: Session, rhs: Session) -> Bool {
        lhs.state.aliceBaseKey == rhs.state.aliceBaseKey &&
                lhs.state.localRegistrationId == rhs.state.localRegistrationId &&
                lhs.state.rootKey.data == rhs.state.rootKey.data &&
                lhs.previousSessionStates.count == rhs.previousSessionStates.count
    }
}
// swiftlint: enable file_length
