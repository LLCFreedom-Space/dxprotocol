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
//  SessionStateFactory.swift
//  DealogX
//
//  Created by Andriy Vasyk on 23.12.2022.
//

import Foundation

/// An enum that creates new session states for Alice and Bob.
///
/// This enum provides two functions to create new session states for Alice and Bob. 
/// The functions take the necessary parameters to initialize the session state, 
/// such as the identity keys of the two users, and the ratchet keys.
enum SessionStateFactory {
    /// Creates a new session state for Alice.
    ///
    /// This method creates a new session state for Alice. 
    /// The session state is initialized with the given parameters, 
    /// including Alice's identity key, 
    /// Bob's identity key, and Bob's ratchet key.
    ///
    /// - Parameters:
    ///     - aliceIdentityKeyPair: Alice's identity key pair.
    ///     - aliceBaseKeyPair: Alice's base key pair.
    ///     - bobIdentityKey: Bob's identity key.
    ///     - bobSignedPreKeyPublic: Bob's signed pre-key public key, if any.
    ///     - bobOneTimePreKey: Bob's one-time pre-key public key, if any.
    ///     - bobRatchetKey: Bob's ratchet key.
    ///
    /// - Returns: The new session state.
    static func createAliceSessionState(aliceIdentityKeyPair: IdentityKeyPair,
                                        aliceBaseKeyPair: KeyPair,
                                        bobIdentityKey: IdentityKeyPublic,
                                        bobSignedPreKeyPublic: SignedPreKeyPublic,
                                        bobOneTimePreKey: OneTimePreKeyPublic?,
                                        bobRatchetKey: PublicKey) throws -> SessionState {
        let secret = try X3DH.calculateAliceSecret(
                aliceIdentityKeyPair: aliceIdentityKeyPair,
                aliceBaseKeyPair: aliceBaseKeyPair,
                bobIdentityKey: bobIdentityKey,
                bobSignedPreKeyPublic: bobSignedPreKeyPublic,
                bobOneTimePreKey: bobOneTimePreKey,
                bobRatchetKey: bobRatchetKey)

        // As part of initialisation Alice generates a new ratchet key pair
        let sendingRatchetKeyPair = try KeyPair()

        // And feeds X3DH output to "root KDF" to calculate new root key (RK) and sending chain key (CK)
        let (rootKey, chainKey) = try RatchetRootKey.createChainFrom(secret: secret)

        let (sendingChainRootKey, sendingChainChainKey) = try rootKey.createChain(
                theirRatchetKey: bobRatchetKey,
                ourRatchetKey: sendingRatchetKeyPair.privateKey)

        // The output keys from the root chain become new KDF keys for the sending and receiving chains
        let senderChain = SenderChain(ratchetKeyPair: sendingRatchetKeyPair, chainKey: sendingChainChainKey)
        let receiverChain = ReceiverChain(ratchetKey: bobRatchetKey, chainKey: chainKey)

        let state = SessionState(
                ourLocalIdentityPublic: aliceIdentityKeyPair.identityKey,
                theirRemoteIdentityPublic: bobIdentityKey,
                rootKey: sendingChainRootKey,
                previousCounter: 0,
                senderChain: senderChain,
                receiverChains: [receiverChain],
                pendingPreKey: nil,
                aliceBaseKey: aliceBaseKeyPair.publicKey)
        return state
    }

    /// Creates a new session state for Bob.
    ///
    /// This method creates a new session state for Bob. 
    /// The session state is initialized with the given parameters, 
    /// including Bob's identity key, 
    /// Alice's identity key, and Alice's base key.
    ///
    /// - Parameters:
    ///     - bobIdentityKeyPair: Bob's identity key pair.
    ///     - bobSignedPreKeyPair: Bob's signed pre-key key pair, if any.
    ///     - bobOneTimePreKeyPair: Bob's one-time pre-key key pair, if any.
    ///     - bobRatchetKeyPair: Bob's ratchet key pair.
    ///     - aliceIdentityKey: Alice's identity key.
    ///     - aliceBaseKey: Alice's base key.
    ///
    /// - Returns: The new session state.
    static func createBobSessionState(bobIdentityKeyPair: IdentityKeyPair,
                                      bobSignedPreKeyPair: SignedPreKeyPair,
                                      bobOneTimePreKeyPair: OneTimePreKeyPair?,
                                      bobRatchetKeyPair: KeyPair,
                                      aliceIdentityKey: IdentityKeyPublic,
                                      aliceBaseKey: PublicKey) throws -> SessionState {
        let secret = try X3DH.calculateBobSecret(
                bobIdentityKeyPair: bobIdentityKeyPair,
                bobSignedPreKeyPair: bobSignedPreKeyPair,
                bobOneTimePreKeyPair: bobOneTimePreKeyPair,
                bobRatchetKeyPair: bobRatchetKeyPair,
                aliceIdentityKey: aliceIdentityKey,
                aliceBaseKey: aliceBaseKey)

        // Create Root chain from shared secret
        let (rootKey, chainKey) = try RatchetRootKey.createChainFrom(secret: secret)

        // The output keys from the root chain become new KDF keys for the sending and receiving chains
        let senderChain = SenderChain(ratchetKeyPair: bobRatchetKeyPair, chainKey: chainKey)

        let state = SessionState(
                ourLocalIdentityPublic: bobIdentityKeyPair.identityKey,
                theirRemoteIdentityPublic: aliceIdentityKey,
                rootKey: rootKey,
                previousCounter: 0,
                senderChain: senderChain,
                receiverChains: [],
                pendingPreKey: nil,
                aliceBaseKey: aliceBaseKey)
        return state
    }
}
