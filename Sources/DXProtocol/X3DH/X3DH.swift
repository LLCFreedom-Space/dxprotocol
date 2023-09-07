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
//  X3DH.swift
//  DealogX
//
//  Created by Andriy Vasyk on 23.12.2022.
//

import Foundation

/// An enum that provides functions for calculating shared secrets for X3DH key exchange.
///
/// X3DH is a key exchange protocol that is used to establish a shared secret between two parties. 
/// The shared secret can then be used to encrypt and decrypt messages.
enum X3DH {
    /// Calculates shared secret for initiator (sender of the first message) of conversation
    /// - Parameter aliceIdentityKeyPair: The local sender's identity key pair
    /// - Parameter aliceBaseKeyPair: The local sender's base key
    /// - Parameter bobIdentityKey: The remote identity key of receiver
    /// - Parameter bobSignedPreKeyPublic: The signed pre key of the receiver
    /// - Parameter bobOneTimePreKey: The public pre key of the receiver
    /// - Parameter bobRatchetKey: The ratchet key of the receiver
    /// - Returns: The raw data that represents shared secret
    /// - Throws: Throws if the operation failed to be performed
    static func calculateAliceSecret(aliceIdentityKeyPair: IdentityKeyPair,
                                     aliceBaseKeyPair: KeyPair,
                                     bobIdentityKey: IdentityKeyPublic,
                                     bobSignedPreKeyPublic: SignedPreKeyPublic,
                                     bobOneTimePreKey: OneTimePreKeyPublic?,
                                     bobRatchetKey: PublicKey) throws -> Data {
        let padding = Data(repeating: 0xFF, count: DXProtocolConstants.curve25519KeyLength)

        // DH1 = DH(IKa, SPKb)
        let ourIdentityPrivateKey = aliceIdentityKeyPair.privateKey
        let dh1 = try ourIdentityPrivateKey.calculateKeyAgreement(with: bobSignedPreKeyPublic.publicKey)

        // DH2 = DH(EKa, IKb)
        let aliceBasePrivateKey = aliceBaseKeyPair.privateKey
        let dh2 = try aliceBasePrivateKey.calculateKeyAgreement(with: bobIdentityKey.publicKey)

        // DH3 = DH(EKa, SPKb)
        let dh3 = try aliceBasePrivateKey.calculateKeyAgreement(with: bobSignedPreKeyPublic.publicKey)

        // DH4 = DH(EKa, OPKb)
        var dh4 = Data()
        if let theirOneTimePreKey = bobOneTimePreKey {
            dh4 = try aliceBasePrivateKey.calculateKeyAgreement(with: theirOneTimePreKey.publicKey)
        }

        // SK = KDF(DH1 || DH2 || DH3 || DH4)
        let secret = padding + dh1 + dh2 + dh3 + dh4

        return secret
    }

    /// Calculates shared secret for receiver of the first message in conversation
    /// - Parameter bobIdentityKeyPair: The local identity key of the receiver
    /// - Parameter bobSignedPreKeyPair: The local signed pre key of the receiver
    /// - Parameter bobOneTimePreKeyPair: The local pre key of the receiver
    /// - Parameter bobRatchetKeyPair: The local ratchet key of the receiver
    /// - Parameter aliceIdentityKey: The identity key of the sender
    /// - Parameter aliceBaseKey: The base key of the sender
    /// - Returns: The raw data that represents shared secret
    /// - Throws: Throws if the operation failed to be performed
    static func calculateBobSecret(bobIdentityKeyPair: IdentityKeyPair,
                                   bobSignedPreKeyPair: SignedPreKeyPair,
                                   bobOneTimePreKeyPair: OneTimePreKeyPair?,
                                   bobRatchetKeyPair: KeyPair,
                                   aliceIdentityKey: IdentityKeyPublic,
                                   aliceBaseKey: PublicKey) throws -> Data {
        let padding = Data(repeating: 0xFF, count: DXProtocolConstants.curve25519KeyLength)

        // DH1 = DH(IKa, SPKb)
        let bobSignedPreKeyPrivate = bobSignedPreKeyPair.privateKey
        let dh1 = try bobSignedPreKeyPrivate.calculateKeyAgreement(with: aliceIdentityKey.publicKey)

        // DH2 = DH(EKa, IKb)
        let dh2 = try bobIdentityKeyPair.privateKey.calculateKeyAgreement(with: aliceBaseKey)

        // DH3 = DH(EKa, SPKb)
        let dh3 = try bobSignedPreKeyPrivate.calculateKeyAgreement(with: aliceBaseKey)

        // DH4 = DH(EKa, OPKb)
        var dh4 = Data()
        if let ourOneTimePreKeyPair = bobOneTimePreKeyPair {
            dh4 = try ourOneTimePreKeyPair.privateKey.calculateKeyAgreement(with: aliceBaseKey)
        }

        // SK = KDF(DH1 || DH2 || DH3 || DH4)
        let secret = padding + dh1 + dh2 + dh3 + dh4

        return secret
    }
}
