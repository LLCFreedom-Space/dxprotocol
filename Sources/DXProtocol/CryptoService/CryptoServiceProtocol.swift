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
//  CryptoServiceable.swift
//  DealogX
//
//  Created by Andriy Vasyk on 07.04.2023.
//

import Foundation

/// `CryptoServiceProtocol` protocol
public protocol CryptoServiceProtocol {
    /// Generates a new X25519 private key and returns raw representation of this key
    /// - Returns: The raw representation of new private key
    func generatePrivateKeyRawData() -> Data

    /// Returns the corresponding signing public key data for this private key data
    /// - Parameter privateKeyData: The 32-bytes representation of the private key.
    /// - Throws: Throws if the operation failed to be performed.
    func publicSigningKeyDataFor(privateKeyData: Data) throws -> Data

    /// Returns the corresponding agreement public key data for this private key data
    /// - Parameter privateKeyData: The 32-bytes representation of the private key.
    /// - Throws: Throws if the operation failed to be performed.
    func publicAgreementKeyDataFor(privateKeyData: Data) throws -> Data

    /// Performs Diffie-Hellman key agreement with the given public key and returns the shared secret.
    ///
    /// - Parameter privateKeyData: The 32-bytes representation of the private key.
    /// - Parameter publicKeyData: The 32-bytes representation of the public key.
    /// - Throws: Throws if the operation failed to be performed.
    func performKeyAgreement(of privateKeyData: Data, with publicKeyData: Data) throws -> Data

    /// Derives a new key from the given key material, using the given info as salt.
    ///
    /// - Parameter inputKeyMaterial: The key material to derive from.
    /// - Parameter info: The salt to use.
    /// - Parameter outputByteCount: The number of bytes to output.
    /// - Returns: The derived key.
    func deriveKey(inputKeyMaterial: Data, info: Data, outputByteCount: Int) -> Data

    /// Derives a new key from the given key material, using the given salt and info as salt.
    ///
    /// - Parameter inputKeyMaterial: The key material to derive from.
    /// - Parameter salt: The salt to use.
    /// - Parameter info: The salt to use.
    /// - Parameter outputByteCount: The number of bytes to output.
    /// - Returns: The derived key.
    func deriveKey(inputKeyMaterial: Data, salt: Data, info: Data, outputByteCount: Int) -> Data

    /// Calculates the HMAC-SHA256 of the given message using the given key.
    ///
    /// - Parameter message: The message to calculate the HMAC over.
    /// - Parameter key: The key to use.
    /// - Returns: The HMAC-SHA256 of the message.
    func hmacSHA256(for message: Data, with key: Data) -> Data

    /// Verifies that the given signature is valid for the given digest and public key.
    ///
    /// - Parameter signature: The signature to verify.
    /// - Parameter digest: The digest that the signature was calculated over.
    /// - Parameter publicKey: The public key that was used to sign the digest.
    /// - Returns: True if the signature is valid, false otherwise.
    func isValidSignature(_ signature: Data, for digest: Data, publicKey: Data) throws -> Bool

    /// Signs the given data using the given private key.
    ///
    /// - Parameter data: The data to sign.
    /// - Parameter privateKey: The private key to use.
    /// - Returns: The signature of the data.
    func signature(for data: Data, with privateKey: Data) throws -> Data

    /// Encrypts the given plaintext using the given key and initialization vector.
    ///
    /// - Parameter key: The key to use for encryption.
    /// - Parameter initializationVector: The initialization vector to use.
    /// - Parameter plaintext: The plaintext to encrypt.
    /// - Returns: The ciphertext.
    func QCCAESPadCBCEncrypt(key: [UInt8],
                             initializationVector: [UInt8],
                             plaintext: [UInt8]) throws -> [UInt8]
    /// Decrypts the given ciphertext using the given key and initialization vector.
    ///
    /// - Parameter key: The key to use for decryption.
    /// - Parameter initializationVector: The initialization vector to use.
    /// - Parameter cyphertext: The cypher text to encrypt.
    func QCCAESPadCBCDecrypt(key: [UInt8],
                             initializationVector: [UInt8],
                             cyphertext: [UInt8]) throws -> [UInt8]
}
