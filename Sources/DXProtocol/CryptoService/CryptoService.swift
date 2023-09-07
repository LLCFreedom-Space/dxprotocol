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
//  CryptoService.swift
//  DealogX
//
//  Created by Andriy Vasyk on 1.12.2022.
//

import Foundation
import CommonCrypto
import CryptoKit

/// Implementation of Crypto Service Protocol
public struct CryptoService: CryptoServiceProtocol {
    static var shared: CryptoServiceProtocol = CryptoService.makeCryptoService()

    /// Generates a new X25519 private key and returns raw representation of this key
    /// - Returns: The raw representation of new private key
    public func generatePrivateKeyRawData() -> Data {
        let key = Curve25519.KeyAgreement.PrivateKey()
        return key.rawRepresentation
    }

    /// Returns the corresponding signing public key data for this private key data
    /// - Parameter privateKeyData: The 32-bytes representation of the private key.
    /// - Throws: Throws if the operation failed to be performed.
    public func publicSigningKeyDataFor(privateKeyData: Data) throws -> Data {
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData)
        return key.publicKey.rawRepresentation
    }

    /// Returns the corresponding agreement public key data for this private key data
    /// - Parameter privateKeyData: The 32-bytes representation of the private key.
    /// - Throws: Throws if the operation failed to be performed.
    public func publicAgreementKeyDataFor(privateKeyData: Data) throws -> Data {
        let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
        return key.publicKey.rawRepresentation
    }

    /// Performs an elliptic curve Diffie-Hellmann key agreement over X25519 between specified private key and public key.
    /// - Parameter privateKeyData: The raw representation of private key
    /// - Parameter publicKeyData: The raw representation of public key to perform agreement with
    /// - Throws: Throws if the operation failed to be performed.
    /// - Returns: The shared agreement data
    public func performKeyAgreement(of privateKeyData: Data, with publicKeyData: Data) throws -> Data {
        let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
        let publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKeyData)

        let sharedSecret = try key.sharedSecretFromKeyAgreement(with: publicKey)
        var bytes: [UInt8] = []
        sharedSecret.withUnsafeBytes { bytes.append(contentsOf: $0) }
        return Data(bytes)
    }

    /// Derives a symmetric key using the HKDF algorithm.
    /// - Parameter inputKeyMaterial: The input key material to use to derive the secrets
    /// - Parameter info: Context and application specific information
    /// - Parameter outputByteCount: The desired number of output bytes
    /// - Returns: The raw representation of derived key
    public func deriveKey(inputKeyMaterial: Data, info: Data, outputByteCount: Int) -> Data {
        let material = SymmetricKey(data: inputKeyMaterial)
        let derived = HKDF<SHA256>.deriveKey(
                inputKeyMaterial: material,
                info: info,
                outputByteCount: outputByteCount)
        var derivedKeyBytes: [UInt8] = []
        derivedKeyBytes.reserveCapacity(outputByteCount)
        derived.withUnsafeBytes { derivedKeyBytes.append(contentsOf: $0) }

        return Data(derivedKeyBytes)
    }

    /// Derives a symmetric key using the HKDF algorithm.
    /// - Parameter inputKeyMaterial: The input key material to use to derive the secrets
    /// - Parameter salt: A non-secret random value
    /// - Parameter info: Context and application specific information
    /// - Parameter outputByteCount: The desired number of output bytes
    /// - Returns: The raw representation of derived key
    public func deriveKey(inputKeyMaterial: Data, salt: Data, info: Data, outputByteCount: Int) -> Data {
        let material = SymmetricKey(data: inputKeyMaterial)
        let derived = HKDF<SHA256>.deriveKey(
                inputKeyMaterial: material,
                salt: salt,
                info: info,
                outputByteCount: outputByteCount)
        var derivedKeyBytes: [UInt8] = []
        derivedKeyBytes.reserveCapacity(outputByteCount)
        derived.withUnsafeBytes { derivedKeyBytes.append(contentsOf: $0) }

        return Data(derivedKeyBytes)
    }

    /// Returns the Message Authentication Code based on SHA256.
    /// - Parameter message: The message to authenticate
    /// - Parameter key: The key to use for HMAC
    /// - Returns: Returns the Message Authentication Code (MAC) from the data passed into the MAC
    public func hmacSHA256(for message: Data, with key: Data) -> Data {
        var hmac = HMAC<SHA256>(key: SymmetricKey(data: key))
        hmac.update(data: message)
        let result = hmac.finalize()

        var bytes: [UInt8] = []
        result.withUnsafeBytes { bytes.append(contentsOf: $0) }
        return Data(bytes)
    }

    /// Verifies that the signature corresponds to the signed data.
    /// - Parameter signature: The 64-bytes signature to verify
    /// - Parameter digest: The digest that was signed
    /// - Parameter publicKey: The key to check signature with
    /// - Returns: True if the signature is valid. False otherwise
    public func isValidSignature(_ signature: Data, for digest: Data, publicKey: Data) throws -> Bool {
        let key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
        return key.isValidSignature(signature, for: digest)
    }

    /// Returns a signature for the specified data
    /// - Parameter data: The data to sign
    /// - Parameter privateKey: The key to sign data with
    /// - Returns: The 64-bytes signature for the data
    /// - Throws: Throws if the operation failed to be performed
    public func signature(for data: Data, with privateKey: Data) throws -> Data {
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey)
        return try key.signature(for: data)
    }

    /// The QCCAESPadCBCEncrypt function encrypts data using AES in CBC mode with PKCS7 padding.
    /// The padding ensures that the ciphertext is a multiple of the block size.
    /// - Parameters:
    ///     - key: The encryption key.
    ///     - initializationVector: The initialization vector.
    ///     - plaintext: The data to encrypt.
    /// - Returns: The encrypted data.
    /// - Throws: CryptoError if an error occurs.
    public func QCCAESPadCBCEncrypt(key: [UInt8],
                                    initializationVector: [UInt8],
                                    plaintext: [UInt8]) throws -> [UInt8] {
        // The key size must be "128", "192", or "256".
        // The IV size must match the block size.

        guard [kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256].contains(key.count),
              initializationVector.count == kCCBlockSizeAES128 else {
            throw CryptoError(code: kCCParamError)
        }


        ///    Padding can expand the data, so we have to allocate space for that.  The
        ///    rule for block cyphers, like AES, is that the padding only adds space on
        ///    encryption (on decryption it can reduce space, obviously, but we don't
        ///    need to account for that) and it will only add at most one block size
        ///    worth of space.

        var cyphertext = [UInt8](repeating: 0, count: plaintext.count + kCCBlockSizeAES128)
        var cyphertextCount = 0
        let err = CCCrypt(
                CCOperation(kCCEncrypt),
                CCAlgorithm(kCCAlgorithmAES),
                CCOptions(kCCOptionPKCS7Padding),
                key,
                key.count,
                initializationVector,
                plaintext,
                plaintext.count,
                &cyphertext,
                cyphertext.count,
                &cyphertextCount
        )

        // This code is not covered by tests
        guard err == kCCSuccess else {
            throw CryptoError(code: err)
        }

        /// The cyphertext can expand by up to one block but it doesn’t always use the full block,
        /// so trim off any unused bytes.

        assert(cyphertextCount <= cyphertext.count)
        cyphertext.removeLast(cyphertext.count - cyphertextCount)
        assert(cyphertext.count.isMultiple(of: kCCBlockSizeAES128))

        return cyphertext
    }

    /// The QCCAESPadCBCDecrypt function decrypts data using AES in CBC mode with PKCS7 padding.
    // The padding ensures that the ciphertext is a multiple of the block size.
    /// - Parameters:
    ///     - key: The decryption key.
    ///     - initializationVector: The initialization vector.
    ///     - cyphertext: The data to decrypt.
    ///
    /// - Returns: The decrypted data.
    ///
    /// - Throws: CryptoError if an error occurs.
    public func QCCAESPadCBCDecrypt(key: [UInt8],
                                    initializationVector: [UInt8],
                                    cyphertext: [UInt8]) throws -> [UInt8] {
        // The key size must be "128", "192", or "256".
        // The IV size must match the block size.
        // The ciphertext must be a multiple of the block size.

        guard [kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256].contains(key.count),
              initializationVector.count == kCCBlockSizeAES128,
              cyphertext.count.isMultiple(of: kCCBlockSizeAES128) else {
            throw CryptoError(code: kCCParamError)
        }

        /// Padding can expand the data on encryption, but on decryption the data can
        /// only shrink so we use the cyphertext size as our plaintext size.

        var plaintext = [UInt8](repeating: 0, count: cyphertext.count)
        var plaintextCount = 0
        let err = CCCrypt(
                CCOperation(kCCDecrypt),
                CCAlgorithm(kCCAlgorithmAES),
                CCOptions(kCCOptionPKCS7Padding),
                key,
                key.count,
                initializationVector,
                cyphertext,
                cyphertext.count,
                &plaintext,
                plaintext.count,
                &plaintextCount
        )

        // This code is not covered by tests
        guard err == kCCSuccess else {
            throw CryptoError(code: err)
        }

        // Trim any unused bytes off the plaintext.

        assert(plaintextCount <= plaintext.count)
        plaintext.removeLast(plaintext.count - plaintextCount)

        return plaintext
    }
}

extension CryptoService {
    /// Set up type alias for `CreateCryptoService` allowing to declare closure
    /// that create concrete implementation of `CryptoServiceProtocol` protocol
    typealias CreateCryptoService = () -> CryptoServiceProtocol

    /// Closure that allows to create concrete implementation of `CryptoServiceProtocol` protocol
    private static var makeCryptoService: CreateCryptoService = {
        CryptoService()
    }

    /// Allows to set the closure that will be used to create concrete instance of `CryptoServiceProtocol`
    /// - Parameter make: closure - `@escaping CreateCryptoService`
    static func use(_ make: @escaping CreateCryptoService) {
        Self.makeCryptoService = make
    }
}
