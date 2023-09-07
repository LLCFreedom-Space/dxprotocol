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
//  MockCryptoService.swift
//  DealogX
//
//  Created by Andriy Vasyk on 27.12.2022.
//

import CryptoKit
import Foundation
@testable import DXProtocol

struct MockCryptoService: CryptoServiceProtocol {
    static var mockRawPrivateKeys: [Data] = []
    static var mockPrivateKeysIndex: Int = 0
    let impl = CryptoService()

    func generatePrivateKeyRawData() -> Data {
        if Self.mockPrivateKeysIndex < 0 || Self.mockPrivateKeysIndex >= Self.mockRawPrivateKeys.count {
            return self.impl.generatePrivateKeyRawData()
        }

        let rawMockKey = Self.mockRawPrivateKeys[Self.mockPrivateKeysIndex]
        Self.mockPrivateKeysIndex += 1

        return rawMockKey
    }

    func publicSigningKeyDataFor(privateKeyData: Data) throws -> Data {
        return try self.impl.publicSigningKeyDataFor(privateKeyData: privateKeyData)
    }

    func publicAgreementKeyDataFor(privateKeyData: Data) throws -> Data {
        return try self.impl.publicAgreementKeyDataFor(privateKeyData: privateKeyData)
    }

    func performKeyAgreement(of privateKeyData: Data, with publicKeyData: Data) throws -> Data {
        return try self.impl.performKeyAgreement(of: privateKeyData, with: publicKeyData)
    }

    func deriveKey(inputKeyMaterial: Data, info: Data, outputByteCount: Int) -> Data {
        return self.impl.deriveKey(
                inputKeyMaterial: inputKeyMaterial,
                info: info,
                outputByteCount: outputByteCount)
    }

    func deriveKey(inputKeyMaterial: Data, salt: Data, info: Data, outputByteCount: Int) -> Data {
        return self.impl.deriveKey(
                inputKeyMaterial: inputKeyMaterial,
                salt: salt,
                info: info,
                outputByteCount: outputByteCount)
    }

    func hmacSHA256(for message: Data, with key: Data) -> Data {
        return self.impl.hmacSHA256(for: message, with: key)
    }

    func isValidSignature(_ signature: Data, for digest: Data, publicKey: Data) throws -> Bool {
        return try self.impl.isValidSignature(signature, for: digest, publicKey: publicKey)
    }

    func signature(for data: Data, with privateKey: Data) throws -> Data {
        return try self.impl.signature(for: data, with: privateKey)
    }

    func QCCAESPadCBCEncrypt(
            key: [UInt8],
            initializationVector: [UInt8],
            plaintext: [UInt8]
    ) throws -> [UInt8] {
        return try self.impl.QCCAESPadCBCEncrypt(
                key: key,
                initializationVector: initializationVector,
                plaintext: plaintext)
    }

    func QCCAESPadCBCDecrypt(
            key: [UInt8],
            initializationVector: [UInt8],
            cyphertext: [UInt8]
    ) throws -> [UInt8] {
        return try self.impl.QCCAESPadCBCDecrypt(
                key: key,
                initializationVector: initializationVector,
                cyphertext: cyphertext)
    }
}
