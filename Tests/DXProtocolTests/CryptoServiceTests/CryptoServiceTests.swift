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
//  CryptoServiceTests.swift
//  DealogXTests
//
//  Created by Andriy Vasyk on 01.03.2023.
//

import CryptoKit
import Foundation
import XCTest

@testable import DXProtocol

final class CryptoServiceTests: XCTestCase {
    let sut = CryptoService()

    func testCBCWithPadEncryptDecrypt() throws {
        let key: [UInt8] = [
            0xa6, 0x4c, 0x16, 0x14, 0x04, 0xe2, 0x7d, 0x6f, 0x95, 0x74, 0xc6, 0x19, 0x41,
            0x6e, 0x80, 0x4d, 0xc0, 0x86, 0xc2, 0x9d, 0x35, 0x4c, 0x2e, 0xc6, 0xba, 0x55,
            0xe9, 0xab, 0x93, 0x58, 0x1b, 0x17
        ]

        let initializationVector: [UInt8] = [
            0x24, 0x8e, 0xb3, 0xab, 0xf7, 0x1f, 0x5c, 0x40, 0x61, 0xc3, 0x49, 0x2f, 0xfb, 0x01, 0xa3,
            0xb6
        ]

        let message: [UInt8] = [0x75, 0x70, 0x20, 0x74, 0x68, 0x65, 0x20, 0x70, 0x75, 0x6e, 0x6b, 0x73]

        let expected: [UInt8] = [
            0xc7, 0x7a, 0x93, 0x51, 0x0c, 0x9c, 0x3f, 0x1e, 0x66, 0xb6, 0x60, 0x5e, 0x97, 0x92, 0x41,
            0x41
        ]

        let encrypted = try sut.QCCAESPadCBCEncrypt(
                key: key,
                initializationVector: initializationVector,
                plaintext: message)
        XCTAssertEqual(encrypted, expected)

        let decrypted = try sut.QCCAESPadCBCDecrypt(
                key: key,
                initializationVector: initializationVector,
                cyphertext: encrypted)
        XCTAssertEqual(decrypted, message)
    }

    func testCBCWithPadDecryptErrorInvalidKey() throws {
        let key: [UInt8] = [
            0xa6, 0x4c, 0x16, 0x14, 0x04, 0xe2, 0x7d, 0x6f, 0x95, 0x74, 0xc6, 0x19, 0x41,
            0x6e, 0x80, 0x4d, 0xc0, 0x86, 0xc2, 0x9d, 0x35, 0x4c, 0x2e, 0xc6, 0xba, 0x55,
            0xe9, 0xab, 0x93, 0x58, 0x1b, 0x17
        ]

        let initializationVector: [UInt8] = [
            0x24, 0x8e, 0xb3, 0xab, 0xf7, 0x1f, 0x5c, 0x40, 0x61, 0xc3, 0x49, 0x2f, 0xfb, 0x01, 0xa3,
            0xb6
        ]

        let message: [UInt8] = [0x75, 0x70, 0x20, 0x74, 0x68, 0x65, 0x20, 0x70, 0x75, 0x6e, 0x6b, 0x73]

        let expected: [UInt8] = [
            0xc7, 0x7a, 0x93, 0x51, 0x0c, 0x9c, 0x3f, 0x1e, 0x66, 0xb6, 0x60, 0x5e, 0x97, 0x92, 0x41,
            0x41
        ]

        let encrypted = try sut.QCCAESPadCBCEncrypt(
                key: key,
                initializationVector: initializationVector,
                plaintext: message)
        XCTAssertEqual(encrypted, expected)

        do {
            let result = try sut.QCCAESPadCBCDecrypt(
                    key: [],
                    initializationVector: initializationVector,
                    cyphertext: encrypted)
            XCTFail("Should be failed: \(result)")
        } catch is CryptoError {
            return
        } catch {
            XCTFail("Wrong error type")
        }
    }

    func testCBCWithPadEncryptCryptoError() throws {
        let key: [UInt8] = [0xa6]

        let initializationVector: [UInt8] = [
            0x24, 0x8e, 0xb3, 0xab, 0xf7, 0x1f, 0x5c, 0x40, 0x61, 0xc3, 0x49, 0x2f, 0xfb, 0x01, 0xa3,
            0xb6
        ]

        let message: [UInt8] = [0x75, 0x70, 0x20, 0x74, 0x68, 0x65, 0x20, 0x70, 0x75, 0x6e, 0x6b, 0x73]

        do {
            let result = try sut.QCCAESPadCBCEncrypt(
                    key: key,
                    initializationVector: initializationVector,
                    plaintext: message)
            XCTFail("Should be failed: \(result)")
        } catch is CryptoError {
            return
        } catch {
            XCTFail("Wrong error type")
        }
    }

    func testIsValidSignature() throws {
        let publicKeyCount = 32
        let dataCount = 64
        let signatureCount = 64
        let publicKey = Data(repeating: 0, count: publicKeyCount)
        let data = Data(repeating: 0, count: dataCount)
        let signature = Data(repeating: 1, count: signatureCount)
        let result = try CryptoService().isValidSignature(signature, for: data, publicKey: publicKey)
        XCTAssertFalse(result)
    }

    func testSignatureForData() throws {
        let privateKeyCount = 32
        let dataCount = 64
        let privateKey = Data(repeating: 0, count: privateKeyCount)
        let data = Data(repeating: 0, count: dataCount)
        let result = try CryptoService().signature(for: data, with: privateKey)
        XCTAssertEqual(result.count, dataCount)
    }
}
