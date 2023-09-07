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
//  CipherMetadataTests.swift
//  DealogXTests
//
//  Created by Mykhailo Bondarenko on 09.07.2023.
//

import CryptoKit
import Foundation
import XCTest

@testable import DXProtocol

final class CipherMetadataTests: XCTestCase {
    func testInitSymmetricKey() {
        let size = 256
        let count = 32
        let key = SymmetricKey(size: .bits256)
        let macKey = SymmetricKey(size: .bits256)
        let digest = SHA256.hash(data: Data())
        let metaData = CipherMetadata(key: key, macKey: macKey, digest: digest)
        XCTAssertNotNil(key)
        XCTAssertEqual(key.bitCount, size)
        XCTAssertEqual(macKey.bitCount, size)
        XCTAssertEqual(metaData.key.count, count)
        XCTAssertEqual(metaData.macKey.count, count)
        XCTAssertEqual(metaData.digest.count, count)
    }

    func testInitData() {
        let count = 32
        let keyData = Data(count: count)
        let macKeyData = Data(count: count)
        let digestData = Data(count: count)
        let metaData = CipherMetadata(key: keyData, macKey: macKeyData, digest: digestData)
        XCTAssertEqual(keyData.count, count)
        XCTAssertEqual(macKeyData.count, count)
        XCTAssertEqual(metaData.key.count, count)
        XCTAssertEqual(metaData.macKey.count, count)
        XCTAssertEqual(metaData.digest.count, count)
    }

    func testInitEncoder() throws {
        let count = 32
        let keyData = Data(count: count)
        let macKeyData = Data(count: count)
        let digestData = Data(count: count)

        let metaData = CipherMetadata(key: keyData, macKey: macKeyData, digest: digestData)

        let jsonEncoder = JSONEncoder()
        let jsonData = try jsonEncoder.encode(metaData)
        XCTAssertNotNil(jsonData)
    }

    func testInitDecoder() throws {
        let count = 32
        let keyData = Data(count: count)
        let macKeyData = Data(count: count)
        let digestData = Data(count: count)
        let metadata = CipherMetadata(key: keyData, macKey: macKeyData, digest: digestData)
        let jsonEncoder = JSONEncoder()
        let jsonData = try jsonEncoder.encode(metadata)
        let jsonDecoder = JSONDecoder()
        let metaData = try jsonDecoder.decode(CipherMetadata.self, from: jsonData)
        XCTAssertEqual(metaData.key, keyData)
        XCTAssertEqual(metaData.macKey, macKeyData)
        XCTAssertEqual(metaData.digest, digestData)
    }

    func testInvalidKeyLength() throws {
        let failedCount = 123
        let count = 32
        let keyData = Data(count: failedCount)
        let macKeyData = Data(count: count)
        let digestData = Data(count: count)
        let metadata = CipherMetadata(key: keyData, macKey: macKeyData, digest: digestData)
        let jsonEncoder = JSONEncoder()
        let jsonData = try jsonEncoder.encode(metadata)
        let jsonDecoder = JSONDecoder()
        XCTAssertThrowsError(try jsonDecoder.decode(CipherMetadata.self, from: jsonData)) { error in
            if case DXError.invalidKeyDataLength(let message) = error {
                XCTAssertTrue(message.contains("123"))
            }
        }
    }

    func testInvalidMacKeyLength() throws {
        let failedCount = 123
        let count = 32
        let keyData = Data(count: count)
        let macKeyData = Data(count: failedCount)
        let digestData = Data(count: count)
        let metadata = CipherMetadata(key: keyData, macKey: macKeyData, digest: digestData)
        let jsonEncoder = JSONEncoder()
        let jsonData = try jsonEncoder.encode(metadata)
        let jsonDecoder = JSONDecoder()
        XCTAssertThrowsError(try jsonDecoder.decode(CipherMetadata.self, from: jsonData)) { error in
            if case DXError.invalidKeyDataLength(let message) = error {
                XCTAssertTrue(message.contains("123"))
            }
        }
    }

    func testCodingKeys() {
        let keys = CipherMetadata.Keys.self
        XCTAssertEqual(keys.key, .key)
        XCTAssertEqual(keys.macKey, .macKey)
        XCTAssertEqual(keys.digest, .digest)
    }
}
