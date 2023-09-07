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
//  PublicKeyTests.swift
//  DealogXTests
//
//  Created by Mykhailo Bondarenko on 10.07.2023.
//

import XCTest

@testable import DXProtocol

final class PublicKeyTests: XCTestCase {
    func testPublicKeyEquatable() {
        let data = Data(count: DXProtocolConstants.curve25519KeyLength)
        let publicKey = try? PublicKey(data: data)
        let publicKey2 = try? PublicKey(data: data)
        XCTAssertEqual(publicKey, publicKey2)
    }

    func testPublicKeyDecodeSuccess() throws {
        let data = Data(count: DXProtocolConstants.curve25519KeyLength)
        let publicKey = try? PublicKey(data: data)
        guard let encodablePublicKey = publicKey else {
            XCTFail("Unable to create PublicKey")
            return
        }
        let encodedData = try JSONEncoder().encode(encodablePublicKey)
        let decodedPublicKey = try JSONDecoder().decode(PublicKey.self, from: encodedData)
        XCTAssertEqual(publicKey, decodedPublicKey)
    }

    func testPublicKeyCodableFailureData() throws {
        let data = Data()
        XCTAssertThrowsError(try PublicKey(data: data)) { error in
            XCTAssertEqual(error as? DXError, DXError.invalidKeyDataLength("Invalid key length: 0"))
        }
    }

    func testDecodingPublicKeyWithLongDataThrowsError() throws {
        guard
                let encodedKey = """
                                 {
                                     "data":"",
                                     "type":"curve25519"
                                 }
                                 """.data(using: .utf8)
        else {
            XCTFail("Unable to create PublicKey")
            return
        }

        XCTAssertThrowsError(try JSONDecoder().decode(PublicKey.self, from: encodedKey)) { error in
            XCTAssertEqual(error as? DXError, DXError.invalidKeyDataLength("Invalid key length: 0"))
        }
    }

    func testDecodingPublicKeyWithWrongTypeThrowsError() throws {
        guard
                let encodedKey = """
                                 {
                                     "data":"GGs1m/yRPJGclkk/fVtQ6YCO54Wi5I7i1amr4W/GODA=",
                                     "type":"p512"
                                 }
                                 """.data(using: .utf8)
        else {
            XCTFail("Unable to create PublicKey")
            return
        }

        XCTAssertThrowsError(try JSONDecoder().decode(PublicKey.self, from: encodedKey)) { error in
            XCTAssertEqual(error as? DXError, DXError.invalidType("Invalid key type"))
        }
    }

    func testFailedDecodingPublicKey() throws {
        guard
                let encodedKey = """
                                 {
                                     "data":"GGs1m/yRPJGclkk/fVtQ6YCO54Wi5I7iamr4W/GODA=",
                                     "type":"p512"
                                 }
                                 """.data(using: .utf8)
        else {
            XCTFail("Unable to create PublicKey")
            return
        }

        XCTAssertThrowsError(try JSONDecoder().decode(PublicKey.self, from: encodedKey)) { error in
            XCTAssertEqual(error as? DXError, DXError.invalidKeyData("Failed to decode public pre key"))
        }
    }
}
