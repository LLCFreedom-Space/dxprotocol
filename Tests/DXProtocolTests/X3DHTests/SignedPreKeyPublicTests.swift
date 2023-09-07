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
//  CryptoErrorTests.swift
//  DealogXTests
//
//  Created by Mykhailo Bondarenko on 11.07.2023.
//

import XCTest

@testable import DXProtocol

final class SignedPreKeyPublicTests: XCTestCase {
    func testInit() throws {
        let id = UUID()
        let dataCount = DXProtocolConstants.curve25519KeyLength
        let signatureCount = 64
        let publicKey = try PublicKey(data: Data(count: dataCount), type: .curve25519)
        let signature = Data(repeating: 1, count: signatureCount)
        let sut = SignedPreKeyPublic(
                id: id,
                publicKey: publicKey,
                signature: signature
        )
        XCTAssertEqual(sut.id, id)
        XCTAssertEqual(sut.publicKey, publicKey)
        XCTAssertEqual(sut.type, CryptoType.curve25519)
        XCTAssertEqual(sut.data, Data(count: dataCount))
        XCTAssertEqual(sut.signature, Data(repeating: 1, count: signatureCount))
    }

    func testInitFromSignedPreKeyPair() throws {
        let id = UUID()
        let dataCount = DXProtocolConstants.curve25519KeyLength
        let signatureCount = 64
        let publicKey = try PublicKey(data: Data(count: dataCount), type: .curve25519)
        let privateKey = try PrivateKey(data: Data(count: dataCount), type: .curve25519)
        let signature = Data(repeating: 1, count: signatureCount)
        let signedPreKeyPair = SignedPreKeyPair(
                id: id,
                date: Date(),
                publicKey: publicKey,
                privateKey: privateKey,
                signature: signature
        )

        let sut = SignedPreKeyPublic(signedPreKeyPair: signedPreKeyPair)
        XCTAssertEqual(sut.id, id)
        XCTAssertEqual(sut.publicKey, publicKey)
        XCTAssertEqual(sut.type, .curve25519)
        XCTAssertEqual(sut.data, Data(count: dataCount))
        XCTAssertEqual(sut.signature, signature)
    }

    func testSignedPreKeyPublicEncodingDecoding() throws {
        let id = UUID()
        let signatureCount = 64
        let signatureData = Data(repeating: 1, count: signatureCount)
        let data = Data(count: DXProtocolConstants.curve25519KeyLength)
        let publicKey = try PublicKey(data: data, type: .curve25519)
        let encodablePublicKey = SignedPreKeyPublic(
                id: id,
                publicKey: publicKey,
                signature: signatureData
        )
        let encodedData = try JSONEncoder().encode(encodablePublicKey)
        let signedPreKeyPublic = try JSONDecoder().decode(SignedPreKeyPublic.self, from: encodedData)
        XCTAssertEqual(signedPreKeyPublic.id, id)
        XCTAssertEqual(signedPreKeyPublic.publicKey, publicKey)
        XCTAssertEqual(signedPreKeyPublic.signature, signatureData)
    }

    func testFailedDecode() throws {
        let jsonString = """
                         {
                             "client_key_id": "\(UUID())",
                             "key": {
                                 "type": "curve25519",
                                 "data": "GGs1m/yRPJGclkk/fVtQ6YCO54Wi5I7i1amr4W/GODA="
                             },
                             "signature": "\(UUID())"
                         }
                         """
        guard let jsonData = jsonString.data(using: .utf8) else {
            XCTFail("JSON should decode")
            return
        }

        XCTAssertThrowsError(try JSONDecoder().decode(SignedPreKeyPublic.self, from: jsonData)) { error in
            XCTAssertEqual(
                    error as? DXError, DXError.invalidKeyData("Failed to decode public pre key signature"))
        }
    }
}
