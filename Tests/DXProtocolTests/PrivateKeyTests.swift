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
//  SessionTests.swift
//  DealogXTests
//
//  Created by Mykhailo Bondarenko on 11.07.2023.
//

import XCTest

@testable import DXProtocol

final class PrivateKeyTests: XCTestCase {
    func testCodable() throws {
        let data = Data(count: DXProtocolConstants.curve25519KeyLength)
        let privateKey = try PrivateKey(data: data, type: .curve25519)
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        let encodedData = try encoder.encode(privateKey)
        let decodedPrivate = try decoder.decode(PrivateKey.self, from: encodedData)
        XCTAssertEqual(privateKey.data, decodedPrivate.data)
        XCTAssertEqual(privateKey.type, decodedPrivate.type)
    }

    func testPrivateKeyInvalidKeyData() throws {
        let data = Data()
        XCTAssertThrowsError(try PrivateKey(data: data)) { error in
            XCTAssertEqual(error as? DXError, DXError.invalidKeyDataLength("Invalid key length: 0"))
        }
    }
}
