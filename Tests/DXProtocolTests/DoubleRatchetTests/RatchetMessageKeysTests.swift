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
//  RatchetMessageKeysTests.swift
//  
//
//  Created by Sergey Basin on 15.08.2023.
//

import Foundation
import XCTest
@testable import DXProtocol

final class RatchetMessageKeysTests: XCTestCase {
    func testInitInvalidChiperKeyDataLength() {
        XCTAssertThrowsError(
                try RatchetMessageKeys(
                        cipherKey: Data([0x00]),
                        macKey: Data(),
                        initializationVector: Data(),
                        index: 0)) { error in
            XCTAssertEqual(error as? DXError, DXError.invalidKeyDataLength("Invalid cipher key length 1"))
        }
    }

    func testInitInvalidMacKeyDataLength() {
        let count = 32
        XCTAssertThrowsError(
                try RatchetMessageKeys(
                        cipherKey: Data(Array(repeating: 0x00, count: count)),
                        macKey: Data([0x00]),
                        initializationVector: Data(),
                        index: 0)) { error in
            XCTAssertEqual(error as? DXError, DXError.invalidKeyDataLength("Invalid mac key length 1"))
        }
    }

    func testInitInvalidIVDataLength() {
        let count = 32
        XCTAssertThrowsError(
                try RatchetMessageKeys(
                        cipherKey: Data(Array(repeating: 0x00, count: count)),
                        macKey: Data(Array(repeating: 0x00, count: count)),
                        initializationVector: Data([0x00]),
                        index: 0)) { error in
            XCTAssertEqual(error as? DXError, DXError.invalidKeyDataLength("Invalid IV length 1"))
        }
    }
}
