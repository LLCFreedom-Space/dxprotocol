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
//  Created by Mykhailo Bondarenko on 10.07.2023.
//

import XCTest

@testable import DXProtocol

final class CryptoErrorTests: XCTestCase {
    let code: Int = 102

    func testCryptoErrorInit() {
        let cryptoError = CryptoError.init(code: code)
        // swiftlint: disable numbers_smell
        XCTAssertEqual(cryptoError.code, 102)
        // swiftlint: enable numbers_smell
    }

    func testCryptoErrorDigestMismatch() {
        let cryptoError = CryptoError.digestMismatch
        // swiftlint: disable numbers_smell
        XCTAssertEqual(cryptoError.code, 101)
        // swiftlint: enable numbers_smell
    }

    func testCryptoErrorInvalidAuthenticationCode() {
        let cryptoError = CryptoError.invalidAuthenticationCode
        // swiftlint: disable numbers_smell
        XCTAssertEqual(cryptoError.code, 102)
        // swiftlint: enable numbers_smell
    }

    func testCryptoErrorInvalidInputFileData() {
        let cryptoError = CryptoError.invalidInputFileData
        // swiftlint: disable numbers_smell
        XCTAssertEqual(cryptoError.code, 103)
        // swiftlint: enable numbers_smell
    }
}
