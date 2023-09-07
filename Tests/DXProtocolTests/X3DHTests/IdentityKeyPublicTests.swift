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

final class IdentityKeyPublicTests: XCTestCase {
    func testType() throws {
        let data = Data(count: DXProtocolConstants.curve25519KeyLength)
        let publicKey = try PublicKey(data: data)
        let identityKeyPublic = IdentityKeyPublic(publicKey: publicKey)
        XCTAssertEqual(identityKeyPublic.type, .curve25519)
    }
}
