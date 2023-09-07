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

final class SigningKeyPublicTests: XCTestCase {
    func testSigningKeyPublicEquatable() throws {
        let data = Data(count: DXProtocolConstants.curve25519KeyLength)
        let publicKey = try PublicKey(data: data)
        let key = SigningKeyPublic(publicKey: publicKey)
        let key2 = SigningKeyPublic(publicKey: publicKey)
        XCTAssertEqual(key, key2)
    }

    func testVerifySignatureInvalidKeyType() throws {
        let keyData = Data(count: DXProtocolConstants.curve25519KeyLength)
        let signature = Data(count: DXProtocolConstants.curve25519KeyLength)
        let digest = Data(count: DXProtocolConstants.curve25519KeyLength)
        let publicKey = try PublicKey(data: keyData, type: .p512)
        let signingKeyPublic = SigningKeyPublic(publicKey: publicKey)
        XCTAssertThrowsError(try signingKeyPublic.verifySignature(signature, for: digest)) { error in
            XCTAssertNotNil(error)
            XCTAssertEqual(
                    error as? DXError, DXError.invalidKey("Currently only Curve25519 keys are supported"))
        }
    }
}
