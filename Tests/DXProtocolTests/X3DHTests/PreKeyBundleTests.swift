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

final class PreKeyBundleTests: XCTestCase {
    func testDecode() throws {
        let data = Data(count: DXProtocolConstants.curve25519KeyLength)
        let publicKey = try PublicKey(data: data)
        let oneTimePreKeyPublic = OneTimePreKeyPublic(id: UUID(), publicKey: publicKey)
        let identityKeyPublic = IdentityKeyPublic(publicKey: publicKey)
        let signingKeyPublic = SigningKeyPublic(publicKey: publicKey)
        let signedPreKeyPublic = SignedPreKeyPublic(publicKey: publicKey, signature: data)
        let preKeyBundle = PreKeyBundle(
                identityKey: identityKeyPublic,
                signingKey: signingKeyPublic,
                registrationId: UUID(),
                deviceId: UUID(),
                signedPreKey: signedPreKeyPublic,
                oneTimePreKey: oneTimePreKeyPublic
        )
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        let encodedData = try encoder.encode(preKeyBundle)
        let decodedPreKeyBundle = try decoder.decode(PreKeyBundle.self, from: encodedData)
        XCTAssertEqual(preKeyBundle.identityKey, decodedPreKeyBundle.identityKey)
        XCTAssertEqual(preKeyBundle.signingKey, decodedPreKeyBundle.signingKey)
        XCTAssertEqual(preKeyBundle.registrationId, decodedPreKeyBundle.registrationId)
        XCTAssertEqual(preKeyBundle.deviceId, decodedPreKeyBundle.deviceId)
    }
}
