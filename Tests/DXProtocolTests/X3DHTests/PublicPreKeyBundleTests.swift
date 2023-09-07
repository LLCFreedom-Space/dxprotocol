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
//  PublicPreKeyBundleTests.swift
//  
//
//  Created by Sergey Basin on 16.08.2023.
//
import Foundation
import XCTest
@testable import DXProtocol

final class PublicPreKeyBundleTests: XCTestCase {
    func testInit() throws {
        let publicKey = try PublicKey(data: Data(UUID().uuidString.dropLast(4).utf8))
        let identityKey = IdentityKeyPublic(publicKey: publicKey)
        let signingKey = SigningKeyPublic(publicKey: publicKey)
        let signedPreKey = SignedPreKeyPublic(publicKey: publicKey, signature: Data())
        let oneTimePreKeys = [
            OneTimePreKeyPublic(publicKey: publicKey),
            OneTimePreKeyPublic(publicKey: publicKey)
        ]
        let publicPreKeysBundle = PublicPreKeysBundle(
                identityKey: identityKey,
                signingKey: signingKey,
                signedPreKey: signedPreKey,
                oneTimePreKeys: oneTimePreKeys
        )
        XCTAssertEqual(publicPreKeysBundle.identityKey, identityKey)
        XCTAssertEqual(publicPreKeysBundle.signingKey, signingKey)
        XCTAssertEqual(publicPreKeysBundle.signedPreKey.id, signedPreKey.id)
        XCTAssertEqual(publicPreKeysBundle.oneTimePreKeys[0].id, oneTimePreKeys[0].id)
        XCTAssertEqual(publicPreKeysBundle.oneTimePreKeys.count, oneTimePreKeys.count)
    }

    func testCoding() throws {
        let publicKey = try PublicKey(data: Data(UUID().uuidString.dropLast(4).utf8))
        let identityKey = IdentityKeyPublic(publicKey: publicKey)
        let signingKey = SigningKeyPublic(publicKey: publicKey)
        let signedPreKey = SignedPreKeyPublic(publicKey: publicKey, signature: Data())
        let oneTimePreKeys = [
            OneTimePreKeyPublic(publicKey: publicKey),
            OneTimePreKeyPublic(publicKey: publicKey)
        ]
        let publicPreKeysBundle = PublicPreKeysBundle(
                identityKey: identityKey,
                signingKey: signingKey,
                signedPreKey: signedPreKey,
                oneTimePreKeys: oneTimePreKeys
        )
        let encoder = JSONEncoder()
        let data = try encoder.encode(publicPreKeysBundle)
        let decoder = JSONDecoder()
        let decodedPublicPreKeysBundle = try decoder.decode(PublicPreKeysBundle.self, from: data)
        XCTAssertEqual(publicPreKeysBundle.identityKey, decodedPublicPreKeysBundle.identityKey)
        XCTAssertEqual(publicPreKeysBundle.oneTimePreKeys[0].id, decodedPublicPreKeysBundle.oneTimePreKeys[0].id)
        XCTAssertEqual(publicPreKeysBundle.oneTimePreKeys.count, decodedPublicPreKeysBundle.oneTimePreKeys.count)
        XCTAssertEqual(publicPreKeysBundle.signedPreKey.id, decodedPublicPreKeysBundle.signedPreKey.id)
        XCTAssertEqual(publicPreKeysBundle.signingKey, decodedPublicPreKeysBundle.signingKey)
    }
}
