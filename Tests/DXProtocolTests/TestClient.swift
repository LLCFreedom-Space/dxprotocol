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
//  TestClient.swift
//  DealogXTests
//
//  Created by Mykhailo Bondarenko on 11.07.2023.
//

import Foundation
import DXProtocol

/// Can be used to represent the protocol state held by a remote client.
/// i.e. someone who's sending messages to the local client.
struct TestClient {
    var userId: UUID
    var sessionStore: SessionStorable { return store }
    var preKeyStore: PreKeyStorable { return store }
    var signedPreKeyStore: SignedPreKeyStorable { return store }
    var identityKeyStore: IdentityKeyStorable { return store }

    let store: InMemoryTestKeysStore
    var deviceId = UUID()

    init(userId: UUID, isClientIdentityTrusted: Bool = true) throws {
        self.userId = userId
        self.store = try InMemoryTestKeysStore(isIdentityTrusted: isClientIdentityTrusted)
    }

    init(userId: UUID, identityKeyPair: IdentityKeyPair) throws {
        self.userId = userId
        self.store = InMemoryTestKeysStore(identity: identityKeyPair, registrationId: userId)
    }

    var protocolAddress: ProtocolAddress {
        return ProtocolAddress(userId: self.userId, deviceId: deviceId)
    }
}
