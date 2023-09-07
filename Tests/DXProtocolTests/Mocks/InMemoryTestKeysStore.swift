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
//  InMemoryTestKeysStore.swift
//  DealogXTests
//
//  Created by Mykhailo Bondarenko on 12.07.2023.
//

import Foundation
import DXProtocol

final class InMemoryTestKeysStore: IdentityKeyStorable, PreKeyStorable, SignedPreKeyStorable, SessionStorable {
    private var publicKeys: [ProtocolAddress: IdentityKeyPublic] = [:]
    private var identityKeyPairVar: IdentityKeyPair
    private var registrationId: UUID
    private var prekeyMap: [UUID: OneTimePreKeyPair] = [:]
    private var signedPrekeyMap: [UUID: SignedPreKeyPair] = [:]
    private var sessionMap: [ProtocolAddress: Session] = [:]

    private var isIdentityTrusted: Bool

    init(isIdentityTrusted: Bool = true) throws {
        identityKeyPairVar = try IdentityKeyPair()
        registrationId = UUID()
        self.isIdentityTrusted = isIdentityTrusted
    }

    init(identity: IdentityKeyPair, registrationId: UUID) {
        self.identityKeyPairVar = identity
        self.registrationId = registrationId
        self.isIdentityTrusted = true
    }

    public func identityKeyPair() throws -> IdentityKeyPair {
        return identityKeyPairVar
    }

    public func localRegistrationId() throws -> UUID {
        return registrationId
    }

    // MARK: - IdentityKeyStorable

    public func saveIdentity(_ identity: IdentityKeyPublic,
                             for address: ProtocolAddress) throws -> Bool {
        if publicKeys.updateValue(identity, forKey: address) == nil {
            return false
        } else {
            return true
        }
    }

    public func isTrustedIdentity(_ identity: IdentityKeyPublic,
                                  for address: ProtocolAddress,
                                  direction: DirectionType) throws -> Bool {
        if !isIdentityTrusted {
            return false
        }
        if let key = publicKeys[address] {
            return key.data == identity.data
        } else {
            return true
        }
    }

    public func identity(for address: ProtocolAddress) throws -> IdentityKeyPublic? {
        return publicKeys[address]
    }

    // MARK: - PreKeyStorable

    public func loadPreKey(id: UUID) throws -> OneTimePreKeyPair {
        if let record = prekeyMap[id] {
            return record
        } else {
            throw DXError.invalidKeyIdentifier("no prekey with this identifier")
        }
    }

    public func storePreKey(_ record: OneTimePreKeyPair, id: UUID) throws {
        prekeyMap[id] = record
    }

    public func removePreKey(id: UUID) throws {
        prekeyMap.removeValue(forKey: id)
    }

    func removeAllPreKeys() throws {
        prekeyMap.removeAll()
    }

    // MARK: - SignedPreKeyStorable

    public func loadSignedPreKey(id: UUID) throws -> SignedPreKeyPair {
        if let record = signedPrekeyMap[id] {
            return record
        } else {
            throw DXError.invalidKeyIdentifier("no signed prekey with this identifier")
        }
    }

    public func storeSignedPreKey(_ record: SignedPreKeyPair, id: UUID) throws {
        signedPrekeyMap[id] = record
    }

    func removeSignedPreKey(id: UUID) throws {
        signedPrekeyMap[id] = nil
    }

    func removeAllSignedPreKeys() throws {
        signedPrekeyMap.removeAll()
    }

    // MARK: - SessionStorable

    public func loadSession(for address: ProtocolAddress) throws -> Session? {
        return sessionMap[address]
    }

    public func loadExistingSessions(for addresses: [ProtocolAddress]) throws -> [Session] {
        return try addresses.map { address in
            if let session = sessionMap[address] {
                return session
            }
            throw DXError.sessionNotFound("\(address)")
        }
    }

    public func storeSession(_ record: Session, for address: ProtocolAddress) throws {
        sessionMap[address] = record
    }
}
