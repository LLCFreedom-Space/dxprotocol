// DXProtocol
// Copyright (C) 2022  FREEDOM SPACE, LLC

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
//  RatchetRootKey.swift
//  DealogX
//
//  Created by Andriy Vasyk on 07.12.2022.
//

import Foundation

/// A Root Key is stored by both parties
/// and is updated on every ratchet step using the DH result and the previous Root Key.
/// The Key used to derive new sender and receiver chain keys.
/// Shared secret (output from X3DH) is the initial root key.
/// Initialises a new root key from raw data
struct RatchetRootKey: Codable {
    /// The raw data of this root key
    let data: Data

    // MARK: - Interfaces

    /// Creates a new root key and chain key.
    /// - Parameter theirRatchetKey: The ratchet key from the remote user.
    /// - Parameter ourRatchetKey: The our local ratchet key
    /// - Throws: Throws if the operation failed to be performed.
    /// - Returns: A tuple of the root key and chain key
    func createChain(theirRatchetKey: PublicKey,
                     ourRatchetKey: PrivateKey) throws -> (RatchetRootKey, RatchetChainKey) {
        let material = try ourRatchetKey.calculateKeyAgreement(with: theirRatchetKey)
        let info = "DXRatchet"
        let infoData = Data(info.utf8)

        let outputByteCount = DXProtocolConstants.curve25519KeyLength * 2
        let bytes = CryptoService.shared.deriveKey(
                inputKeyMaterial: material,
                salt: self.data,
                info: infoData,
                outputByteCount: outputByteCount)

        let rootKeyData = bytes[0 ..< DXProtocolConstants.curve25519KeyLength]
        let chainKeyData = bytes[DXProtocolConstants.curve25519KeyLength ..< outputByteCount]

        return (RatchetRootKey(data: rootKeyData), RatchetChainKey(data: chainKeyData, index: 0))
    }

    /// The "root KDF" to calculate a new root key (RK) and sending chain key (CK)
    /// Creates the first root key and chain key from the secret.
    /// - Parameter secret: The input (X3DH output) for the KDF
    /// - Throws: Throws if the operation failed to be performed.
    /// - Returns: A tuple of the root key and chain key
    static func createChainFrom(secret: Data) throws -> (rootKey: RatchetRootKey,
                                                         chainKey: RatchetChainKey) {
        let info = "DXText"
        let infoData = Data(info.utf8)

        let outputByteCount = DXProtocolConstants.curve25519KeyLength * 2
        let derived = CryptoService.shared.deriveKey(
                inputKeyMaterial: secret,
                info: infoData,
                outputByteCount: outputByteCount)

        // The first half is used as the input for the next KDF calculation.
        // The second half is used for calculation of the message keys
        let rootKeyData = derived[0 ..< DXProtocolConstants.curve25519KeyLength]
        let chainKeyData = derived[DXProtocolConstants.curve25519KeyLength ..< outputByteCount]

        return (RatchetRootKey(data: rootKeyData), RatchetChainKey(data: chainKeyData, index: 0))
    }
}
