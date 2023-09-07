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
//  RatchetChainKey.swift
//  DealogX
//
//  Created by Andriy Vasyk on 07.12.2022.
//

import Foundation

/// Initialises a ratchet chain key with the components
struct RatchetChainKey: Codable {
    /// The seed which is used to calculate input material for deriving of the message keys
    static let messageKeysSeed = Data([0x01])

    /// The seed which is used to calculate input material for deriving of the chain keys
    static let chainKeySeed = Data([0x02])

    /// The raw data of this chain key
    let data: Data

    /// The current index of this key in chain
    let index: UInt32

    // MARK: - Interface

    /// Returns an instance of `RatchetMessageKeys` containing keys for encryption/decryption
    /// - Returns: A message keys for encryption/decryption
    /// - Throws: Throws if the operation failed to be performed.
    func messageKeys() throws -> RatchetMessageKeys {
        let material = self.calculateBaseMaterial(seed: Self.messageKeysSeed)
        return try RatchetMessageKeys.deriveKeys(inputKeyMaterial: material, index: self.index)
    }

    /// Returns next chain key `RatchetChainKey`
    /// - Returns: The next chain key `RatchetChainKey`
    func nextChainKey() -> Self {
        let key = self.calculateBaseMaterial(seed: Self.chainKeySeed)
        return Self(data: key, index: self.index + 1)
    }

    // MARK: - Private

    /// Calculates the SHA256 HMAC for the seed.
    /// - Parameter seed: The input for calculation of base material
    /// - Returns: The HMAC of the seed with the key
    private func calculateBaseMaterial(seed: Data) -> Data {
        let rawKey = self.data
        return CryptoService.shared.hmacSHA256(for: seed, with: rawKey)
    }
}
