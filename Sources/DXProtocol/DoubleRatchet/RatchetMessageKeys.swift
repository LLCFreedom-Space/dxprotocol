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
//  RatchetMessageKeys.swift
//  DealogX
//
//  Created by Andriy Vasyk on 07.12.2022.
//

import Foundation

/// The `RatchetMessageKeys` struct represents a set of keys used to encrypt and decrypt messages
struct RatchetMessageKeys: Codable {
    /// The cipher key for encrypting/decrypting messages
    let cipherKey: Data

    /// The mac key of a message
    let macKey: Data

    /// The initialization vector aka. nonce
    let initializationVector: Data

    /// The index of the message
    var index: UInt32

    /// Initializes instance of message keys with components
    /// - Parameter cipherKey: The cipher key
    /// - Parameter macKey: The mac key
    /// - Parameter initializationVector: The initialization vector
    /// - Parameter index: The index of the message
    /// - Throws: `DXError` of type `invalidKeyDataLength`, if the key data is invalid
    init(cipherKey: Data, macKey: Data, initializationVector: Data, index: UInt32) throws {
        guard cipherKey.count == DXProtocolConstants.cipherKeyLength else {
            throw DXError.invalidKeyDataLength("Invalid cipher key length \(cipherKey.count)")
        }

        guard macKey.count == DXProtocolConstants.macKeyLength else {
            throw DXError.invalidKeyDataLength("Invalid mac key length \(macKey.count)")
        }

        guard initializationVector.count == DXProtocolConstants.ivLength else {
            throw DXError.invalidKeyDataLength("Invalid IV length \(initializationVector.count)")
        }

        self.cipherKey = cipherKey
        self.macKey = macKey
        self.initializationVector = initializationVector
        self.index = index
    }

    // MARK: - Interface

    /// Creates a new instance of `RatchetMessageKeys` containing keys for encryption/decryption
    /// - Parameter inputKeyMaterial: The ratchet key from the remote user
    /// - Parameter index: The our local ratchet key
    /// - Throws: Throws if the operation failed to be performed
    /// - Returns: A message keys for encryption/decryption
    static func deriveKeys(inputKeyMaterial: Data, index: UInt32) throws -> RatchetMessageKeys {
        let info = "DXMessageKeys"
        let infoData = Data(info.utf8)

        let outputByteCount = DXProtocolConstants.cipherKeyLength + DXProtocolConstants.macKeyLength + DXProtocolConstants.ivLength
        let derived = CryptoService.shared.deriveKey(
                inputKeyMaterial: inputKeyMaterial,
                info: infoData,
                outputByteCount: outputByteCount)

        // 32 bytes or 256 bits(kCCKeySizeAES256)
        let cipherKeyRange = 0 ..< DXProtocolConstants.cipherKeyLength
        let cipherKey = derived[cipherKeyRange]

        let macKeyRange = DXProtocolConstants.cipherKeyLength ..< DXProtocolConstants.cipherKeyLength + DXProtocolConstants.macKeyLength
        let macKey = derived[macKeyRange]

        // 16 bytes or 128 bits(kCCBlockSizeAES128)
        let initializationVectorRange = DXProtocolConstants.cipherKeyLength + DXProtocolConstants.macKeyLength ..< derived.count
        let initializationVector = derived[initializationVectorRange]

        return try RatchetMessageKeys(
                cipherKey: cipherKey,
                macKey: macKey,
                initializationVector: initializationVector,
                index: index)
    }
}
