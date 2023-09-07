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
//  ReceiverChain.swift
//  DealogX
//
//  Created by Andriy Vasyk on 07.12.2022.
//

import Foundation

/// The chain of keys which is used to calculate message keys for the received messages
final class ReceiverChain: Codable {
    /// The current receiver ratchet key
    let ratchetKey: PublicKey

    /// The current receiver chain key
    private(set) var chainKey: RatchetChainKey

    /// The stored message keys for out-of-order messages
    private(set) var messageKeys: [RatchetMessageKeys]

    /// Initialises a receiver chain from the components.
    /// - Parameter ratchetKey: The current receiver ratchet key
    /// - Parameter chainKey: The current receiver chain key
    /// - Parameter messageKeys: The list of message keys
    init(ratchetKey: PublicKey, chainKey: RatchetChainKey, messageKeys: [RatchetMessageKeys] = []) {
        self.ratchetKey = ratchetKey
        self.chainKey = chainKey
        self.messageKeys = messageKeys
    }

    // MARK: - Interface

    /// Adds new message keys at the beginning of the list.
    /// - Parameter keys: The message keys to be added
    func pushMessageKeys(_ keys: RatchetMessageKeys) {
        self.messageKeys.insert(keys, at: 0)

        let limit = DXProtocolConstants.messageKeyMaximum
        if self.messageKeys.count > limit {
            _ = self.messageKeys.popLast()
        }
    }

    /// Removes keys `RatchetMessageKeys` with specified counter
    /// - Parameter counter: The message counter in the chain
    /// - Returns: The message keys, if they exist
    func removeMessageKeys(with counter: UInt32) -> RatchetMessageKeys? {
        var result: RatchetMessageKeys?

        if let index = self.messageKeys.firstIndex(where: { $0.index == counter }) {
            result = self.messageKeys.remove(at: index)
        }
        return result
    }
}
