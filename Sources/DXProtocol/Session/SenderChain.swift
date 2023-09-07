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
//  SenderChain.swift
//  DealogX
//
//  Created by Andriy Vasyk on 07.12.2022.
//

import Foundation

/// The chain of keys which is used to calculate `RatchetMessageKeys` for encryption of messages for sending
final class SenderChain: Codable {
    /// The current sender ratchet key pair
    let ratchetKeyPair: KeyPair

    /// The current chain key of the ratchet step
    var chainKey: RatchetChainKey

    /// Initialises a sender chain from the components
    /// - Parameter ratchetKeyPair: The key pair of the ratchet
    /// - Parameter chainKey: The current chain key of the ratchet
    init(ratchetKeyPair: KeyPair, chainKey: RatchetChainKey) {
        self.ratchetKeyPair = ratchetKeyPair
        self.chainKey = chainKey
    }
}
