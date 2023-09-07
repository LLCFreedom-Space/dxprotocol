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
//  ProtocolAddress.swift
//  DealogX
//
//  Created by Andriy Vasyk on 06.12.2022.
//

import Foundation

/// `ProtocolAddress` represents the all necessary information allowing to identify the receiver user
public struct ProtocolAddress {
    /// Registration identifier of remote user
    public let userId: UUID

    /// Identifier of the device used by remote user
    public let deviceId: UUID

    /// Initialises new address for remote
    /// - Parameter userId: Registration identifier of remote user we want to send message to
    /// - Parameter deviceId: Identifier of the device used by remote user
    public init(userId: UUID, deviceId: UUID) {
        self.userId = userId
        self.deviceId = deviceId
    }
}

extension ProtocolAddress: Hashable {
    /// Hashes the `ProtocolAddress` instance.
    ///
    /// - Parameter hasher: The hasher to use.
    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.userId)
        hasher.combine(self.deviceId)
    }
}

extension ProtocolAddress: Equatable {
    /// Conform `ProtocolAddress` to `Equatable` protocol
    /// - Parameters:
    ///   - lhs: `ProtocolAddress`
    ///   - rhs: `ProtocolAddress`
    /// - Returns: `Bool`
    public static func == (lhs: ProtocolAddress, rhs: ProtocolAddress) -> Bool {
        if lhs.deviceId != rhs.deviceId {
            return false
        }
        return lhs.userId == rhs.userId
    }
}
