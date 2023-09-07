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
//  PendingPreKey.swift
//  DealogX
//
//  Created by Andriy Vasyk on 07.12.2022.
//

import Foundation

/// Represents info about keys which was used to send PreKeyMessage,
/// until the message is received and confirmed by the remote user
struct PendingPreKey: Codable {
    /// The identifier of the one-time pre key, if it was used
    var oneTimePreKeyId: UUID?

    /// The identifier of the signed pre key
    var signedPreKeyId: UUID

    /// The base key used for the encrypting pre key message
    var baseKeyPublic: PublicKey
}
