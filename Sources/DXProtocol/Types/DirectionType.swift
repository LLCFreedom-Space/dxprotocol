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
//  DirectionType.swift
//  DealogX
//
//  Created by Andriy Vasyk on 23.12.2022.
//

import Foundation

/// A generic `DirectionType` type that is used to specify direction of protocol run
public enum DirectionType {
    /// Specifies that protocol is running for outgoing messages
    case sending
    /// Specifies that protocol is running for incoming messages
    case receiving
}
