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
//  ProtocolAddressTests.swift
//  DealogXTests
//
//  Created by Mykhailo Bondarenko on 10.07.2023.
//

import XCTest

@testable import DXProtocol

final class ProtocolAddressTests: XCTestCase {
    func testInitAddress() {
        let userId = UUID()
        let deviceId = UUID()
        let sut = ProtocolAddress(userId: userId, deviceId: deviceId)
        XCTAssertEqual(sut.userId, userId)
        XCTAssertEqual(sut.deviceId, deviceId)
    }

    func testTrueForEqualAddresses() {
        let userId = UUID()
        let deviceId = UUID()
        let first = ProtocolAddress(userId: userId, deviceId: deviceId)
        let second = ProtocolAddress(userId: userId, deviceId: deviceId)
        XCTAssertEqual(first, second)
    }

    func testFalseForDifferentDevices() {
        let userId = UUID()
        let first = ProtocolAddress(userId: userId, deviceId: UUID())
        let second = ProtocolAddress(userId: userId, deviceId: UUID())
        XCTAssertNotEqual(first, second)
    }

    func testHash() {
        let userId = UUID()
        let deviceId = UUID()
        let first = ProtocolAddress(userId: userId, deviceId: deviceId)
        let second = ProtocolAddress(userId: userId, deviceId: deviceId)

        XCTAssertEqual(first.hashValue, second.hashValue)
    }
}
