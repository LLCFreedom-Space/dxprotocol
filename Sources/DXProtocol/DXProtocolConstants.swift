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
//  DXProtocolConstants.swift
//  DealogX
//
//  Created by Mykhailo Bondarenko on 15.12.2022.
//

import Foundation

/// Constants of the protocol
public enum DXProtocolConstants {
    /// The maximum number of one-time pre keys
    public static let oneTimePreKeysLimit = 100

    /// We generate `oneTimePreKeysLimit` one-time pre keys at a time.
    /// We should replenish whenever ~2/3 of them have been consumed
    public static let oneTimePreKeysMinCount = 35

    /// The size of the Curve25519 key
    static let curve25519KeyLength = 32

    /// The length of the MAC key (in bytes)
    static let macKeyLength = 32

    /// The current version of message structure
    static let cipertextMessageCurrentVersion: UInt8 = 1

    /// The maximum number of archived session states
    static let archivedStatesMaxLength = 40

    /// The maximum number of message keys that should be stored
    static let messageKeyMaximum = 2000

    static let maxReceiverChains = 5

    static let futureMessagesLimit: UInt32 = 2000

    /// The length of cipher keys (in bytes)
    static let cipherKeyLength = 32

    /// The length of the initialisation vector (in bytes)
    static let ivLength = 16

    /// The length of the MAC (in bytes)
    static let macLength = 8

    /// The size of the chunk to be used when encrypting files or other BLOBs (in bytes)
    public static let chunkSize = 1024 * 1024

    /// The size of code produced by Hash-based message authentication algorithm with hash SHA256 (in bytes)
    public static let hmac256Length = 32

    /// The time interval between two successful checks of one-time pre keys (in seconds)
    public static let oneTimePreKeysCheckInterval: TimeInterval = 12 * 3600

    /// The maximum number of failures while updating signed pre key before it will became necessary to take some drastic steps.
    /// For example run signed pre key update on each attempt to send message
    public static let signedPreKeyUpdateMaxFailureCount = 5

    /// The maximum amount of time that can elapse without updating signed pre key before it will became necessary to take some drastic steps.
    /// For example run signed pre key update on each attempt to send message (in seconds)
    public static let signedPreKeyUpdateMaxFailureDuration: TimeInterval = 10 * 24 * 3600

    /// The time interval to be elapsed after successful enrolling of current signed pre key
    /// and before next update (in seconds)
    public static let signedPreKeyUpdateInterval: TimeInterval = 2 * 24 * 3600

    /// The time interval to be elapsed after successful enrolling of non-current signed pre key
    /// and before allowing to delete this pre key
    public static let signedPreKeyDeletionInterval: TimeInterval = 30 * 24 * 3600

    /// The time interval to be elapsed after successful enrolling of one-time pre key
    /// and before allowing to delete this pre key
    public static let oneTimePreKeyDeletionInterval: TimeInterval = 30 * 24 * 3600
}
