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
//  CryptoError.swift
//  DealogX
//
//  Created by Andriy Vasyk on 27.12.2022.
//

import Foundation
import CommonCrypto

/// Crypto Error
public struct CryptoError: Error {
    /// The underlying `CCCryptorStatus` code that represents the error
    var code: CCCryptorStatus
}

extension CryptoError {
    /// Represents the error code for a digest mismatch
    public static var digestMismatch: CryptoError {
        let code = 101
        return .init(code: code)
    }

    /// Represents the error code for an invalid authentication code
    public static var invalidAuthenticationCode: CryptoError {
        let code = 102
        return .init(code: code)
    }

    /// Represents the error code for invalid input file data
    public static var invalidInputFileData: CryptoError {
        let code = 103
        return .init(code: code)
    }

    /// The initializer that takes an `Int` as the error code
    public init(code: Int) {
        self.init(code: CCCryptorStatus(code))
    }
}
