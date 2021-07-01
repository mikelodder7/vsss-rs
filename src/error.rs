/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
/// Errors during secret sharing
#[derive(Copy, Clone, Debug)]
pub enum Error {
    /// Error when threshold is less than 2
    SharingMinThreshold,
    /// Error when limit is less than threshold
    SharingLimitLessThanThreshold,
    /// Invalid share identifier
    SharingInvalidIdentifier,
    /// Duplicate identifier when combining
    SharingDuplicateIdentifier,
    /// An invalid share was supplied for verification or combine
    InvalidShare,
    /// An invalid secret was supplied for split
    InvalidSecret,
}
