/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use thiserror_no_std::Error;

/// Errors during secret sharing
#[derive(Error, Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub enum Error {
    /// Error when threshold is less than 2
    #[error("Threshold cannot be less than 2")]
    SharingMinThreshold,
    /// Error when limit is less than threshold
    #[error("Limit is less than threshold")]
    SharingLimitLessThanThreshold,
    /// When dealing with fixed size arrays, the caller requested more shares than there is space
    /// or more shares the field supports.
    #[error("Requested more shares than space was provided")]
    InvalidSizeRequest,
    /// Invalid share identifier
    #[error("An invalid share detected")]
    SharingInvalidIdentifier,
    /// Duplicate identifier when combining
    #[error("Duplicate share detected")]
    SharingDuplicateIdentifier,
    /// The maximum number of shares to be made when splitting
    #[error("The maximum number of shares to be made when splitting was reached")]
    SharingMaxRequest,
    /// An invalid share was supplied for verification or combine
    #[error("An invalid share was supplied for verification or combine")]
    InvalidShare,
    /// An invalid generator was supplied for share generation
    #[error("An invalid generator was supplied for share generation")]
    InvalidGenerator,
    /// An invalid secret was supplied for split
    #[error("An invalid secret was supplied for split")]
    InvalidSecret,
    /// A share cannot be converted to a group or field element
    #[error("A share cannot be converted to a group or field element")]
    InvalidShareConversion,
    /// A specific function is not implemented
    #[error("Not implemented")]
    NotImplemented,
}

/// Results returned by this crate
pub type VsssResult<T> = Result<T, Error>;
