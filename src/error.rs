/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use core::fmt::{self, Display, Formatter};
use core2::error::Error as StdError;

/// Errors during secret sharing
#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub enum Error {
    /// Error when threshold is less than 2
    SharingMinThreshold,
    /// Error when limit is less than threshold
    SharingLimitLessThanThreshold,
    /// Invalid share identifier
    SharingInvalidIdentifier,
    /// Duplicate identifier when combining
    SharingDuplicateIdentifier,
    /// The maximum number of shares to be made when splitting
    SharingMaxRequest,
    /// An invalid share was supplied for verification or combine
    InvalidShare,
    /// An invalid secret was supplied for split
    InvalidSecret,
    /// A share cannot be converted to a group or field element
    InvalidShareConversion,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::SharingMinThreshold => write!(f, "Threshold cannot be less than 2"),
            Self::SharingLimitLessThanThreshold => write!(f, "Limit is less than threshold"),
            Self::SharingInvalidIdentifier => write!(f, "An invalid share detected"),
            Self::SharingDuplicateIdentifier => write!(f, "Duplicate share detected"),
            Self::SharingMaxRequest => write!(
                f,
                "The maximum number of shares to be made when splitting was reached"
            ),
            Self::InvalidShare => write!(
                f,
                "An invalid share was supplied for verification or combine"
            ),
            Self::InvalidSecret => write!(f, "An invalid secret was supplied for split"),
            Self::InvalidShareConversion => {
                write!(f, "A share cannot be converted to a group or field element")
            }
        }
    }
}

impl StdError for Error {}
