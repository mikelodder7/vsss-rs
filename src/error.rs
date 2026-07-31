/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use core::fmt::{self, Display, Formatter};

/// Errors during secret sharing
#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub enum Error {
    /// Error when threshold is less than 2
    SharingMinThreshold,
    /// Error when limit is less than threshold
    SharingLimitLessThanThreshold,
    /// When dealing with fixed-size arrays, the caller requested more shares than the array can
    /// hold or more shares than the field supports.
    InvalidSizeRequest,
    /// Invalid share identifier
    SharingInvalidIdentifier,
    /// Duplicate identifier when combining
    SharingDuplicateIdentifier,
    /// The maximum number of shares to be made when splitting
    SharingMaxRequest,
    /// An invalid share was supplied for verification or combination
    InvalidShare,
    /// An invalid generator was supplied for share generation
    InvalidGenerator(&'static str),
    /// An invalid secret was supplied for splitting
    InvalidSecret,
    /// A share cannot be converted to a group or field element
    InvalidShareConversion,
    /// A specific function is not implemented
    NotImplemented,
    /// Invalid share element
    InvalidShareElement,
    /// Not enough share identifiers available when creating shares
    NotEnoughShareIdentifiers,
    /// Not enough shares were available when combining from a stream
    NotEnoughShares,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::SharingMinThreshold => write!(f, "Threshold cannot be less than 2"),
            Error::SharingLimitLessThanThreshold => write!(f, "Limit is less than threshold"),
            Error::InvalidSizeRequest => write!(f, "Requested more shares than space was provided"),
            Error::SharingInvalidIdentifier => write!(f, "An invalid share detected"),
            Error::SharingDuplicateIdentifier => write!(f, "Duplicate share detected"),
            Error::SharingMaxRequest => write!(
                f,
                "The maximum number of shares to be made when splitting was reached"
            ),
            Error::InvalidShare => write!(
                f,
                "An invalid share was supplied for verification or combine"
            ),
            Error::InvalidGenerator(s) => write!(
                f,
                "An invalid generator was supplied for share generation: {}",
                s
            ),
            Error::InvalidSecret => write!(f, "An invalid secret was supplied for split"),
            Error::InvalidShareConversion => {
                write!(f, "A share cannot be converted to a group or field element")
            }
            Error::NotImplemented => write!(f, "Not implemented"),
            Error::InvalidShareElement => write!(f, "Invalid share element"),
            Error::NotEnoughShareIdentifiers => write!(f, "Not enough share identifiers available"),
            Error::NotEnoughShares => write!(f, "Not enough shares available"),
        }
    }
}

/// Results returned by this crate
pub type VsssResult<T> = Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;
    use std::string::ToString;

    #[test]
    fn display_messages_cover_all_error_variants() {
        let cases = [
            (
                Error::SharingMinThreshold,
                "Threshold cannot be less than 2",
            ),
            (
                Error::SharingLimitLessThanThreshold,
                "Limit is less than threshold",
            ),
            (
                Error::InvalidSizeRequest,
                "Requested more shares than space was provided",
            ),
            (Error::SharingInvalidIdentifier, "An invalid share detected"),
            (
                Error::SharingDuplicateIdentifier,
                "Duplicate share detected",
            ),
            (
                Error::SharingMaxRequest,
                "The maximum number of shares to be made when splitting was reached",
            ),
            (
                Error::InvalidShare,
                "An invalid share was supplied for verification or combine",
            ),
            (
                Error::InvalidGenerator("empty list"),
                "An invalid generator was supplied for share generation: empty list",
            ),
            (
                Error::InvalidSecret,
                "An invalid secret was supplied for split",
            ),
            (
                Error::InvalidShareConversion,
                "A share cannot be converted to a group or field element",
            ),
            (Error::NotImplemented, "Not implemented"),
            (Error::InvalidShareElement, "Invalid share element"),
            (
                Error::NotEnoughShareIdentifiers,
                "Not enough share identifiers available",
            ),
            (Error::NotEnoughShares, "Not enough shares available"),
        ];

        for (error, message) in cases {
            assert_eq!(error.to_string(), message);
        }
    }
}
