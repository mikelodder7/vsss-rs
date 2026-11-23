/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

/// Errors during secret sharing
#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, thiserror::Error)]
pub enum Error {
    /// Error when threshold is less than 2
    #[error("Threshold cannot be less than 2")]
    SharingMinThreshold,
    /// Error when limit is less than threshold
    #[error("Limit is less than threshold")]
    SharingLimitLessThanThreshold,
    /// When dealing with fixed-size arrays, the caller requested more shares than the array can
    /// hold or more shares than the field supports.
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
    /// An invalid share was supplied for verification or combination
    #[error("An invalid share was supplied for verification or combine")]
    InvalidShare,
    /// An invalid generator was supplied for share generation
    #[error("An invalid generator was supplied for share generation: {0}")]
    InvalidGenerator(&'static str),
    /// An invalid secret was supplied for splitting
    #[error("An invalid secret was supplied for split")]
    InvalidSecret,
    /// A share cannot be converted to a group or field element
    #[error("A share cannot be converted to a group or field element")]
    InvalidShareConversion,
    /// A specific function is not implemented
    #[error("Not implemented")]
    NotImplemented,
    /// Invalid share element
    #[error("Invalid share element")]
    InvalidShareElement,
    /// Not enough share identifiers available when creating shares
    #[error("Not enough share identifiers available")]
    NotEnoughShareIdentifiers,
    /// Not enough shares were available when combining from a stream
    #[error("Not enough shares available")]
    NotEnoughShares,
    /// A lattice PVSS operation failed, with the reason
    #[error("Lattice PVSS operation failed: {0}")]
    Lattice(&'static str),
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
            (
                Error::Lattice("bad ciphertext"),
                "Lattice PVSS operation failed: bad ciphertext",
            ),
        ];

        for (error, message) in cases {
            assert_eq!(error.to_string(), message);
        }
    }
}
