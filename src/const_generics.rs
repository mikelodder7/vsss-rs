//! A const generic implementation when the stack space is even more controlled
//! but the interfaces are not exactly compatible with the other versions
pub mod feldman;
pub mod pedersen;
mod polynomial;
pub mod shamir;
mod share;
mod verifier;

pub use polynomial::Polynomial;
pub use shamir::{combine_shares, combine_shares_group};
pub use share::Share;
pub use verifier::*;
