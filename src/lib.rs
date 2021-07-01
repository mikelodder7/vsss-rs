/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Verifiable Secret Sharing Schemes are using to split secrets into
//! multiple shares and distribute them among different entities,
//! with the ability to verify if the shares are correct and belong
//! to a specific set. This crate includes Shamir's secret sharing
//! scheme which does not support verification but is more of a
//! building block for the other schemes.
//!
//! This crate supports Feldman and Pedersen verifiable secret sharing
//! schemes.
//!
//! Feldman and Pedersen are similar in many ways. It's hard to describe when to use
//! one over the other. Indeed both are used in
//! <http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.134.6445&rep=rep1&type=pdf>.
//!
//! Feldman reveals the public value of the verifier whereas Pedersen's hides it.
#![no_std]
#![deny(
    missing_docs,
    unused_import_braces,
    unused_qualifications,
    unused_parens,
    unused_lifetimes,
    unconditional_recursion,
    unused_extern_crates,
    trivial_casts,
    trivial_numeric_casts
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(test)]
#[macro_use]
extern crate std;

#[cfg(test)]
mod tests;

#[cfg(feature = "curve25519")]
mod curve25519;
mod error;
mod feldman;
mod pedersen;
mod polynomial;
mod shamir;
mod share;
mod util;
mod verifier;

use polynomial::*;
use util::*;

#[cfg(feature = "curve25519")]
pub use curve25519::*;
pub use error::*;
pub use feldman::*;
pub use pedersen::*;
pub use shamir::*;
pub use share::*;
pub use verifier::*;
