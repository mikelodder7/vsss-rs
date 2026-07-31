/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Verifiable secret sharing schemes are used to split secrets into
//! multiple shares and distribute them among different entities while
//! providing the ability to verify that the shares are correct and belong
//! to a specific set. This crate includes Shamir's secret sharing
//! scheme, which does not support verification but serves as a
//! building block for the other schemes.
//!
//! This crate supports Feldman and Pedersen verifiable secret sharing
//! schemes.
//!
//! Feldman and Pedersen are similar in many ways. It's hard to describe when to use
//! one over the other. Indeed, both are used in
//! [GennaroDKG](https://link.springer.com/article/10.1007/s00145-006-0347-3).
//!
//! Feldman reveals the public value of the verifier, whereas Pedersen hides it.
//!
//! Feldman and Pedersen are different from Shamir when splitting the secret.
//! Combining shares back into the original secret is identical across all methods
//! and is available for each scheme for convenience.
//!
//! This crate is `no_std` compatible and uses const generics to specify sizes.
//!
//! Most applications need no more than 255 shares. That said, this crate does not
//! impose that limit: any number can be requested because identifiers can be any size.
//!
//! Shares are represented as [`ShareElement`]s. A share element can use any
//! suitable representation, but finite fields and groups are the most common,
//! depending on the use case. In the simplest case, the share identifier is the
//! x-coordinate, and the actual share value is the y-coordinate.
//! However, anything can be used as the identifier as long as it implements the
//! [`ShareIdentifier`] trait.
//!
//! Feldman and Pedersen use the [`ShareVerifier`] trait to verify shares.
//!
//! In version 5, many of the required generics were removed and replaced with associated types.
//! This simplified the API, made it easier to use, and reduced the amount of necessary code.
//!
//! To split a P-256 secret using Shamir:
//!
//! ```
//! #[cfg(any(feature = "alloc", feature = "std"))]
//! {
//! use vsss_rs::{*, shamir};
//! use elliptic_curve::{Generate, ff::PrimeField};
//! use p256::{NonZeroScalar, Scalar, SecretKey};
//! use rand::{rngs::StdRng, SeedableRng};
//!
//! type P256Share = DefaultShare<IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>>;
//!
//! let mut osrng = StdRng::from_seed([1u8; 32]);
//! let sk = SecretKey::generate_from_rng(&mut osrng);
//! let nzs = sk.to_nonzero_scalar();
//! let shared_secret = IdentifierPrimeField(*nzs.as_ref());
//! let res = shamir::split_secret::<P256Share>(2, 3, &shared_secret, &mut osrng);
//! assert!(res.is_ok());
//! let shares = res.unwrap();
//! let res = shares.combine();
//! assert!(res.is_ok());
//! let scalar = res.unwrap();
//! let nzs_dup =  NonZeroScalar::from_repr(scalar.0.to_repr()).unwrap();
//! let sk_dup = SecretKey::from(nzs_dup);
//! assert_eq!(sk_dup.to_bytes(), sk.to_bytes());
//! }
//! ```
//!
//! To split a K-256 secret using Shamir:
//!
//! ```
//! #[cfg(any(feature = "alloc", feature = "std"))]
//! {
//! use vsss_rs::{*, shamir};
//! use elliptic_curve::{Generate, ff::PrimeField};
//! use k256::{NonZeroScalar, Scalar, ProjectivePoint, SecretKey};
//! use rand::{rngs::StdRng, SeedableRng};
//!
//! type K256Share = DefaultShare<IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>>;
//!
//! let mut osrng = StdRng::from_seed([2u8; 32]);
//! let sk = SecretKey::generate_from_rng(&mut osrng);
//! let secret = IdentifierPrimeField(*sk.to_nonzero_scalar());
//! let res = shamir::split_secret::<K256Share>(2, 3, &secret, &mut osrng);
//! assert!(res.is_ok());
//! let shares = res.unwrap();
//! let res = shares.combine();
//! assert!(res.is_ok());
//! let scalar = res.unwrap();
//! let nzs_dup = NonZeroScalar::from_repr(scalar.0.to_repr()).unwrap();
//! let sk_dup = SecretKey::from(nzs_dup);
//! assert_eq!(sk_dup.to_bytes(), sk.to_bytes());
//! }
//! ```
//!
//! Feldman and Pedersen return extra information for verification using their respective verifiers.
//!
//! ```
//! #[cfg(any(feature = "alloc", feature = "std"))]
//! {
//! use vsss_rs::{*, feldman};
//! use k256::{ProjectivePoint, Scalar};
//! use elliptic_curve::ff::Field;
//! use rand::{rngs::StdRng, SeedableRng};
//!
//! type K256Share = DefaultShare<IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>>;
//! type K256ShareVerifier = ShareVerifierGroup<ProjectivePoint>;
//!
//! let mut rng = StdRng::from_seed([3u8; 32]);
//! let secret = IdentifierPrimeField(Scalar::random(&mut rng));
//! let res = feldman::split_secret::<K256Share, K256ShareVerifier>(2, 3, &secret, None, &mut rng);
//! assert!(res.is_ok());
//! let (shares, verifier) = res.unwrap();
//! for s in &shares {
//!     assert!(verifier.verify_share(s).is_ok());
//! }
//! let res = shares.combine();
//! assert!(res.is_ok());
//! let secret_1 = res.unwrap();
//! assert_eq!(secret, secret_1);
//! }
//! ```
//!
//! Curve25519-dalek 5.0.0 implements the native `ff` and `group` traits, so its scalar
//! and group types can be used with Shamir, Feldman, and Pedersen.
//!
//! Here is an example using Ed25519 and X25519:
//!
//! ```
//! #[cfg(any(feature = "alloc", feature = "std"))]
//! {
//! use curve25519_dalek::scalar::Scalar;
//! use rand::{RngExt, SeedableRng, rngs::StdRng};
//! use ed25519_dalek::SigningKey;
//! use vsss_rs::*;
//! use x25519_dalek::StaticSecret;
//!
//! type Ed25519Share = DefaultShare<IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>>;
//!
//! let mut osrng = StdRng::from_seed([4u8; 32]);
//! let sc = Scalar::hash_from_bytes::<sha2::Sha512>(&osrng.random::<[u8; 32]>());
//! let sk1 = StaticSecret::from(sc.to_bytes());
//! let ske1 = SigningKey::from_bytes(&sc.to_bytes());
//! let secret = IdentifierPrimeField(sc);
//! let res = shamir::split_secret::<Ed25519Share>(2, 3, &secret, &mut osrng);
//! assert!(res.is_ok());
//! let shares = res.unwrap();
//! let res = shares.combine();
//! assert!(res.is_ok());
//! let scalar = res.unwrap();
//! assert_eq!(scalar.0, sc);
//! let sk2 = StaticSecret::from(scalar.0.to_bytes());
//! let ske2 = SigningKey::from_bytes(&scalar.0.to_bytes());
//! assert_eq!(sk2.to_bytes(), sk1.to_bytes());
//! assert_eq!(ske1.to_bytes(), ske2.to_bytes());
//! }
//! ```
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
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(all(feature = "alloc", not(feature = "std")))]
#[cfg_attr(all(feature = "alloc", not(feature = "std")), macro_use)]
extern crate alloc;

#[cfg(feature = "std")]
#[cfg_attr(feature = "std", macro_use)]
extern crate std;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;
use core::fmt::Debug;
#[cfg(feature = "std")]
use std::vec::Vec;

/// Macros for creating VSSS implementations
#[macro_use]
pub mod macros;
#[cfg(test)]
pub(crate) mod tests;

mod element;
mod error;
pub mod feldman;
mod fixed_array;
#[allow(clippy::suspicious_arithmetic_impl)]
#[allow(clippy::suspicious_op_assign_impl)]
mod gf16;
#[allow(clippy::suspicious_arithmetic_impl)]
#[allow(clippy::suspicious_op_assign_impl)]
mod gf256;
mod numbering;
pub mod pedersen;
mod polynomial;
#[cfg(feature = "primitive")]
mod primitive;
#[cfg(feature = "bigint")]
mod saturating;
mod set;
pub mod shamir;
mod share;
mod util;

use shamir::check_params;
#[allow(unused_imports)]
use subtle::*;

pub use element::*;
pub use error::*;
pub use feldman::Feldman;
pub use fixed_array::*;
pub use gf16::*;
pub use gf256::*;
pub use numbering::*;
pub use pedersen::{Pedersen, PedersenResult};
pub use polynomial::*;
#[cfg(feature = "primitive")]
pub use primitive::*;
#[cfg(feature = "bigint")]
pub use saturating::*;
pub use set::*;
pub use shamir::Shamir;
pub use share::*;
pub use util::*;

#[cfg(any(feature = "alloc", feature = "std"))]
pub use pedersen::StdPedersenResult;

#[cfg(feature = "curve")]
pub use elliptic_curve;
#[cfg(feature = "curve")]
use elliptic_curve::Group;

pub use subtle;

pub(crate) const USIZE_BYTES: usize = size_of::<usize>();
pub(crate) const ISIZE_BYTES: usize = size_of::<isize>();

/// A share whose identifier and value are elements of the same prime field.
#[cfg(feature = "curve")]
pub type PrimeFieldShare<F> = DefaultShare<IdentifierPrimeField<F>, ValuePrimeField<F>>;

/// A share whose identifier is a group scalar and whose value is a group element.
#[cfg(feature = "curve")]
pub type GroupShare<G> = DefaultShare<IdentifierPrimeField<<G as Group>::Scalar>, ValueGroup<G>>;

#[cfg(any(feature = "alloc", feature = "std"))]
/// Standard Shamir secret sharing scheme.
pub type StdShamir<S> = Vec<S>;

#[cfg(any(feature = "alloc", feature = "std"))]
/// Standard Feldman verifiable secret sharing scheme.
pub type StdFeldman<S, V> = StdVsss<S, V>;

#[cfg(any(feature = "alloc", feature = "std"))]
/// Standard Pedersen verifiable secret sharing scheme.
pub type StdPedersen<S, V> = StdVsss<S, V>;

#[cfg(any(feature = "alloc", feature = "std"))]
/// Standard verifiable secret sharing scheme.
pub struct StdVsss<S, V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    _marker: (core::marker::PhantomData<V>, core::marker::PhantomData<S>),
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S, V> Shamir<S> for StdVsss<S, V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    type InnerPolynomial = Vec<S>;
    type ShareSet = Vec<S>;
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S, V> Feldman<S, V> for StdVsss<S, V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    type VerifierSet = Vec<V>;
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S, V> Pedersen<S, V> for StdVsss<S, V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    type FeldmanVerifierSet = Vec<V>;
    type PedersenVerifierSet = Vec<V>;
    type PedersenResult = StdPedersenResult<S, V>;
}
