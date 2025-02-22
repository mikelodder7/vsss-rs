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
//! one over the other. Indeed, both are used in
//! [GennaroDKG](https://link.springer.com/article/10.1007/s00145-006-0347-3).
//!
//! Feldman reveals the public value of the verifier whereas Pedersen's hides it.
//!
//! Feldman and Pedersen are different from Shamir when splitting the secret.
//! Combining shares back into the original secret is identical across all methods
//! and is available for each scheme for convenience.
//!
//! This crate is no-standard compliant and uses const generics to specify sizes.
//!
//! This crate supports any number as the maximum number of shares to be requested.
//! Anything higher than 255 is pretty ridiculous but if such a use case exists please let me know.
//! This said, any number of shares can be requested since identifiers can be any size.
//!
//! Shares are represented as [`ShareElement`]s. Shares can be represented by
//! really but is most commonly finite fields or groups
//! depending on the use case. In the simplest case,
//! the share identifier is the x-coordinate
//! and the actual value of the share the y-coordinate.
//! However, anything can be used as the identifier as long as it implements the
//! [`ShareIdentifier`] trait.
//!
//! Feldman and Pedersen use the [`ShareVerifier`] trait to verify shares.
//!
//! In version 5, many of the required generics were removed and replaced with associated types.
//! This simplifies the API and makes it easier to use and reduced the amount of necessary code.
//!
//! To split a p256 secret using Shamir
//!
//! ```
//! #[cfg(any(feature = "alloc", feature = "std"))]
//! {
//! use vsss_rs::{*, shamir};
//! use elliptic_curve::ff::PrimeField;
//! use p256::{NonZeroScalar, Scalar, SecretKey};
//!
//! type P256Share = DefaultShare<IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>>;
//!
//! let mut osrng = rand_core::OsRng::default();
//! let sk = SecretKey::random(&mut osrng);
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
//! To split a k256 secret using Shamir
//!
//! ```
//! #[cfg(any(feature = "alloc", feature = "std"))]
//! {
//! use vsss_rs::{*, shamir};
//! use elliptic_curve::ff::PrimeField;
//! use k256::{NonZeroScalar, Scalar, ProjectivePoint, SecretKey};
//!
//! type K256Share = DefaultShare<IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>>;
//!
//! let mut osrng = rand_core::OsRng::default();
//! let sk = SecretKey::random(&mut osrng);
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
//! Feldman or Pedersen return extra information for verification using their respective verifiers
//!
//! ```
//! #[cfg(any(feature = "alloc", feature = "std"))]
//! {
//! use vsss_rs::{*, feldman};
//! use bls12_381_plus::{Scalar, G1Projective};
//! use elliptic_curve::ff::Field;
//!
//! type BlsShare = DefaultShare<IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>>;
//! type BlsShareVerifier = ShareVerifierGroup<G1Projective>;
//!
//! let mut rng = rand_core::OsRng::default();
//! let secret = IdentifierPrimeField(Scalar::random(&mut rng));
//! let res = feldman::split_secret::<BlsShare, BlsShareVerifier>(2, 3, &secret, None, &mut rng);
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
//! Curve25519 is not a prime field but this crate does support it using
//! `features=["curve25519"]` which is enabled by default. This feature
//! wraps curve25519-dalek libraries so they can be used with Shamir, Feldman, and Pedersen.
//!
//! Here's an example of using Ed25519 and x25519
//!
//! ```
//! #[cfg(all(feature = "curve25519", any(feature = "alloc", feature = "std")))] {
//! use curve25519_dalek::scalar::Scalar;
//! use rand::Rng;
//! use ed25519_dalek::SigningKey;
//! use vsss_rs::{curve25519::WrappedScalar, *};
//! use x25519_dalek::StaticSecret;
//!
//! type Ed25519Share = DefaultShare<IdentifierPrimeField<WrappedScalar>, IdentifierPrimeField<WrappedScalar>>;
//!
//! let mut osrng = rand::rngs::OsRng::default();
//! let sc = Scalar::hash_from_bytes::<sha2::Sha512>(&osrng.gen::<[u8; 32]>());
//! let sk1 = StaticSecret::from(sc.to_bytes());
//! let ske1 = SigningKey::from_bytes(&sc.to_bytes());
//! let secret = IdentifierPrimeField(WrappedScalar(sc));
//! let res = shamir::split_secret::<Ed25519Share>(2, 3, &secret, &mut osrng);
//! assert!(res.is_ok());
//! let shares = res.unwrap();
//! let res = shares.combine();
//! assert!(res.is_ok());
//! let scalar = res.unwrap();
//! assert_eq!(scalar.0.0, sc);
//! let sk2 = StaticSecret::from(scalar.0.0.to_bytes());
//! let ske2 = SigningKey::from_bytes(&scalar.0.0.to_bytes());
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
use alloc::{boxed::Box, vec::Vec};
use core::fmt::Debug;
#[cfg(feature = "std")]
use std::{boxed::Box, vec::Vec};

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
use subtle::*;

pub use element::*;
pub use error::*;
pub use feldman::Feldman;
pub use fixed_array::*;
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

#[cfg(feature = "curve25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "curve25519")))]
pub mod curve25519;

//
#[cfg(feature = "curve25519")]
pub use curve25519_dalek;
pub use elliptic_curve;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::Group;

pub use subtle;

pub(crate) const USIZE_BYTES: usize = size_of::<usize>();
pub(crate) const ISIZE_BYTES: usize = size_of::<isize>();

#[cfg(any(feature = "alloc", feature = "std"))]
/// Standard verifiable secret sharing scheme
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
