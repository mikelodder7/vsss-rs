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
//!
//! Feldman and Pedersen are different from Shamir when splitting the secret.
//! Combining shares back into the original secret is identical across all methods
//! and is available for each scheme for convenience.
//!
//! This crate is no-standard compliant and uses const generics to specify sizes.
//!
//! This crate supports 255 as the maximum number of shares to be requested.
//! Anything higher is pretty ridiculous but if such a use case exists please let me know.
//!
//! Shares are represented as byte arrays. Shares can represent finite fields or groups
//! depending on the use case. The first byte is reserved for the share identifier (x-coordinate)
//! and everything else is the actual value of the share (y-coordinate).
//!
//! When specifying share sizes, use the field size in bytes + 1 for the identifier.
//!
//! To split a p256 secret using Shamir
//!
//! ```
//! use vsss_rs::{*, shamir};
//! use elliptic_curve::ff::PrimeField;
//! use p256::{NonZeroScalar, Scalar, SecretKey};
//!
//! let mut osrng = rand_core::OsRng::default();
//! let sk = SecretKey::random(&mut osrng);
//! let nzs = sk.to_nonzero_scalar();
//! let res = shamir::split_secret::<Scalar, _>(2, 3, *nzs.as_ref(), &mut osrng);
//! assert!(res.is_ok());
//! let shares = res.unwrap();
//! let res = combine_shares::<Scalar>(&shares);
//! assert!(res.is_ok());
//! let scalar = res.unwrap();
//! let nzs_dup =  NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
//! let sk_dup = SecretKey::from(nzs_dup);
//! assert_eq!(sk_dup.to_be_bytes(), sk.to_be_bytes());
//! ```
//!
//! To split a k256 secret using Shamir
//!
//! ```
//! use vsss_rs::{*, shamir};
//! use elliptic_curve::ff::PrimeField;
//! use k256::{NonZeroScalar, Scalar, ProjectivePoint, SecretKey};
//!
//! let mut osrng = rand_core::OsRng::default();
//! let sk = SecretKey::random(&mut osrng);
//! let secret = *sk.to_nonzero_scalar();
//! let res = shamir::split_secret::<Scalar, _>(2, 3, secret, &mut osrng);
//! assert!(res.is_ok());
//! let shares = res.unwrap();
//! let res = combine_shares::<Scalar>(&shares);
//! assert!(res.is_ok());
//! let scalar = res.unwrap();
//! let nzs_dup = NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
//! let sk_dup = SecretKey::from(nzs_dup);
//! assert_eq!(sk_dup.to_be_bytes(), sk.to_be_bytes());
//! ```
//!
//! Feldman or Pedersen return extra information for verification using their respective verifiers
//!
//! ```
//! use vsss_rs::{*, feldman};
//! use bls12_381_plus::{Scalar, G1Projective};
//! use elliptic_curve::ff::Field;
//!
//! let mut rng = rand_core::OsRng::default();
//! let secret = Scalar::random(&mut rng);
//! let res = feldman::split_secret::<Scalar, G1Projective, _>(2, 3, secret, None, &mut rng);
//! assert!(res.is_ok());
//! let (shares, verifier) = res.unwrap();
//! for s in &shares {
//!     assert!(verifier.verify(s).is_ok());
//! }
//! let res = combine_shares::<Scalar>(&shares);
//! assert!(res.is_ok());
//! let secret_1 = res.unwrap();
//! assert_eq!(secret, secret_1);
//! ```
//!
//! Curve25519 is not a prime field but this crate does support it using
//! `features=["curve25519"]` which is enabled by default. This feature
//! wraps curve25519-dalek libraries so they can be used with Shamir, Feldman, and Pedersen.
//!
//! Here's an example of using Ed25519 and x25519
//!
//! ```
//! use curve25519_dalek::scalar::Scalar;
//! use ed25519_dalek::SecretKey;
//! use vsss_rs::{curve25519::WrappedScalar, *};
//! use x25519_dalek::StaticSecret;
//!
//! let mut osrng_7 = rand_7::rngs::OsRng::default();
//! let mut osrng_8 = rand::rngs::OsRng::default();
//! let sc = Scalar::random(&mut osrng_7);
//! let sk1 = StaticSecret::from(sc.to_bytes());
//! let ske1 = SecretKey::from_bytes(&sc.to_bytes()).unwrap();
//! let res = shamir::split_secret::<WrappedScalar, _>(2, 3, sc.into(), &mut osrng_8);
//! assert!(res.is_ok());
//! let shares = res.unwrap();
//! let res = combine_shares::<WrappedScalar>(&shares);
//! assert!(res.is_ok());
//! let scalar = res.unwrap();
//! assert_eq!(scalar.0, sc);
//! let sk2 = StaticSecret::from(scalar.0.to_bytes());
//! let ske2 = SecretKey::from_bytes(&scalar.0.to_bytes()).unwrap();
//! assert_eq!(sk2.to_bytes(), sk1.to_bytes());
//! assert_eq!(ske1.to_bytes(), ske2.to_bytes());
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
#![cfg_attr(feature = "nightly", generic_const_exprs)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
#[cfg_attr(feature = "std", macro_use)]
extern crate std;

#[cfg(test)]
mod tests;

mod error;
pub mod feldman;
pub mod pedersen;
mod polynomial;
pub mod shamir;
mod share;
mod util;
mod verifier;

use heapless::Vec;
use shamir::*;
use util::*;

pub use error::*;
pub use pedersen::PedersenResult;
pub use polynomial::*;
pub use shamir::{combine_shares, combine_shares_group};
pub use share::*;
pub use verifier::*;

#[cfg(feature = "curve25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "curve25519")))]
pub mod curve25519;
#[cfg(feature = "curve25519")]
pub use curve25519_dalek;
pub use elliptic_curve;
pub use heapless;
#[cfg(feature = "secp256k1")]
pub use k256;
#[cfg(feature = "curve25519")]
pub use sha2;
#[cfg(any(feature = "secp256k1", feature = "curve25519"))]
pub use subtle;
