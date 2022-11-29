// Copyright Michael Lodder. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
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
//! use ff::PrimeField;
//! use p256::{NonZeroScalar, Scalar, SecretKey};
//! use rand::rngs::OsRng;
//! use vsss_rs::Shamir;
//!
//! let mut osrng = OsRng::default();
//! let sk = SecretKey::random(&mut osrng);
//! let nzs = sk.to_nonzero_scalar();
//! // 32 for field size, 1 for identifier = 33
//! let res = Shamir { t: 2, n: 3 }.split_secret::<Scalar, OsRng>(*nzs.as_ref(), &mut osrng);
//! assert!(res.is_ok());
//! let shares = res.unwrap();
//! let res = Shamir { t: 2, n: 3 }.combine_shares::<Scalar>(&shares);
//! assert!(res.is_ok());
//! let scalar = res.unwrap();
//! let nzs_dup = NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
//! let sk_dup = SecretKey::from(nzs_dup);
//! assert_eq!(sk_dup.to_be_bytes(), sk.to_be_bytes());
//! ```
//!
//! To split a k256 secret using Shamir
//!
//! ```
//! use ff::PrimeField;
//! use k256::{NonZeroScalar, SecretKey};
//! use rand::rngs::OsRng;
//! use vsss_rs::{secp256k1::WrappedScalar, Shamir};
//!
//! let mut osrng = OsRng::default();
//! let sk = SecretKey::random(&mut osrng);
//! let secret = WrappedScalar(*sk.to_nonzero_scalar());
//! let res = Shamir { t: 2, n: 3 }.split_secret::<WrappedScalar, OsRng>(secret, &mut osrng);
//! assert!(res.is_ok());
//! let shares = res.unwrap();
//! let res = Shamir { t: 2, n: 3 }.combine_shares::<WrappedScalar>(&shares);
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
//! use bls12_381_plus::{G1Projective, Scalar};
//! use ff::Field;
//! use rand::rngs::OsRng;
//! use vsss_rs::Feldman;
//!
//! let mut rng = OsRng::default();
//! let secret = Scalar::random(&mut rng);
//! let res =
//!     Feldman { t: 2, n: 3 }.split_secret::<Scalar, G1Projective, OsRng>(secret, None, &mut rng);
//! assert!(res.is_ok());
//! let (shares, verifier) = res.unwrap();
//! for s in &shares {
//!     assert!(verifier.verify(s));
//! }
//! let res = Feldman { t: 2, n: 3 }.combine_shares::<Scalar>(&shares);
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
//! use rand::rngs::OsRng;
//! use rand_7::rngs::OsRng as OsRng_7;
//! use vsss_rs::{curve25519::WrappedScalar, Shamir};
//! use x25519_dalek::StaticSecret;
//!
//! let mut osrng = rand::rngs::OsRng::default();
//! let sc = Scalar::random(&mut OsRng_7);
//! let sk1 = StaticSecret::from(sc.to_bytes());
//! let ske1 = SecretKey::from_bytes(&sc.to_bytes()).unwrap();
//! let res = Shamir { t: 2, n: 3 }.split_secret::<WrappedScalar, OsRng>(sc.into(), &mut osrng);
//! assert!(res.is_ok());
//! let shares = res.unwrap();
//! let res = Shamir { t: 2, n: 3 }.combine_shares::<WrappedScalar>(&shares);
//! assert!(res.is_ok());
//! let scalar = res.unwrap();
//! assert_eq!(scalar.0, sc);
//! let sk2 = StaticSecret::from(scalar.0.to_bytes());
//! let ske2 = SecretKey::from_bytes(&scalar.0.to_bytes()).unwrap();
//! assert_eq!(sk2.to_bytes(), sk1.to_bytes());
//! assert_eq!(ske1.to_bytes(), ske2.to_bytes());
//! ```
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

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

mod lib {
    #[cfg(all(feature = "alloc", not(feature = "std")))]
    pub use alloc::collections::BTreeSet;
    #[cfg(all(feature = "alloc", not(feature = "std")))]
    pub use alloc::vec::Vec;
    #[cfg(feature = "std")]
    pub use std::collections::BTreeSet;
    #[cfg(feature = "std")]
    pub use std::vec::Vec;
}

#[cfg(test)]
mod tests;

#[cfg(feature = "curve25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "curve25519")))]
pub mod curve25519;
mod error;
#[cfg(all(not(feature = "std"), not(feature = "alloc")))]
mod no_std;
#[cfg(feature = "secp256k1")]
#[cfg_attr(docsrs, doc(cfg(feature = "secp256k1")))]
pub mod secp256k1;
#[cfg(any(feature = "std", feature = "alloc"))]
mod standard;
mod util;

pub use error::*;
#[cfg(all(not(feature = "std"), not(feature = "alloc")))]
pub use no_std::*;
#[cfg(any(feature = "std", feature = "alloc"))]
pub use standard::*;
use util::*;

/// Use shamir split regardless of no-std or std used
#[macro_export]
macro_rules! shamir_split {
    ($threshold:expr, $limit:expr, $secret:expr, $rng:expr) => {
        #[cfg(all(not(feature = "std"), not(feature = "alloc")))]
        Shamir::<$threshold, $limit>::split_secret($secret, $rng)
        #[cfg(any(feature = "std", feature = "alloc"))]
        Shamir::split_secret($secret, $rng, $threshold, $limit)
    };
}
