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
//! let res = shamir::split_secret::<Scalar, u8, Vec<u8>>(2, 3, *nzs.as_ref(), &mut osrng);
//! assert!(res.is_ok());
//! let shares = res.unwrap();
//! let res = combine_shares(&shares);
//! assert!(res.is_ok());
//! let scalar: Scalar = res.unwrap();
//! let nzs_dup =  NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
//! let sk_dup = SecretKey::from(nzs_dup);
//! assert_eq!(sk_dup.to_bytes(), sk.to_bytes());
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
//! let res = shamir::split_secret::<Scalar, u8, Vec<u8>>(2, 3, secret, &mut osrng);
//! assert!(res.is_ok());
//! let shares = res.unwrap();
//! let res = combine_shares(&shares);
//! assert!(res.is_ok());
//! let scalar: Scalar = res.unwrap();
//! let nzs_dup = NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
//! let sk_dup = SecretKey::from(nzs_dup);
//! assert_eq!(sk_dup.to_bytes(), sk.to_bytes());
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
//! let res = feldman::split_secret::<G1Projective, u8, Vec<u8>>(2, 3, secret, None, &mut rng);
//! assert!(res.is_ok());
//! let (shares, verifier) = res.unwrap();
//! for s in &shares {
//!     assert!(verifier.verify_share(s).is_ok());
//! }
//! let res = combine_shares(&shares);
//! assert!(res.is_ok());
//! let secret_1: Scalar = res.unwrap();
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
//! #[cfg(feature = "curve25519")] {
//! use curve25519_dalek::scalar::Scalar;
//! use rand::Rng;
//! use ed25519_dalek::SigningKey;
//! use vsss_rs::{curve25519::WrappedScalar, *};
//! use x25519_dalek::StaticSecret;
//!
//! let mut osrng = rand::rngs::OsRng::default();
//! let sc = Scalar::hash_from_bytes::<sha2::Sha512>(&osrng.gen::<[u8; 32]>());
//! let sk1 = StaticSecret::from(sc.to_bytes());
//! let ske1 = SigningKey::from_bytes(&sc.to_bytes());
//! let res = shamir::split_secret::<WrappedScalar, u8, Vec<u8>>(2, 3, sc.into(), &mut osrng);
//! assert!(res.is_ok());
//! let shares = res.unwrap();
//! let res = combine_shares(&shares);
//! assert!(res.is_ok());
//! let scalar: WrappedScalar = res.unwrap();
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
#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(test)]
pub(crate) mod tests;

mod error;
pub mod feldman;
pub mod pedersen;
mod polynomial;
mod set;
pub mod shamir;
mod share;
mod util;

use shamir::{check_params, create_shares};
use subtle::*;
use util::*;

pub use error::*;
pub use feldman::Feldman;
pub use pedersen::{Pedersen, PedersenResult};
pub use polynomial::*;
pub use set::*;
pub use shamir::Shamir;
pub use share::*;

#[cfg(any(feature = "alloc", feature = "std"))]
pub use pedersen::StdPedersenResult;

#[cfg(feature = "curve25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "curve25519")))]
pub mod curve25519;

#[cfg(feature = "curve25519")]
pub use curve25519_dalek;
pub use elliptic_curve;
pub use subtle;

/// Create a no-std verifiable secret sharing scheme with size $num using fixed arrays
/// The arguments in order are:
///     The vsss name
///     The name for a pedersen secret sharing scheme result
///     The maximum threshold allowed
///     The maximum number of shares allowed
#[macro_export]
macro_rules! vsss_arr_impl {
    ($name:ident, $result:ident, $max_threshold:expr, $max_shares:expr) => {
        /// No-std verifiable secret sharing scheme with size $num
        pub struct $name<G, I, S>
        where
            G: elliptic_curve::Group + Default,
            I: ShareIdentifier,
            S: Share<Identifier = I>,
        {
            marker: core::marker::PhantomData<(G, I, S)>,
        }

        impl<G: elliptic_curve::Group + Default, I: ShareIdentifier, S: Share<Identifier = I>>
            Shamir<G::Scalar, I, S> for $name<G, I, S>
        {
            type InnerPolynomial = [G::Scalar; $max_threshold];
            type ShareSet = [S; $max_shares];
        }

        impl<G: elliptic_curve::Group + Default, I: ShareIdentifier, S: Share<Identifier = I>>
            Feldman<G, I, S> for $name<G, I, S>
        {
            type VerifierSet = [G; $max_threshold + 1];
        }

        impl<G: elliptic_curve::Group + Default, I: ShareIdentifier, S: Share<Identifier = I>>
            Pedersen<G, I, S> for $name<G, I, S>
        {
            type FeldmanVerifierSet = [G; $max_threshold + 1];
            type PedersenVerifierSet = [G; $max_threshold + 2];
            type PedersenResult = $result<G, I, S>;
        }

        /// The no-std result to use when an allocator is available with size $num
        pub struct $result<G, I, S>
        where
            G: elliptic_curve::Group + Default,
            I: ShareIdentifier,
            S: Share<Identifier = I>,
        {
            blinder: G::Scalar,
            secret_shares: [S; $max_shares],
            blinder_shares: [S; $max_shares],
            feldman_verifier_set: [G; $max_threshold + 1],
            pedersen_verifier_set: [G; $max_threshold + 2],
        }

        impl<G, I, S> PedersenResult<G, I, S> for $result<G, I, S>
        where
            G: elliptic_curve::Group + Default,
            I: ShareIdentifier,
            S: Share<Identifier = I>,
        {
            type ShareSet = [S; $max_shares];
            type FeldmanVerifierSet = [G; $max_threshold + 1];
            type PedersenVerifierSet = [G; $max_threshold + 2];

            fn new(
                blinder: G::Scalar,
                secret_shares: Self::ShareSet,
                blinder_shares: Self::ShareSet,
                feldman_verifier_set: Self::FeldmanVerifierSet,
                pedersen_verifier_set: Self::PedersenVerifierSet,
            ) -> Self {
                Self {
                    blinder,
                    secret_shares,
                    blinder_shares,
                    feldman_verifier_set,
                    pedersen_verifier_set,
                }
            }

            fn blinder(&self) -> G::Scalar {
                self.blinder
            }

            fn secret_shares(&self) -> &Self::ShareSet {
                &self.secret_shares
            }

            fn blinder_shares(&self) -> &Self::ShareSet {
                &self.blinder_shares
            }

            fn feldman_verifier_set(&self) -> &Self::FeldmanVerifierSet {
                &self.feldman_verifier_set
            }

            fn pedersen_verifier_set(&self) -> &Self::PedersenVerifierSet {
                &self.pedersen_verifier_set
            }
        }
    };
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Reconstruct a secret from shares created from split_secret. The X-coordinates operate in F The Y-coordinates operate in F
pub fn combine_shares<
    F: elliptic_curve::PrimeField,
    I: ShareIdentifier,
    S: Share<Identifier = I>,
>(
    shares: &[S],
) -> VsssResult<F> {
    shares.combine_to_field_element::<F, Vec<(F, F)>>()
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Reconstruct a secret from shares created from split_secret. The X-coordinates operate in F The Y-coordinates operate in G
///
/// Exists to support operations like threshold BLS where the shares operate in F but the partial signatures operate in G.
pub fn combine_shares_group<
    G: elliptic_curve::Group + elliptic_curve::group::GroupEncoding + Default,
    I: ShareIdentifier,
    S: Share<Identifier = I>,
>(
    shares: &[S],
) -> VsssResult<G> {
    shares.combine_to_group_element::<G, Vec<(G::Scalar, G)>>()
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Standard verifiable secret sharing scheme
pub struct StdVsss<G, I, S>
where
    G: elliptic_curve::Group + Default,
    I: ShareIdentifier,
    S: Share<Identifier = I>,
{
    _marker: (core::marker::PhantomData<G>, core::marker::PhantomData<S>),
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<G: elliptic_curve::Group + Default, I: ShareIdentifier, S: Share<Identifier = I>>
    Shamir<G::Scalar, I, S> for StdVsss<G, I, S>
{
    type InnerPolynomial = Vec<G::Scalar>;
    type ShareSet = Vec<S>;
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<G: elliptic_curve::Group + Default, I: ShareIdentifier, S: Share<Identifier = I>>
    Feldman<G, I, S> for StdVsss<G, I, S>
{
    type VerifierSet = Vec<G>;
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<G: elliptic_curve::Group + Default, I: ShareIdentifier, S: Share<Identifier = I>>
    Pedersen<G, I, S> for StdVsss<G, I, S>
{
    type FeldmanVerifierSet = Vec<G>;
    type PedersenVerifierSet = Vec<G>;
    type PedersenResult = StdPedersenResult<G, I, S>;
}
