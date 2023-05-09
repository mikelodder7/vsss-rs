/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::invalid::*;
use super::valid::*;
use crate::tests::standard::ScalarShare;
use crate::*;
use elliptic_curve::ff::PrimeField;
use k256::{NonZeroScalar, ProjectivePoint, Scalar, SecretKey};
use rand::rngs::OsRng;

#[test]
fn invalid_tests() {
    split_invalid_args::<ProjectivePoint>();
    combine_invalid::<Scalar>();
}

#[test]
fn valid_tests() {
    combine_single::<ProjectivePoint>();
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn valid_std_tests() {
    combine_all::<ProjectivePoint>();
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn key_tests() {
    let mut osrng = OsRng::default();
    let sk = SecretKey::random(&mut osrng);
    let secret = *sk.to_nonzero_scalar();
    let res = shamir::split_secret::<Scalar, u8, ScalarShare>(2, 3, secret, &mut osrng);
    assert!(res.is_ok());
    let shares = res.unwrap();
    let res = combine_shares(&shares);
    assert!(res.is_ok());
    let scalar: Scalar = res.unwrap();
    let nzs_dup = NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
    let sk_dup = SecretKey::from(nzs_dup);
    assert_eq!(sk_dup.to_bytes(), sk.to_bytes());
}
