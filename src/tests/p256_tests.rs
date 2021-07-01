/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::invalid::*;
use super::valid::*;
use crate::Shamir;
use ff::PrimeField;
use p256::{NonZeroScalar, ProjectivePoint, Scalar, SecretKey};
use rand::rngs::OsRng;

#[test]
fn invalid_tests() {
    split_invalid_args::<Scalar, ProjectivePoint, 33>();
    combine_invalid::<Scalar, 33>();
}

#[test]
fn valid_tests() {
    combine_single::<Scalar, ProjectivePoint, 33>();
    combine_all::<Scalar, ProjectivePoint, 33>();
}

#[test]
fn key_tests() {
    let mut osrng = OsRng::default();
    let sk = SecretKey::random(&mut osrng);
    let nzs = sk.to_secret_scalar();
    let res = Shamir::<2, 3>::split_secret::<Scalar, OsRng, 33>(*nzs.as_ref(), &mut osrng);
    assert!(res.is_ok());
    let shares = res.unwrap();
    let res = Shamir::<2, 3>::combine_shares::<Scalar, 33>(&shares);
    assert!(res.is_ok());
    let scalar = res.unwrap();
    let nzs_dup = NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
    let sk_dup = SecretKey::from(nzs_dup);
    assert_eq!(sk_dup.to_bytes(), sk.to_bytes());
}
