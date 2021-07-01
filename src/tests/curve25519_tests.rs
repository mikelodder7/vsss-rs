/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use super::invalid::*;
use super::valid::*;
use crate::{Shamir, WrappedPoint, WrappedScalar};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SecretKey;
use rand::rngs::OsRng;
use x25519_dalek::StaticSecret;

#[test]
fn invalid_tests() {
    split_invalid_args::<WrappedScalar, WrappedPoint, 33>();
    combine_invalid::<WrappedScalar, 33>();
}

#[test]
fn valid_tests() {
    combine_single::<WrappedScalar, WrappedPoint, 33>();
    combine_all::<WrappedScalar, WrappedPoint, 33>();
}

#[test]
fn key_tests() {
    let mut osrng = rand::rngs::OsRng::default();
    let sc = Scalar::random(&mut osrng);
    let sk1 = StaticSecret::from(sc.to_bytes());
    let ske1 = SecretKey::from_bytes(&sc.to_bytes()).unwrap();
    let res = Shamir::<2, 3>::split_secret::<WrappedScalar, OsRng, 33>(sc.into(), &mut osrng);
    assert!(res.is_ok());
    let shares = res.unwrap();
    let res = Shamir::<2, 3>::combine_shares::<WrappedScalar, 33>(&shares);
    assert!(res.is_ok());
    let scalar = res.unwrap();
    assert_eq!(scalar.0, sc);
    let sk2 = StaticSecret::from(scalar.0.to_bytes());
    let ske2 = SecretKey::from_bytes(&scalar.0.to_bytes()).unwrap();
    assert_eq!(sk2.to_bytes(), sk1.to_bytes());
    assert_eq!(ske1.to_bytes(), ske2.to_bytes());
}
