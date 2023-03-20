/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::super::{combine_shares, feldman, shamir, FeldmanVerifier};
use super::invalid::*;
use super::valid::*;
use super::SHARE_SIZE;
use elliptic_curve::ff::PrimeField;
use k256::{NonZeroScalar, ProjectivePoint, Scalar, SecretKey};
use rand::rngs::OsRng;

#[test]
fn invalid_tests() {
    split_invalid_args::<Scalar, ProjectivePoint>();
    combine_invalid::<Scalar, SHARE_SIZE>();
}

#[test]
fn valid_tests() {
    combine_single::<Scalar, ProjectivePoint, SHARE_SIZE>();
    combine_all::<Scalar, ProjectivePoint, SHARE_SIZE>();
}

#[test]
fn key_tests() {
    let mut osrng = OsRng::default();
    let sk = SecretKey::random(&mut osrng);
    let secret = *sk.to_nonzero_scalar();
    let res = shamir::split_secret::<Scalar, _, 2, 3, SHARE_SIZE>(secret, &mut osrng);
    assert!(res.is_ok());
    let shares = res.unwrap();
    let res = combine_shares::<Scalar, SHARE_SIZE>(&shares);
    assert!(res.is_ok());
    let scalar = res.unwrap();
    let nzs_dup = NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
    let sk_dup = SecretKey::from(nzs_dup);
    assert_eq!(sk_dup.to_bytes(), sk.to_bytes());
}

#[test]
fn verifier_serde_test() {
    let mut osrng = OsRng::default();
    let sk = SecretKey::random(&mut osrng);
    let secret = *sk.to_nonzero_scalar();
    let res = feldman::split_secret::<Scalar, ProjectivePoint, _, 2, 3, SHARE_SIZE>(
        secret, None, &mut osrng,
    );
    assert!(res.is_ok());
    let (shares, verifier) = res.unwrap();
    for s in &shares {
        assert!(verifier.verify(s).is_ok());
    }

    let res = serde_json::to_string(&verifier);
    assert!(res.is_ok());
    let v_str = res.unwrap();
    let res = serde_json::from_str::<FeldmanVerifier<Scalar, ProjectivePoint, 2>>(&v_str);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);

    let res = serde_bare::to_vec(&verifier);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res = serde_bare::from_slice::<FeldmanVerifier<Scalar, ProjectivePoint, 2>>(&v_bytes);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);
}
