// Copyright Michael Lodder. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use ff::PrimeField;
use k256::{NonZeroScalar, SecretKey};
use rand::rngs::OsRng;

use super::{invalid::*, valid::*};
use crate::{
    secp256k1::{WrappedProjectivePoint, WrappedScalar},
    Feldman,
    FeldmanVerifier,
    Shamir,
};

#[test]
fn invalid_tests() {
    split_invalid_args::<WrappedScalar, WrappedProjectivePoint>();
    combine_invalid::<WrappedScalar>();
}

#[test]
fn valid_tests() {
    combine_single::<WrappedScalar, WrappedProjectivePoint>();
    combine_all::<WrappedScalar, WrappedProjectivePoint>();
}

#[test]
fn key_tests() {
    let mut osrng = OsRng::default();
    let sk = SecretKey::random(&mut osrng);
    let secret = WrappedScalar(*sk.to_nonzero_scalar());
    let res = Shamir { t: 2, n: 3 }.split_secret::<WrappedScalar, OsRng>(secret, &mut osrng);
    assert!(res.is_ok());
    let shares = res.unwrap();
    let res = Shamir { t: 2, n: 3 }.combine_shares::<WrappedScalar>(&shares);
    assert!(res.is_ok());
    let scalar = res.unwrap();
    let nzs_dup = NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
    let sk_dup = SecretKey::from(nzs_dup);
    assert_eq!(sk_dup.to_be_bytes(), sk.to_be_bytes());
}

#[test]
fn verifier_serde_test() {
    let mut osrng = OsRng::default();
    let sk = SecretKey::random(&mut osrng);
    let secret = WrappedScalar(*sk.to_nonzero_scalar());
    let res =
        Feldman { t: 2, n: 3 }.split_secret::<WrappedScalar, WrappedProjectivePoint, OsRng>(secret, None, &mut osrng);
    assert!(res.is_ok());
    let (shares, verifier) = res.unwrap();
    for s in &shares {
        assert!(verifier.verify(s));
    }
    let res = serde_cbor::to_vec(&verifier);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res = serde_cbor::from_slice::<FeldmanVerifier<WrappedScalar, WrappedProjectivePoint>>(&v_bytes);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);

    let res = serde_json::to_string(&verifier);
    assert!(res.is_ok());
    let v_str = res.unwrap();
    let res = serde_json::from_str::<FeldmanVerifier<WrappedScalar, WrappedProjectivePoint>>(&v_str);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);

    let res = serde_bare::to_vec(&verifier);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res = serde_bare::from_slice::<FeldmanVerifier<WrappedScalar, WrappedProjectivePoint>>(&v_bytes);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);
}
