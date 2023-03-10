/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use super::invalid::*;
use super::valid::*;
use crate::{
    curve25519::{WrappedEdwards, WrappedRistretto, WrappedScalar},
    Feldman, FeldmanVerifier, Pedersen, PedersenResult, PedersenVerifier, Shamir,
};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SecretKey;
use x25519_dalek::StaticSecret;

#[test]
fn invalid_tests() {
    split_invalid_args::<WrappedScalar, WrappedRistretto>();
    combine_invalid::<WrappedScalar>();
    split_invalid_args::<WrappedScalar, WrappedEdwards>();
    combine_invalid::<WrappedScalar>();
}

#[test]
fn valid_tests() {
    combine_single::<WrappedScalar, WrappedRistretto>();
    combine_all::<WrappedScalar, WrappedRistretto>();
    combine_single::<WrappedScalar, WrappedEdwards>();
    combine_all::<WrappedScalar, WrappedEdwards>();
}

#[test]
fn key_tests() {
    let mut osrng_7 = rand_7::rngs::OsRng::default();
    let mut osrng_8 = rand::rngs::OsRng::default();
    let sc = Scalar::random(&mut osrng_7);
    let sk1 = StaticSecret::from(sc.to_bytes());
    let ske1 = SecretKey::from_bytes(&sc.to_bytes()).unwrap();
    let res = Shamir { t: 2, n: 3 }.split_secret::<WrappedScalar, _>(sc.into(), &mut osrng_8);
    assert!(res.is_ok());
    let shares = res.unwrap();
    let res = Shamir { t: 2, n: 3 }.combine_shares::<WrappedScalar>(&shares);
    assert!(res.is_ok());
    let scalar = res.unwrap();
    assert_eq!(scalar.0, sc);
    let sk2 = StaticSecret::from(scalar.0.to_bytes());
    let ske2 = SecretKey::from_bytes(&scalar.0.to_bytes()).unwrap();
    assert_eq!(sk2.to_bytes(), sk1.to_bytes());
    assert_eq!(ske1.to_bytes(), ske2.to_bytes());
}

#[test]
fn feldman_verifier_serde_test() {
    let mut osrng_7 = rand_7::rngs::OsRng::default();
    let mut osrng_8 = rand::rngs::OsRng::default();
    let sk = Scalar::random(&mut osrng_7);
    let res = Feldman { t: 2, n: 3 }.split_secret::<WrappedScalar, WrappedRistretto, _>(
        sk.into(),
        None,
        &mut osrng_8,
    );
    assert!(res.is_ok());
    let (shares, verifier) = res.unwrap();
    for s in &shares {
        assert!(verifier.verify(s).is_ok());
    }
    let res = serde_cbor::to_vec(&verifier);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res = serde_cbor::from_slice::<FeldmanVerifier<WrappedScalar, WrappedRistretto>>(&v_bytes);
    if res.is_err() {
        println!("{:?}", res);
    }
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);

    let res = serde_json::to_string(&verifier);
    assert!(res.is_ok());
    let v_str = res.unwrap();
    let res = serde_json::from_str::<FeldmanVerifier<WrappedScalar, WrappedRistretto>>(&v_str);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);

    let res = serde_bare::to_vec(&verifier);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res = serde_bare::from_slice::<FeldmanVerifier<WrappedScalar, WrappedRistretto>>(&v_bytes);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);
}

#[test]
fn pedersen_verifier_serde_test() {
    let mut osrng_7 = rand_7::rngs::OsRng::default();
    let mut osrng_8 = rand::rngs::OsRng::default();
    let sk = Scalar::random(&mut osrng_7);
    let res = Pedersen { t: 2, n: 3 }
        .split_secret::<WrappedScalar, WrappedEdwards, rand::rngs::OsRng>(
            sk.into(),
            None,
            None,
            None,
            &mut osrng_8,
        );
    assert!(res.is_ok());
    let ped_res = res.unwrap();
    let PedersenResult {
        blinding: _,
        blind_shares,
        secret_shares,
        verifier,
    } = ped_res;
    for (s, b) in secret_shares.iter().zip(blind_shares.iter()) {
        assert!(verifier.verify(s, b).is_ok());
    }
    let res = serde_cbor::to_vec(&verifier);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res = serde_cbor::from_slice::<PedersenVerifier<WrappedScalar, WrappedEdwards>>(&v_bytes);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);

    let res = serde_json::to_string(&verifier);
    assert!(res.is_ok());
    let v_str = res.unwrap();
    let res = serde_json::from_str::<PedersenVerifier<WrappedScalar, WrappedEdwards>>(&v_str);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);

    let res = serde_bare::to_vec(&verifier);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res = serde_bare::from_slice::<PedersenVerifier<WrappedScalar, WrappedEdwards>>(&v_bytes);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);
}
