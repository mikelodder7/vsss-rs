/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use super::invalid::*;
use super::valid::*;
use crate::{
    Feldman, FeldmanVerifier, Pedersen, PedersenResult, PedersenVerifier, Shamir,
    curve25519::{ WrappedEdwards, WrappedRistretto, WrappedScalar }
};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SecretKey;
use rand::rngs::OsRng;
use x25519_dalek::StaticSecret;

#[test]
fn invalid_tests() {
    split_invalid_args::<WrappedScalar, WrappedRistretto, 33>();
    combine_invalid::<WrappedScalar, 33>();
    split_invalid_args::<WrappedScalar, WrappedEdwards, 33>();
    combine_invalid::<WrappedScalar, 33>();
}

#[test]
fn valid_tests() {
    combine_single::<WrappedScalar, WrappedRistretto, 33>();
    combine_all::<WrappedScalar, WrappedRistretto, 33>();
    combine_single::<WrappedScalar, WrappedEdwards, 33>();
    combine_all::<WrappedScalar, WrappedEdwards, 33>();
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

#[test]
fn feldman_verifier_serde_test() {
    let mut osrng = OsRng::default();
    let sk = Scalar::random(&mut osrng);
    let res = Feldman::<2, 3>::split_secret::<WrappedScalar, WrappedRistretto, OsRng, 33>(
        sk.into(),
        None,
        &mut osrng,
    );
    assert!(res.is_ok());
    let (shares, verifier) = res.unwrap();
    for s in &shares {
        assert!(verifier.verify(s));
    }
    let res = serde_cbor::to_vec(&verifier);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res =
        serde_cbor::from_slice::<FeldmanVerifier<WrappedScalar, WrappedRistretto, 2>>(&v_bytes);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);

    let res = serde_json::to_string(&verifier);
    assert!(res.is_ok());
    let v_str = res.unwrap();
    let res = serde_json::from_str::<FeldmanVerifier<WrappedScalar, WrappedRistretto, 2>>(&v_str);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);

    let res = serde_bare::to_vec(&verifier);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res =
        serde_bare::from_slice::<FeldmanVerifier<WrappedScalar, WrappedRistretto, 2>>(&v_bytes);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);
}

#[test]
fn pedersen_verifier_serde_test() {
    let mut osrng = OsRng::default();
    let sk = Scalar::random(&mut osrng);
    let res = Pedersen::<2, 3>::split_secret::<WrappedScalar, WrappedEdwards, OsRng, 33>(
        sk.into(),
        None,
        None,
        None,
        &mut osrng,
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
        assert!(verifier.verify(s, b));
    }
    let res = serde_cbor::to_vec(&verifier);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res =
        serde_cbor::from_slice::<PedersenVerifier<WrappedScalar, WrappedEdwards, 2>>(&v_bytes);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);

    let res = serde_json::to_string(&verifier);
    assert!(res.is_ok());
    let v_str = res.unwrap();
    let res = serde_json::from_str::<PedersenVerifier<WrappedScalar, WrappedEdwards, 2>>(&v_str);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);

    let res = serde_bare::to_vec(&verifier);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res =
        serde_bare::from_slice::<PedersenVerifier<WrappedScalar, WrappedEdwards, 2>>(&v_bytes);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);
}
