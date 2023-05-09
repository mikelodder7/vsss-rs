/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use super::invalid::*;
use super::valid::*;
use crate::{
    curve25519::{WrappedEdwards, WrappedRistretto, WrappedScalar},
    *,
};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SecretKey;
use rand::Rng;
use x25519_dalek::StaticSecret;
use crate::tests::standard::ScalarShare;

#[test]
fn invalid_tests() {
    split_invalid_args::<WrappedRistretto>();
    combine_invalid::<WrappedScalar>();
    split_invalid_args::<WrappedEdwards>();
    combine_invalid::<WrappedScalar>();
}

#[test]
fn valid_tests() {
    combine_single::<WrappedRistretto>();
    combine_single::<WrappedEdwards>();
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn valid_std_tests() {
    combine_all::<WrappedRistretto>();
    combine_all::<WrappedEdwards>();
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn key_tests() {
    use rand::Rng;

    let mut osrng = rand::rngs::OsRng::default();
    let sc = Scalar::hash_from_bytes::<sha2_9::Sha512>(&osrng.gen::<[u8; 32]>());
    let sk1 = StaticSecret::from(sc.to_bytes());
    let ske1 = SecretKey::from_bytes(&sc.to_bytes()).unwrap();
    let res = shamir::split_secret::<WrappedScalar, u8, ScalarShare>(2, 3, sc.into(), &mut osrng);
    assert!(res.is_ok());
    let shares = res.unwrap();
    let res = combine_shares(&shares);
    assert!(res.is_ok());
    let scalar: WrappedScalar = res.unwrap();
    assert_eq!(scalar.0, sc);
    let sk2 = StaticSecret::from(scalar.0.to_bytes());
    let ske2 = SecretKey::from_bytes(&scalar.0.to_bytes()).unwrap();
    assert_eq!(sk2.to_bytes(), sk1.to_bytes());
    assert_eq!(ske1.to_bytes(), ske2.to_bytes());
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn pedersen_verifier_serde_test() {
    use rand::Rng;

    let mut osrng = rand::rngs::OsRng::default();
    let sk = Scalar::hash_from_bytes::<sha2_9::Sha512>(&osrng.gen::<[u8; 32]>());
    let res = pedersen::split_secret::<WrappedEdwards, u8, ScalarShare>(
        2,
        3,
        sk.into(),
        None,
        None,
        None,
        &mut osrng,
    );
    assert!(res.is_ok());
    let ped_res = res.unwrap();
    let StdPedersenResult {
        blinder: _,
        secret_shares,
        blinder_shares,
        feldman_verifier_set,
        pedersen_verifier_set,
    } = ped_res;
    for (s, b) in secret_shares.iter().zip(blinder_shares.iter()) {
        assert!(feldman_verifier_set.verify_share(s).is_ok());
        assert!(pedersen_verifier_set.verify_share_and_blinder(s, b).is_ok());
    }

    let res = serde_json::to_string(&pedersen_verifier_set);
    assert!(res.is_ok());
    let v_str = res.unwrap();
    let res = serde_json::from_str::<Vec<WrappedEdwards>>(&v_str);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(pedersen_verifier_set.secret_generator(), verifier2.secret_generator());

    let res = serde_bare::to_vec(&pedersen_verifier_set);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res = serde_bare::from_slice::<Vec<WrappedEdwards>>(&v_bytes);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(pedersen_verifier_set.secret_generator(), verifier2.secret_generator());
}
