/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use super::invalid::*;
use super::valid::*;
use crate::tests::standard::TestShare;
use crate::*;
use ed448_goldilocks_plus::{EdwardsPoint, Scalar};
#[cfg(all(test, any(feature = "alloc", feature = "std")))]
use elliptic_curve::hash2curve::ExpandMsgXmd;

#[test]
fn invalid_tests() {
    split_invalid_args::<TestShare<Scalar>, ValueGroup<EdwardsPoint>>();
}

#[test]
fn valid_tests() {
    combine_single::<EdwardsPoint>();
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn valid_std_tests() {
    combine_all::<EdwardsPoint>();
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn key_tests() {
    use rand::Rng;

    let mut osrng = rand::rngs::OsRng::default();
    let sc = Scalar::hash::<ExpandMsgXmd<sha2::Sha512>>(
        &osrng.gen::<[u8; 32]>(),
        b"edwards_XMD:SHA-512_ELL2_RO_",
    );
    let sk = IdentifierPrimeField(sc);
    let res = shamir::split_secret::<TestShare<Scalar>>(2, 3, &sk, &mut osrng);
    assert!(res.is_ok());
    let shares = res.unwrap();
    let res = shares.combine();
    assert!(res.is_ok());
    let scalar = res.unwrap();
    assert_eq!(scalar, sk);
}

#[cfg(all(feature = "serde", any(feature = "alloc", feature = "std")))]
#[test]
fn pedersen_verifier_serde_test() {
    use rand::Rng;

    let mut osrng = rand::rngs::OsRng::default();
    let sc = Scalar::hash::<ExpandMsgXmd<sha2::Sha512>>(
        &osrng.gen::<[u8; 32]>(),
        b"edwards_XMD:SHA-512_ELL2_RO_",
    );
    let sk = IdentifierPrimeField(sc);
    let res = pedersen::split_secret::<TestShare<Scalar>, ValueGroup<EdwardsPoint>>(
        2, 3, &sk, None, None, None, &mut osrng,
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
    if res.is_err() {
        eprintln!("{:?}", res.unwrap_err());
        return;
    }
    assert!(res.is_ok());
    let v_str = res.unwrap();
    let res = serde_json::from_str::<Vec<ValueGroup<EdwardsPoint>>>(&v_str);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(
        <Vec<ValueGroup<EdwardsPoint>> as PedersenVerifierSet::<
            TestShare<Scalar>,
            ValueGroup<EdwardsPoint>,
        >>::secret_generator(&pedersen_verifier_set),
        PedersenVerifierSet::<TestShare<Scalar>, ValueGroup<EdwardsPoint>>::secret_generator(
            &verifier2
        )
    );

    let res = serde_bare::to_vec(&pedersen_verifier_set);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res = serde_bare::from_slice::<Vec<ValueGroup<EdwardsPoint>>>(&v_bytes);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(
        <Vec<ValueGroup<EdwardsPoint>> as PedersenVerifierSet::<
            TestShare<Scalar>,
            ValueGroup<EdwardsPoint>,
        >>::secret_generator(&pedersen_verifier_set),
        PedersenVerifierSet::<TestShare<Scalar>, ValueGroup<EdwardsPoint>>::secret_generator(
            &verifier2
        )
    );
}
