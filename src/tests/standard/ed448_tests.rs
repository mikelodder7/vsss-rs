/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use super::invalid::*;
use super::valid::*;
use crate::*;
use ed448_goldilocks_plus::{EdwardsPoint, Scalar};
#[cfg(all(test, any(feature = "alloc", feature = "std")))]
use elliptic_curve::hash2curve::ExpandMsgXmd;

#[test]
fn invalid_tests() {
    split_invalid_args::<EdwardsPoint, u8, [u8; 58]>();
    let share = [0u8; 58];
    // Invalid identifier
    assert!([share.clone(), [2u8; 58]]
        .combine_to_field_element::<Scalar, [(Scalar, Scalar); 3]>()
        .is_err());
    // Duplicate shares
    assert!([[1u8; 58], [1u8; 58],]
        .combine_to_field_element::<Scalar, [(Scalar, Scalar); 3]>()
        .is_err());
}

#[test]
fn valid_tests() {
    combine_single::<EdwardsPoint, u8, [u8; 58]>();
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn valid_std_tests() {
    combine_all::<EdwardsPoint, u8, [u8; 58]>();
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn key_tests() {
    use crate::combine_shares;
    use rand::Rng;

    let mut osrng = rand::rngs::OsRng::default();
    let sc = Scalar::hash::<ExpandMsgXmd<sha2::Sha512>>(
        &osrng.gen::<[u8; 32]>(),
        b"edwards_XMD:SHA-512_ELL2_RO_",
    );
    let res = shamir::split_secret::<Scalar, u8, [u8; 58]>(2, 3, sc.into(), &mut osrng);
    assert!(res.is_ok());
    let shares = res.unwrap();
    let res = combine_shares(&shares);
    assert!(res.is_ok());
    let scalar: Scalar = res.unwrap();
    assert_eq!(scalar, sc);
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn pedersen_verifier_serde_test() {
    use rand::Rng;

    let mut osrng = rand::rngs::OsRng::default();
    let sk = Scalar::hash::<ExpandMsgXmd<sha2::Sha512>>(
        &osrng.gen::<[u8; 32]>(),
        b"edwards_XMD:SHA-512_ELL2_RO_",
    );
    let res = pedersen::split_secret::<EdwardsPoint, u8, [u8; 58]>(
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
    let res = serde_json::from_str::<Vec<EdwardsPoint>>(&v_str);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(
        pedersen_verifier_set.secret_generator(),
        verifier2.secret_generator()
    );

    let res = serde_bare::to_vec(&pedersen_verifier_set);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res = serde_bare::from_slice::<Vec<EdwardsPoint>>(&v_bytes);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(
        pedersen_verifier_set.secret_generator(),
        verifier2.secret_generator()
    );
}
