/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use super::invalid::*;
use super::valid::*;
use crate::tests::standard::TestShare;
use crate::*;
use curve25519_dalek::{edwards::SubgroupPoint, ristretto::RistrettoPoint, scalar::Scalar};
use ed25519_dalek::SigningKey;
use x25519_dalek::StaticSecret;

#[test]
fn invalid_tests() {
    split_invalid_args::<TestShare<Scalar>, ValueGroup<RistrettoPoint>>();
    combine_invalid::<Scalar>();
    split_invalid_args::<TestShare<Scalar>, ValueGroup<SubgroupPoint>>();
    combine_invalid::<Scalar>();
}

#[test]
fn valid_tests() {
    combine_single::<RistrettoPoint>();
    combine_single::<SubgroupPoint>();
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn valid_std_tests() {
    combine_all::<RistrettoPoint>();
    combine_all::<SubgroupPoint>();
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn key_tests() {
    use rand::{RngExt, SeedableRng};

    let mut osrng = rand::rngs::StdRng::from_seed([4u8; 32]);
    let sc = Scalar::hash_from_bytes::<sha2::Sha512>(&osrng.random::<[u8; 32]>());
    let sk1 = StaticSecret::from(sc.to_bytes());
    let ske1 = SigningKey::from_bytes(&sc.to_bytes());
    let sk = IdentifierPrimeField(sc);
    let res = shamir::split_secret::<TestShare<Scalar>>(2, 3, &sk, &mut osrng);
    assert!(res.is_ok());
    let shares = res.unwrap();
    let res = shares.combine();
    assert!(res.is_ok());
    let scalar = res.unwrap();
    assert_eq!(scalar, sk);
    let sk2 = StaticSecret::from(scalar.0.to_bytes());
    let ske2 = SigningKey::from_bytes(&scalar.0.to_bytes());
    assert_eq!(sk2.to_bytes(), sk1.to_bytes());
    assert_eq!(ske1.to_bytes(), ske2.to_bytes());
}

#[cfg(all(feature = "serde", any(feature = "alloc", feature = "std")))]
#[test]
fn pedersen_verifier_serde_test() {
    use rand::{RngExt, SeedableRng};

    let mut osrng = rand::rngs::StdRng::from_seed([5u8; 32]);
    let sc = Scalar::hash_from_bytes::<sha2::Sha512>(&osrng.random::<[u8; 32]>());
    let sk = IdentifierPrimeField(sc);
    let res = pedersen::split_secret::<TestShare<Scalar>, ValueGroup<SubgroupPoint>>(
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
    if let Err(err) = &res {
        eprintln!("{err:?}");
        return;
    }
    assert!(res.is_ok());
    let v_str = res.unwrap();
    let res = serde_json::from_str::<Vec<ValueGroup<SubgroupPoint>>>(&v_str);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(
        <Vec<ValueGroup<SubgroupPoint>> as PedersenVerifierSet::<
            TestShare<Scalar>,
            ValueGroup<SubgroupPoint>,
        >>::secret_generator(&pedersen_verifier_set),
        PedersenVerifierSet::<TestShare<Scalar>, ValueGroup<SubgroupPoint>>::secret_generator(
            &verifier2
        )
    );

    let res = serde_bare::to_vec(&pedersen_verifier_set);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res = serde_bare::from_slice::<Vec<ValueGroup<SubgroupPoint>>>(&v_bytes);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(
        <Vec<ValueGroup<SubgroupPoint>> as PedersenVerifierSet::<
            TestShare<Scalar>,
            ValueGroup<SubgroupPoint>,
        >>::secret_generator(&pedersen_verifier_set),
        PedersenVerifierSet::<TestShare<Scalar>, ValueGroup<SubgroupPoint>>::secret_generator(
            &verifier2
        )
    );
}
