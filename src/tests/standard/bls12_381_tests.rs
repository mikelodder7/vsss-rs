/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::super::utils::MockRng;
use super::invalid::*;
use super::valid::*;
use crate::*;
use bls12_381_plus::{
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective,
    Scalar,
};
use elliptic_curve::{
    ff::Field,
    hash2curve::ExpandMsgXmd,
    group::{Curve, Group},
};
use rand::rngs::OsRng;

#[test]
fn invalid_tests() {
    split_invalid_args::<Scalar, G1Projective>();
    split_invalid_args::<Scalar, G2Projective>();
    combine_invalid::<Scalar>();
}

#[test]
fn valid_tests() {
    combine_single::<Scalar, G1Projective>();
    combine_single::<Scalar, G2Projective>();
    combine_all::<Scalar, G1Projective>();
    combine_all::<Scalar, G2Projective>();
}

#[test]
fn group_combine() {
    let mut rng = MockRng::default();
    let secret = Scalar::random(&mut rng);
    let res = split_secret::<Scalar, _>(3, 5, secret, &mut rng);
    assert!(res.is_ok());
    let shares = res.unwrap();

    // Compute partial bls signatures
    let dst = b"group_combine";
    let msg = b"1234567890";
    let mut sig_shares1: Vec<Share, 5> = (0..5).map(|_| Share::default()).collect();
    let mut sig_shares2: Vec<Share, 5> = (0..5).map(|_| Share::default()).collect();
    for (i, s) in shares.iter().enumerate() {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(s.value());
        let sk = Scalar::from_bytes(&bytes).unwrap();

        let h1 = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, dst);
        let h2 = G2Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, dst);

        let s1 = h1 * sk;
        let s2 = h2 * sk;

        sig_shares1[i] = Share::from_group_element(s.identifier(), s1).unwrap();
        sig_shares2[i] = Share::from_group_element(s.identifier(), s2).unwrap();
    }

    let res1 = combine_shares_group::<Scalar, G1Projective>(&sig_shares1);
    let res2 = combine_shares_group::<Scalar, G2Projective>(&sig_shares2);
    assert!(res1.is_ok());
    assert!(res2.is_ok());

    let sig1 = res1.unwrap().to_affine();
    let sig2 = G2Prepared::from(res2.unwrap().to_affine());

    let h1 = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, dst).to_affine();
    let h2 =
        G2Prepared::from(G2Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, dst).to_affine());

    let pk1 = (G1Projective::GENERATOR * secret).to_affine();
    let pk2 = G2Prepared::from((G2Projective::GENERATOR * secret).to_affine());

    let g1 = -G1Affine::generator();
    let g2 = G2Prepared::from(-G2Affine::generator());

    // Verify the combined partial signatures verify as a whole signature
    assert_eq!(
        multi_miller_loop(&[(&sig1, &g2), (&h1, &pk2)])
            .final_exponentiation()
            .is_identity()
            .unwrap_u8(),
        1
    );
    assert_eq!(
        multi_miller_loop(&[(&g1, &sig2), (&pk1, &h2)])
            .final_exponentiation()
            .is_identity()
            .unwrap_u8(),
        1
    );
}

#[test]
fn verifier_serde_test() {
    let mut osrng = OsRng::default();
    let sk = Scalar::random(&mut osrng);
    let res = feldman::split_secret::<Scalar, G1Projective, _>(2, 3, sk, None, &mut osrng);
    assert!(res.is_ok());
    let (shares, verifier) = res.unwrap();
    for s in &shares {
        assert!(verifier.verify(s).is_ok());
    }
    let res = serde_json::to_string(&verifier);
    assert!(res.is_ok());
    let v_str = res.unwrap();
    let res = serde_json::from_str::<FeldmanVerifier<Scalar, G1Projective>>(&v_str);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);

    let res = serde_bare::to_vec(&verifier);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res = serde_bare::from_slice::<FeldmanVerifier<Scalar, G1Projective>>(&v_bytes);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);
}
