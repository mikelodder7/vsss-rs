/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::super::utils::MockRng;
use super::invalid::*;
use super::valid::*;
use crate::*;
use bls12_381_plus::{
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Scalar,
};
use elliptic_curve::{
    ff::Field,
    group::{Curve, Group},
    hash2curve::ExpandMsgXmd,
};
use rand::rngs::OsRng;
use rstest::*;

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

#[cfg(feature = "const-generics")]
#[rstest]
#[case::threshold2_of_3(2, 3)]
#[case::threshold3_of_5(3, 5)]
#[case::threshold4_of_7(4, 7)]
#[case::threshold5_of_9(5, 9)]
#[case::threshold6_of_11(6, 11)]
#[case::threshold7_of_13(7, 13)]
#[case::threshold8_of_15(8, 15)]
fn split_combine_test(
   #[case] threshold: usize,
   #[case] limit: usize,
) {
    const SECRET_SHARE_SIZE: usize = 33;
    const G1_SHARE_SIZE: usize = 49;
    const G2_SHARE_SIZE: usize = 97;
    const MAX_TEST_SHARES: usize = 16;
    let secret = Scalar::random(OsRng);
    let shares = split_secret_const_generics::<_, _, SECRET_SHARE_SIZE>(threshold, limit, secret, &mut OsRng).unwrap();
    let secret2 = combine_shares_const_generics::<Scalar, SECRET_SHARE_SIZE>(&shares[..threshold]).unwrap();
    assert_eq!(secret, secret2);

    let mut sigs_g1 = Vec::<const_generics::Share<G1_SHARE_SIZE>, MAX_TEST_SHARES>::new();
    let mut sigs_g2 = Vec::<const_generics::Share<G2_SHARE_SIZE>, MAX_TEST_SHARES>::new();
    for s in &shares {
        let ff = s.as_field_element::<Scalar>().unwrap();
        let sig_g1 = G1Projective::GENERATOR * ff;
        let new_share_g1 = const_generics::Share::<G1_SHARE_SIZE>::from_group_element(s.identifier(), sig_g1).unwrap();
        sigs_g1.push(new_share_g1).unwrap();

        let sig_g2 = G2Projective::GENERATOR * ff;
        let new_share_g2 = const_generics::Share::<G2_SHARE_SIZE>::from_group_element(s.identifier(), sig_g2).unwrap();
        sigs_g2.push(new_share_g2).unwrap();
    }

    let sig_g1 = combine_shares_group_const_generics::<Scalar, G1Projective, G1_SHARE_SIZE>(&sigs_g1[..threshold]).unwrap();
    assert_eq!(sig_g1, G1Projective::GENERATOR * secret);
    let sig_g2 = combine_shares_group_const_generics::<Scalar, G2Projective, G2_SHARE_SIZE>(&sigs_g2[..threshold]).unwrap();
    assert_eq!(sig_g2, G2Projective::GENERATOR * secret);

    let (shares, verifier) = feldman::split_secret_const_generics::<_, G1Projective, _, SECRET_SHARE_SIZE>(threshold, limit, secret, None, &mut OsRng).unwrap();
    for s in &shares {
        assert!(verifier.verify_const_generics(s).is_ok());
    }
}