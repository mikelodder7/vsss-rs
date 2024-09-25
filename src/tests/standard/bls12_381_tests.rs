/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::super::utils::MockRng;
use super::invalid::*;
use super::valid::*;
use super::*;
use crate::feldman::GenericArrayFeldmanVsss;
use crate::pedersen::PedersenOptions;
use crate::*;
use bls12_381_plus::{
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Scalar,
};
use elliptic_curve::{
    ff::Field,
    group::{Curve, Group},
    hash2curve::ExpandMsgXmd,
};
use generic_array::{typenum, GenericArray};
use rstest::*;

#[test]
fn simple() {
    const THRESHOLD: usize = 3;
    const SHARES: usize = 5;

    let mut rng = MockRng::default();
    let secret = Scalar::random(&mut rng);
    let sk = IdentifierPrimeField(secret);

    let shares =
        FixedArrayVsss8Of15::<TestShare<Scalar>, GroupElement<G1Projective>>::split_secret(
            THRESHOLD, SHARES, &sk, &mut rng,
        )
        .unwrap();
    let secret2 = (&shares[..THRESHOLD]).combine().unwrap();
    assert_eq!(sk, secret2);

    let (shares, verifiers) =
        FixedArrayVsss8Of15::<TestShare<Scalar>, GroupElement<G1Projective>>::split_secret_with_verifier(THRESHOLD, SHARES, &sk, None, &mut rng).unwrap();
    for s in &shares[..SHARES] {
        assert!(verifiers.verify_share(s).is_ok());
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn simple_std() {
    const THRESHOLD: usize = 3;
    const SHARES: usize = 5;

    let mut rng = MockRng::default();
    let secret = IdentifierPrimeField(Scalar::random(&mut rng));

    let shares = GenericArrayFeldmanVsss::<
        TestShare<Scalar>,
        GroupElement<G1Projective>,
        typenum::U3,
        typenum::U5,
    >::split_secret(THRESHOLD, SHARES, &secret, &mut rng)
    .unwrap();
    let secret2 = (&shares[..THRESHOLD]).combine().unwrap();
    assert_eq!(secret, secret2);

    let (shares, verifiers) =
        StdVsss::<TestShare<Scalar>, GroupElement<G1Projective>>::split_secret_with_verifier(
            THRESHOLD, SHARES, &secret, None, &mut rng,
        )
        .unwrap();
    for s in &shares {
        assert!(verifiers.verify_share(s).is_ok());
    }

    let numbering = ParticipantIdGeneratorType::default();
    let options = PedersenOptions {
        secret,
        blinder: None,
        secret_generator: None,
        blinder_generator: None,
        participant_generators: &[numbering],
    };
    let ped_res =
        StdPedersenResult::<TestShare<Scalar>, GroupElement<G1Projective>>::split_secret_with_blind_verifiers(
            THRESHOLD,
            SHARES,
            &options,
            &mut rng,
        )
        .unwrap();
    assert_eq!(
        <Scalar as Field>::is_zero(&ped_res.blinder().0).unwrap_u8(),
        0u8
    );
    for (s, bs) in ped_res
        .secret_shares()
        .iter()
        .zip(ped_res.blinder_shares().iter())
    {
        assert!(ped_res
            .pedersen_verifier_set()
            .verify_share_and_blinder(s, bs)
            .is_ok());
    }
}

#[test]
fn invalid_tests() {
    split_invalid_args::<TestShare<Scalar>, GroupElement<G1Projective>>();
    split_invalid_args::<TestShare<Scalar>, GroupElement<G2Projective>>();
    combine_invalid::<Scalar>();
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn invalid_test_std() {
    combine_invalid_vec::<Scalar>();
}

#[test]
fn valid_tests() {
    combine_single::<G1Projective>();
    combine_single::<G2Projective>();
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn valid_std_tests() {
    combine_all::<G1Projective>();
    combine_all::<G2Projective>();
}

#[test]
fn group_combine() {
    let mut rng = MockRng::default();
    let secret = IdentifierPrimeField(Scalar::random(&mut rng));
    let res = <[TestShare<Scalar>; 5]>::split_secret(3, 5, &secret, &mut rng);
    assert!(res.is_ok());
    let shares = res.unwrap();

    // Compute partial bls signatures
    let dst = b"group_combine";
    let msg = b"1234567890";
    let mut sig_shares1 = [(
        IdentifierPrimeField::<Scalar>::ZERO,
        GroupElement::<G1Projective>::identity(),
    ); 5];
    let mut sig_shares2 = [(
        IdentifierPrimeField::<Scalar>::ZERO,
        GroupElement::<G2Projective>::identity(),
    ); 5];
    for (i, s) in shares.iter().enumerate() {
        let h1 = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, dst);
        let h2 = G2Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, dst);

        let s1 = h1 * s.value().0;
        let s2 = h2 * s.value().0;

        sig_shares1[i].0 = *s.identifier();
        sig_shares1[i].1 .0 = s1;
        sig_shares2[i].0 = *s.identifier();
        sig_shares2[i].1 .0 = s2;
    }

    let res2 = sig_shares2.combine();
    let res1 = sig_shares1.combine();
    assert!(res2.is_ok());
    assert!(res1.is_ok());

    let sig1 = res1.unwrap().to_affine();
    let sig2 = G2Prepared::from(res2.unwrap().to_affine());

    let h1 = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, dst).to_affine();
    let h2 =
        G2Prepared::from(G2Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, dst).to_affine());

    let pk1 = (G1Projective::GENERATOR * *secret).to_affine();
    let pk2 = G2Prepared::from((G2Projective::GENERATOR * *secret).to_affine());

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
fn splitter() {
    split_combine_test(2, 3);
}

#[rstest]
#[case::threshold2_of_3(2, 3)]
#[case::threshold3_of_5(3, 5)]
#[case::threshold4_of_7(4, 7)]
#[case::threshold5_of_9(5, 9)]
#[case::threshold6_of_11(6, 11)]
#[case::threshold7_of_13(7, 13)]
#[case::threshold8_of_15(8, 14)]
fn split_combine_test(#[case] threshold: usize, #[case] limit: usize) {
    let mut rng = MockRng::default();
    let secret = IdentifierPrimeField(Scalar::random(&mut rng));

    let shares =
        <[TestShare<Scalar>; 14]>::split_secret(threshold, limit, &secret, &mut rng).unwrap();

    let secret2 = (&shares[..threshold]).combine().unwrap();
    assert_eq!(secret, secret2);
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn point_combine() {
    let mut rng = MockRng::default();
    let secret = IdentifierPrimeField(Scalar::random(&mut rng));
    let res = Vec::<TestShare<Scalar>>::split_secret(2, 3, &secret, &mut rng);
    assert!(res.is_ok());
    let shares = res.unwrap();

    let sigs_g1 = shares
        .iter()
        .map(|s| {
            let pt = G1Projective::GENERATOR * s.value().0;
            <(IdentifierPrimeField<Scalar>, GroupElement<G1Projective>)>::with_identifier_and_value(
                s.identifier().clone(),
                GroupElement(pt),
            )
        })
        .collect::<Vec<_>>();

    let sig_g1 = (&sigs_g1[..2]).combine().unwrap();
    assert_eq!(sig_g1.0, G1Projective::GENERATOR * *secret);
}
