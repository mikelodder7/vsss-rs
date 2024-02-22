/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::super::utils::MockRng;
use super::invalid::*;
use super::valid::*;
use super::*;
use bls12_381_plus::{
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Scalar,
};
use elliptic_curve::{
    ff::Field,
    generic_array::{typenum, GenericArray},
    group::{Curve, Group},
    hash2curve::ExpandMsgXmd,
};
use rstest::*;

#[test]
fn simple() {
    const THRESHOLD: usize = 3;
    const SHARES: usize = 5;

    let mut rng = MockRng::default();
    let secret = Scalar::random(&mut rng);

    let shares: [[u8; 33]; 5] =
        <[[u8; 33]; SHARES]>::split_secret(THRESHOLD, SHARES, secret, &mut rng).unwrap();
    let secret2 = (&shares[..THRESHOLD])
        .combine_to_field_element::<Scalar, [(Scalar, Scalar); 3]>()
        .unwrap();
    assert_eq!(secret, secret2);

    struct Fvss {
        coefficients: [Scalar; THRESHOLD],
    }

    impl Polynomial<Scalar> for Fvss {
        fn create(_size_hint: usize) -> Self {
            Self {
                coefficients: [Scalar::ZERO; THRESHOLD],
            }
        }

        fn coefficients(&self) -> &[Scalar] {
            self.coefficients.as_ref()
        }

        fn coefficients_mut(&mut self) -> &mut [Scalar] {
            self.coefficients.as_mut()
        }
    }

    impl Shamir<Scalar, [u8; 1], u8, [u8; 33]> for Fvss {
        type InnerPolynomial = [Scalar; THRESHOLD];
        type ShareSet = [[u8; 33]; SHARES];
    }

    impl Feldman<G1Projective, [u8; 1], u8, [u8; 33]> for Fvss {
        type VerifierSet = [G1Projective; THRESHOLD + 1];
    }

    let (shares, verifiers) =
        Fvss::split_secret_with_verifier(THRESHOLD, SHARES, secret, None, &mut rng).unwrap();
    for s in &shares {
        assert!(verifiers.verify_share(s).is_ok());
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn simple_std() {
    const THRESHOLD: usize = 3;
    const SHARES: usize = 5;

    let mut rng = MockRng::default();
    let secret = Scalar::random(&mut rng);

    let shares: Vec<Vec<u8>> = <StdVsss<G1Projective, [u8; 1], u8, Vec<u8>>>::split_secret(
        THRESHOLD, SHARES, secret, &mut rng,
    )
    .unwrap();
    let secret2 = (&shares[..THRESHOLD])
        .combine_to_field_element::<Scalar, [(Scalar, Scalar); 3]>()
        .unwrap();
    assert_eq!(secret, secret2);

    let (shares, verifiers): (Vec<Vec<u8>>, Vec<G1Projective>) =
        StdVsss::split_secret_with_verifier(
            THRESHOLD,
            SHARES,
            secret,
            None::<G1Projective>,
            &mut rng,
        )
        .unwrap();
    for s in &shares {
        assert!(verifiers.verify_share(s).is_ok());
    }

    let ped_res: StdPedersenResult<G1Projective, [u8; 1], u8, Vec<u8>> =
        StdVsss::split_secret_with_blind_verifier(
            THRESHOLD,
            SHARES,
            secret,
            None::<Scalar>,
            None::<G1Projective>,
            None::<G1Projective>,
            &mut rng,
        )
        .unwrap();
    assert_eq!(ped_res.blinder().is_zero().unwrap_u8(), 0u8);
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
    split_invalid_args::<G1Projective, [u8; 1], u8, [u8; 48]>();
    split_invalid_args::<G2Projective, [u8; 2], u16, (u16, [u8; 96])>();
    combine_invalid::<Scalar>();
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn invalid_test_std() {
    combine_invalid_vec::<Scalar>();
}

#[test]
fn valid_tests() {
    combine_single::<G1Projective, [u8; 1], u8, [u8; 33]>();
    combine_single::<G2Projective, [u8; 1], u8, [u8; 33]>();
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn valid_std_tests() {
    combine_all::<G1Projective, [u8; 1], u8, Vec<u8>>();
    combine_all::<G2Projective, [u8; 1], u8, Vec<u8>>();
}

#[test]
fn group_combine() {
    let mut rng = MockRng::default();
    let secret = Scalar::random(&mut rng);
    let res =
        TesterVsss::<G1Projective, [u8; 1], u8, [u8; 33]>::split_secret(3, 5, secret, &mut rng);
    assert!(res.is_ok());
    let shares = res.unwrap();

    // Compute partial bls signatures
    let dst = b"group_combine";
    let msg = b"1234567890";
    let mut sig_shares1 = [GenericArray::<u8, typenum::U49>::default(); 5];
    let mut sig_shares2 = [GenericArray::<u8, typenum::U97>::default(); 5];
    for (i, s) in shares[..5].iter().enumerate() {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(s.value());
        let sk = Scalar::from_le_bytes(&bytes).unwrap();

        let h1 = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, dst);
        let h2 = G2Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, dst);

        let s1 = h1 * sk;
        let s2 = h2 * sk;

        sig_shares1[i] =
            GenericArray::<u8, typenum::U49>::from_group_element(s.identifier(), s1).unwrap();
        sig_shares2[i] =
            GenericArray::<u8, typenum::U97>::from_group_element(s.identifier(), s2).unwrap();
    }

    let res2 = sig_shares2.combine_to_group_element::<G2Projective, [(Scalar, G2Projective); 5]>();
    let res1 = sig_shares1.combine_to_group_element::<G1Projective, [(Scalar, G1Projective); 5]>();
    assert!(res2.is_ok());
    assert!(res1.is_ok());

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
    let secret = Scalar::random(&mut rng);

    let shares = TesterVsss::<G1Projective, [u8; 1], u8, [u8; 33]>::split_secret(
        threshold, limit, secret, &mut rng,
    )
    .unwrap();

    let secret2 = (&shares[..threshold])
        .combine_to_field_element::<Scalar, [(Scalar, Scalar); 15]>()
        .unwrap();
    assert_eq!(secret, secret2);

    // let mut sigs_g1 = Vec::<const_generics::Share<G1_SHARE_SIZE>, MAX_TEST_SHARES>::new();
    // let mut sigs_g2 = Vec::<const_generics::Share<G2_SHARE_SIZE>, MAX_TEST_SHARES>::new();
    // for s in &shares {
    //     let ff = s.as_field_element::<Scalar>().unwrap();
    //     let sig_g1 = G1Projective::GENERATOR * ff;
    //     let new_share_g1 =
    //         const_generics::Share::<G1_SHARE_SIZE>::from_group_element(s.identifier(), sig_g1)
    //             .unwrap();
    //     sigs_g1.push(new_share_g1).unwrap();
    //
    //     let sig_g2 = G2Projective::GENERATOR * ff;
    //     let new_share_g2 =
    //         const_generics::Share::<G2_SHARE_SIZE>::from_group_element(s.identifier(), sig_g2)
    //             .unwrap();
    //     sigs_g2.push(new_share_g2).unwrap();
    // }
    //
    // let sig_g1 = combine_shares_group_const_generics::<Scalar, G1Projective, G1_SHARE_SIZE>(
    //     &sigs_g1[..threshold],
    // )
    // .unwrap();
    // assert_eq!(sig_g1, G1Projective::GENERATOR * secret);
    // let sig_g2 = combine_shares_group_const_generics::<Scalar, G2Projective, G2_SHARE_SIZE>(
    //     &sigs_g2[..threshold],
    // )
    // .unwrap();
    // assert_eq!(sig_g2, G2Projective::GENERATOR * secret);
    //
    // let (shares, verifier) =
    //     feldman::split_secret_const_generics::<_, G1Projective, _, SECRET_SHARE_SIZE>(
    //         threshold, limit, secret, None, &mut OsRng,
    //     )
    //     .unwrap();
    // for s in &shares {
    //     assert!(verifier.verify_const_generics(s).is_ok());
    // }
}

#[test]
fn point_combine() {
    let mut rng = MockRng::default();
    let secret = Scalar::random(&mut rng);
    let res =
        TesterVsss::<G1Projective, [u8; 1], u8, [u8; 33]>::split_secret(2, 3, secret, &mut rng);
    assert!(res.is_ok());
    let shares = res.unwrap();

    let sigs_g1 = shares
        .iter()
        .map(|s| {
            let ff = s.as_field_element::<Scalar>().unwrap();
            let pt = G1Projective::GENERATOR * ff;
            <[u8; 49]>::with_identifier_and_value(s.identifier(), &pt.to_compressed())
        })
        .collect::<Vec<[u8; 49]>>();

    let sig_g1 =
        combine_shares_group::<G1Projective, [u8; 1], u8, [u8; 49]>(&sigs_g1[..2]).unwrap();
    assert_eq!(sig_g1, G1Projective::GENERATOR * secret);
}

#[test]
fn big_integer_identifier() {
    let mut rng = MockRng::default();
    let secret = Scalar::random(&mut rng);
    let res =
        TesterVsss::<G1Projective, [u8; 2], u16, (u16, GenericArray<u8, typenum::U32>)>::split_secret(
            2, 3, secret, &mut rng,
        );
    assert!(res.is_ok());
    let shares = res.unwrap();

    let secret2 = combine_shares(&shares[..2]).unwrap();
    assert_eq!(secret, secret2);
}
