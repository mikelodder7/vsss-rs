/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::*;
use crate::tests::standard::TesterVsss;
use crate::tests::utils::MockRng;
use elliptic_curve::{
    ff::{Field, PrimeField},
    group::{Group, GroupEncoding},
};

pub fn combine_single<
    G: Group + GroupEncoding + Default,
    I: ShareIdentifier,
    S: Share<Identifier = I>,
>() {
    let mut repr = <G::Scalar as PrimeField>::Repr::default();
    repr.as_mut()[..5].copy_from_slice(b"hello");
    let secret = G::Scalar::from_repr(repr).unwrap();
    let mut rng = MockRng::default();
    let res = TesterVsss::<G, I, S>::split_secret(2, 3, secret, &mut rng);
    assert!(res.is_ok());
    let shares = res.unwrap();

    let res = (&shares[..3]).combine_to_field_element::<G::Scalar, [(G::Scalar, G::Scalar); 3]>();
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, secret_1);

    // Feldman test
    let res = TesterVsss::<G, I, S>::split_secret_with_verifier(2, 3, secret, None, &mut rng);
    assert!(res.is_ok());
    let (shares, verifier) = res.unwrap();
    for s in &shares[..3] {
        assert!(verifier.verify_share(s).is_ok());
    }
    let res = (&shares[..2]).combine_to_field_element::<G::Scalar, [(G::Scalar, G::Scalar); 2]>();
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, secret_1);

    // Pedersen test
    let res = TesterVsss::<G, I, S>::split_secret_with_blind_verifier(
        2, 3, secret, None, None, None, &mut rng,
    );
    assert!(res.is_ok());
    let p_res = res.unwrap();
    for (s, b) in p_res.secret_shares[..3]
        .iter()
        .zip(p_res.blinder_shares[..3].iter())
    {
        assert!(p_res
            .pedersen_verifier_set
            .verify_share_and_blinder(s, b)
            .is_ok());
    }
    let res = (&shares[..2]).combine_to_field_element::<G::Scalar, [(G::Scalar, G::Scalar); 2]>();
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, secret_1);

    // Zero is a special case so make sure it works
    let secret = G::Scalar::ZERO;
    let res = TesterVsss::<G, I, S>::split_secret(2, 3, secret, &mut rng);
    assert!(res.is_ok());
    let shares = res.unwrap();

    let res = (&shares[..2]).combine_to_field_element::<G::Scalar, [(G::Scalar, G::Scalar); 2]>();
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, secret_1);

    // Feldman test
    let res = TesterVsss::<G, I, S>::split_secret_with_verifier(2, 3, secret, None, &mut rng);
    assert!(res.is_ok());
    let (shares, verifier) = res.unwrap();
    for s in &shares[..3] {
        assert!(verifier.verify_share(s).is_ok());
    }
    // make sure no malicious share works
    let mut bad_share = shares[0].clone();
    repr.as_mut().iter_mut().for_each(|b| *b = 1u8);
    bad_share.value_mut(repr.as_ref()).unwrap();
    assert!(verifier.verify_share(&bad_share).is_err());

    let res = (&shares[..2]).combine_to_field_element::<G::Scalar, [(G::Scalar, G::Scalar); 2]>();
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, secret_1);

    let res = TesterVsss::<G, I, S>::split_secret_with_blind_verifier(
        2, 3, secret, None, None, None, &mut rng,
    );
    assert!(res.is_ok());
    let p_res = res.unwrap();
    for (s, b) in p_res.secret_shares[..3]
        .iter()
        .zip(p_res.blinder_shares[..3].iter())
    {
        assert!(p_res
            .pedersen_verifier_set
            .verify_share_and_blinder(s, b)
            .is_ok());
    }
    assert!(p_res
        .pedersen_verifier_set
        .verify_share_and_blinder(&bad_share, &bad_share)
        .is_err());

    let res = (&shares[..2]).combine_to_field_element::<G::Scalar, [(G::Scalar, G::Scalar); 2]>();
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, secret_1);
}

#[cfg(any(feature = "alloc", feature = "std"))]
pub fn combine_all<
    G: Group + GroupEncoding + Default,
    I: ShareIdentifier,
    S: Share<Identifier = I>,
>() {
    use crate::*;
    use rand::rngs::OsRng;
    const THRESHOLD: usize = 3;
    const LIMIT: usize = 5;

    let mut rng = OsRng::default();
    let secret: G::Scalar = G::Scalar::random(&mut rng);

    let res = shamir::split_secret(THRESHOLD, LIMIT, secret, &mut rng);
    assert!(res.is_ok());
    let shares: Vec<S> = res.unwrap();

    let res = feldman::split_secret::<G, I, S>(THRESHOLD, LIMIT, secret, None, &mut rng);
    assert!(res.is_ok());
    let (feldman_shares, verifier) = res.unwrap();

    let res = pedersen::split_secret(THRESHOLD, LIMIT, secret, None, None, None, &mut rng);
    assert!(res.is_ok());
    let ped_res: StdPedersenResult<G, I, S> = res.unwrap();

    for (i, s) in shares.iter().enumerate() {
        assert!(verifier.verify_share(s).is_err());
        assert!(ped_res.feldman_verifier_set().verify_share(s).is_err());

        assert!(verifier.verify_share(&feldman_shares[i]).is_ok());
        assert!(ped_res
            .pedersen_verifier_set()
            .verify_share_and_blinder(&ped_res.secret_shares()[i], &ped_res.blinder_shares()[i])
            .is_ok());
    }

    // There is 5*4*3 possible choices
    // try them all. May take a while
    for i in 0..5 {
        for j in 0..5 {
            if i == j {
                continue;
            }

            for k in 0..5 {
                if k == i || k == j {
                    continue;
                }

                let parts = &[shares[i].clone(), shares[j].clone(), shares[k].clone()];

                let res = combine_shares(parts);
                assert!(res.is_ok());
                let secret_1 = res.unwrap();
                assert_eq!(secret, secret_1);

                let parts = &[
                    feldman_shares[i].clone(),
                    feldman_shares[j].clone(),
                    feldman_shares[k].clone(),
                ];

                let res = combine_shares(parts);
                assert!(res.is_ok());
                let secret_1 = res.unwrap();
                assert_eq!(secret, secret_1);

                let parts = &[
                    ped_res.secret_shares()[i].clone(),
                    ped_res.secret_shares()[j].clone(),
                    ped_res.secret_shares()[k].clone(),
                ];

                let res = combine_shares(parts);
                assert!(res.is_ok());
                let secret_1 = res.unwrap();
                assert_eq!(secret, secret_1);
            }
        }
    }
}
