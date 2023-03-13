/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{tests::utils::MockRng, util::bytes_to_field, *};
use elliptic_curve::{
    ff::PrimeField,
    group::{Group, GroupEncoding, ScalarMul},
};
use zeroize::Zeroize;

pub fn combine_single<
    F: PrimeField + Zeroize,
    G: Group + GroupEncoding + Default + ScalarMul<F>,
>() {
    let secret: F = bytes_to_field(b"hello").unwrap();
    let mut rng = MockRng::default();
    let res = split_secret::<F, _>(2, 3, secret, &mut rng);
    assert!(res.is_ok());
    let shares = res.unwrap();

    let res = combine_shares::<F>(&shares);
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, secret_1);

    // Feldman test
    let res = feldman::split_secret::<F, G, _>(2, 3, secret, None, &mut rng);
    assert!(res.is_ok());
    let (shares, verifier) = res.unwrap();
    for s in &shares {
        assert!(verifier.verify(s).is_ok());
    }
    let res = combine_shares::<F>(&shares);
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, secret_1);

    // Pedersen test
    let res = pedersen::split_secret::<F, G, _>(2, 3, secret, None, None, None, &mut rng);
    assert!(res.is_ok());
    let p_res = res.unwrap();
    for (i, s) in p_res.secret_shares.iter().enumerate() {
        assert!(p_res.verifier.verify(s, &p_res.blind_shares[i]).is_ok());
    }
    let res = combine_shares::<F>(&shares);
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, secret_1);

    // Zero is a special case so make sure it works
    let secret = F::zero();
    let res = split_secret::<F, _>(2, 3, secret, &mut rng);
    assert!(res.is_ok());
    let shares = res.unwrap();

    let res = combine_shares::<F>(&shares);
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, secret_1);

    // Feldman test
    let res = feldman::split_secret::<F, G, _>(2, 3, secret, None, &mut rng);
    assert!(res.is_ok());
    let (shares, verifier) = res.unwrap();
    for s in &shares {
        assert!(verifier.verify(s).is_ok());
    }
    // make sure no malicious share works
    let bad_share = Share(Vec::from_slice(&[1u8; 33]).unwrap());
    assert!(verifier.verify(&bad_share).is_err());

    let res = combine_shares::<F>(&shares);
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, secret_1);

    let res = pedersen::split_secret::<F, G, _>(2, 3, secret, None, None, None, &mut rng);
    assert!(res.is_ok());
    let p_res = res.unwrap();
    for (i, s) in p_res.secret_shares.iter().enumerate() {
        assert!(p_res.verifier.verify(s, &p_res.blind_shares[i]).is_ok());
    }
    assert!(p_res.verifier.verify(&bad_share, &bad_share).is_err());
    let res = combine_shares::<F>(&shares);
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, secret_1);
}

pub fn combine_all<F: PrimeField + Zeroize, G: Group + GroupEncoding + Default + ScalarMul<F>>() {
    use rand::rngs::OsRng;
    const THRESHOLD: usize = 3;
    const LIMIT: usize = 5;

    let mut rng = OsRng::default();
    let secret: F = F::random(&mut rng);

    let res = split_secret::<F, _>(THRESHOLD, LIMIT, secret, &mut rng);
    assert!(res.is_ok());
    let shares = res.unwrap();

    let res = feldman::split_secret::<F, G, _>(THRESHOLD, LIMIT, secret, None, &mut rng);
    assert!(res.is_ok());
    let (feldman_shares, verifier) = res.unwrap();

    let res =
        pedersen::split_secret::<F, G, _>(THRESHOLD, LIMIT, secret, None, None, None, &mut rng);
    assert!(res.is_ok());
    let ped_res = res.unwrap();

    for (i, s) in shares.iter().enumerate() {
        assert!(verifier.verify(s).is_err());
        assert!(ped_res.verifier.feldman_verifier.verify(s).is_err());

        assert!(verifier.verify(&feldman_shares[i]).is_ok());
        assert!(ped_res
            .verifier
            .verify(&ped_res.secret_shares[i], &ped_res.blind_shares[i])
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
                    ped_res.secret_shares[i].clone(),
                    ped_res.secret_shares[j].clone(),
                    ped_res.secret_shares[k].clone(),
                ];

                let res = combine_shares(parts);
                assert!(res.is_ok());
                let secret_1 = res.unwrap();
                assert_eq!(secret, secret_1);
            }
        }
    }
}
