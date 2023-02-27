/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{tests::utils::MockRng, util::bytes_to_field, Feldman, Pedersen, Shamir, Share};
use elliptic_curve::{
    ff::PrimeField,
    group::{Group, GroupEncoding, ScalarMul},
};
use zeroize::Zeroize;

pub fn combine_single<
    F: PrimeField + Zeroize,
    G: Group + GroupEncoding + Default + ScalarMul<F>,
>() {
    let shamir = Shamir { t: 2, n: 3 };
    let secret: F = bytes_to_field(b"hello").unwrap();
    let mut rng = MockRng::default();
    let res = shamir.split_secret::<F, MockRng>(secret, &mut rng);
    assert!(res.is_ok());
    let shares = res.unwrap();

    let res = shamir.combine_shares::<F>(&shares);
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, secret_1);

    // Feldman test
    let res = Feldman { t: 2, n: 3 }.split_secret::<F, G, MockRng>(secret, None, &mut rng);
    assert!(res.is_ok());
    let (shares, verifier) = res.unwrap();
    for s in &shares {
        assert!(verifier.verify(s));
    }
    let res = shamir.combine_shares::<F>(&shares);
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, secret_1);

    // Pedersen test
    let res =
        Pedersen { t: 2, n: 3 }.split_secret::<F, G, MockRng>(secret, None, None, None, &mut rng);
    assert!(res.is_ok());
    let p_res = res.unwrap();
    for (i, s) in p_res.secret_shares.iter().enumerate() {
        assert!(p_res.verifier.verify(s, &p_res.blind_shares[i]));
    }
    let res = shamir.combine_shares::<F>(&shares);
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, secret_1);

    // Zero is a special case so make sure it works
    let secret = F::zero();
    let res = shamir.split_secret::<F, MockRng>(secret, &mut rng);
    assert!(res.is_ok());
    let shares = res.unwrap();

    let res = shamir.combine_shares::<F>(&shares);
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, secret_1);

    // Feldman test
    let res = Feldman { t: 2, n: 3 }.split_secret::<F, G, MockRng>(secret, None, &mut rng);
    assert!(res.is_ok());
    let (shares, verifier) = res.unwrap();
    for s in &shares {
        assert!(verifier.verify(s));
    }
    // make sure no malicious share works
    let bad_share = Share(vec![1u8; 33]);
    assert!(!verifier.verify(&bad_share));

    let res = shamir.combine_shares::<F>(&shares);
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, secret_1);

    let res =
        Pedersen { t: 2, n: 3 }.split_secret::<F, G, MockRng>(secret, None, None, None, &mut rng);
    assert!(res.is_ok());
    let p_res = res.unwrap();
    for (i, s) in p_res.secret_shares.iter().enumerate() {
        assert!(p_res.verifier.verify(s, &p_res.blind_shares[i]));
    }
    assert!(!p_res.verifier.verify(&bad_share, &bad_share));
    let res = shamir.combine_shares::<F>(&shares);
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, secret_1);
}

pub fn combine_all<F: PrimeField + Zeroize, G: Group + GroupEncoding + Default + ScalarMul<F>>() {
    use rand::rngs::OsRng;

    let shamir = Shamir { t: 3, n: 5 };
    let mut rng = OsRng::default();
    let secret: F = F::random(&mut rng);

    let res = shamir.split_secret::<F, OsRng>(secret, &mut rng);
    assert!(res.is_ok());
    let shares = res.unwrap();

    let res = Feldman { t: 3, n: 5 }.split_secret::<F, G, OsRng>(secret, None, &mut rng);
    assert!(res.is_ok());
    let (feldman_shares, verifier) = res.unwrap();

    let res =
        Pedersen { t: 3, n: 5 }.split_secret::<F, G, OsRng>(secret, None, None, None, &mut rng);
    assert!(res.is_ok());
    let ped_res = res.unwrap();

    for (i, s) in shares.iter().enumerate() {
        assert!(!verifier.verify(s));
        assert!(!ped_res.verifier.feldman_verifier.verify(s));

        assert!(verifier.verify(&feldman_shares[i]));
        assert!(ped_res
            .verifier
            .verify(&ped_res.secret_shares[i], &ped_res.blind_shares[i]));
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

                let res = shamir.combine_shares(parts);
                assert!(res.is_ok());
                let secret_1 = res.unwrap();
                assert_eq!(secret, secret_1);

                let parts = &[
                    feldman_shares[i].clone(),
                    feldman_shares[j].clone(),
                    feldman_shares[k].clone(),
                ];

                let res = Feldman { t: 3, n: 5 }.combine_shares(parts);
                assert!(res.is_ok());
                let secret_1 = res.unwrap();
                assert_eq!(secret, secret_1);

                let parts = &[
                    ped_res.secret_shares[i].clone(),
                    ped_res.secret_shares[j].clone(),
                    ped_res.secret_shares[k].clone(),
                ];

                let res = Pedersen { t: 3, n: 5 }.combine_shares(parts);
                assert!(res.is_ok());
                let secret_1 = res.unwrap();
                assert_eq!(secret, secret_1);
            }
        }
    }
}
