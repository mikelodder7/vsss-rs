/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{tests::utils::MockRng, util::bytes_to_field, Feldman, Pedersen, Shamir};
use ff::PrimeField;
use group::{Group, GroupEncoding, ScalarMul};

type Shamir23 = Shamir<2, 3>;
type Feldman23 = Feldman<2, 3>;
type Pedersen23 = Pedersen<2, 3>;

pub fn combine_single<
    F: PrimeField,
    G: Group + GroupEncoding + Default + ScalarMul<F>,
    const S: usize,
>() {
    let secret: F = bytes_to_field(b"hello").unwrap();
    let mut rng = MockRng::default();
    let res = Shamir23::split_secret::<F, MockRng, S>(secret, &mut rng);
    assert!(res.is_ok());
    let shares = res.unwrap();

    let res = Shamir23::combine_shares::<F, S>(&shares);
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, secret_1);

    // Feldman test
    let res = Feldman23::split_secret::<F, G, MockRng, S>(secret, None, &mut rng);
    assert!(res.is_ok());
    let (shares, verifier) = res.unwrap();
    for s in &shares {
        assert!(verifier.verify(s));
    }
    let res = Shamir23::combine_shares::<F, S>(&shares);
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, secret_1);

    // Pedersen test
    let res = Pedersen23::split_secret::<F, G, MockRng, S>(secret, None, None, None, &mut rng);
    assert!(res.is_ok());
    let p_res = res.unwrap();
    for (i, s) in p_res.secret_shares.iter().enumerate() {
        assert!(p_res.verifier.verify(s, &p_res.blind_shares[i]));
    }
    let res = Shamir23::combine_shares::<F, S>(&shares);
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, secret_1);
}

pub fn combine_all<
    F: PrimeField,
    G: Group + GroupEncoding + Default + ScalarMul<F>,
    const S: usize,
>() {
    use rand::rngs::OsRng;

    let mut rng = OsRng::default();
    let secret: F = F::random(&mut rng);

    let res = Shamir::<3, 5>::split_secret::<F, OsRng, S>(secret, &mut rng);
    assert!(res.is_ok());
    let shares = res.unwrap();

    let res = Feldman::<3, 5>::split_secret::<F, G, OsRng, S>(secret, None, &mut rng);
    assert!(res.is_ok());
    let (feldman_shares, verifier) = res.unwrap();

    let res = Pedersen::<3, 5>::split_secret::<F, G, OsRng, S>(secret, None, None, None, &mut rng);
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

                let parts = &[shares[i], shares[j], shares[k]];

                let res = Shamir::<3, 5>::combine_shares(parts);
                assert!(res.is_ok());
                let secret_1 = res.unwrap();
                assert_eq!(secret, secret_1);

                let parts = &[feldman_shares[i], feldman_shares[j], feldman_shares[k]];

                let res = Feldman::<3, 5>::combine_shares(parts);
                assert!(res.is_ok());
                let secret_1 = res.unwrap();
                assert_eq!(secret, secret_1);

                let parts = &[
                    ped_res.secret_shares[i],
                    ped_res.secret_shares[j],
                    ped_res.secret_shares[k],
                ];

                let res = Pedersen::<3, 5>::combine_shares(parts);
                assert!(res.is_ok());
                let secret_1 = res.unwrap();
                assert_eq!(secret, secret_1);
            }
        }
    }
}
