/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::*;
use crate::pedersen::PedersenOptions;
use crate::tests::utils::MockRng;
use elliptic_curve::{
    ff::{Field, PrimeField},
    group::{Group, GroupEncoding},
};

pub fn combine_single<G: Group + GroupEncoding + Default>() {
    let mut repr = <G::Scalar as PrimeField>::Repr::default();
    repr.as_mut()[..5].copy_from_slice(b"hello");
    let secret = G::Scalar::from_repr(repr).unwrap();
    let mut rng = MockRng::default();
    let res = shamir_split::<G>(2, 3, secret, &mut rng);
    assert!(res.is_ok());
    let shares = res.unwrap();

    let res = (&shares[..3]).combine();
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, *secret_1);

    // Feldman test
    let res = feldman_split::<G>(2, 3, secret, &mut rng);
    assert!(res.is_ok());
    let (shares, verifier) = res.unwrap();
    for s in &shares[..3] {
        assert!(verifier.verify_share(s).is_ok());
    }
    let res = (&shares[..2]).combine();
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, *secret_1);

    // Pedersen test
    let res = pedersen_split::<G>(2, 3, secret, &mut rng);
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
    let res = (&shares[..2]).combine();
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, *secret_1);

    // Zero is a special case so make sure it works
    let secret = G::Scalar::ZERO;
    let res = shamir_split::<G>(2, 3, secret, &mut rng);
    assert!(res.is_ok());
    let shares = res.unwrap();

    let res = (&shares[..2]).combine();
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, *secret_1);

    // Feldman test
    let res = feldman_split::<G>(2, 3, secret, &mut rng);
    assert!(res.is_ok());
    let (shares, verifier) = res.unwrap();
    for s in &shares[..3] {
        assert!(verifier.verify_share(s).is_ok());
    }
    // make sure no malicious share works
    let mut bad_share = shares[0].clone();
    repr.as_mut().iter_mut().for_each(|b| *b = 1u8);
    *bad_share.value_mut() = IdentifierPrimeField(G::Scalar::from_repr(repr).unwrap());
    assert!(verifier.verify_share(&bad_share).is_err());

    let res = (&shares[..2]).combine();
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, *secret_1);

    let res = pedersen_split::<G>(2, 3, secret, &mut rng);
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

    let res = (&shares[..2]).combine();
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, *secret_1);
}

#[cfg(any(feature = "alloc", feature = "std"))]
pub fn combine_all<G: Group + GroupEncoding + Default>() {
    use crate::*;
    use rand::rngs::OsRng;
    const THRESHOLD: usize = 3;
    const LIMIT: usize = 5;

    let mut rng = OsRng::default();
    let secret = IdentifierPrimeField::from(G::Scalar::random(&mut rng));

    let res = shamir::split_secret::<TestShare<G::Scalar>>(THRESHOLD, LIMIT, &secret, &mut rng);
    assert!(res.is_ok());
    let shares = res.unwrap();

    let res = feldman::split_secret::<TestShare<G::Scalar>, ValueGroup<G>>(
        THRESHOLD, LIMIT, &secret, None, &mut rng,
    );
    assert!(res.is_ok());
    let (feldman_shares, verifier) = res.unwrap();

    let res = pedersen::split_secret::<TestShare<G::Scalar>, ValueGroup<G>>(
        THRESHOLD, LIMIT, &secret, None, None, None, &mut rng,
    );
    assert!(res.is_ok());
    let ped_res = res.unwrap();

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

                let res = parts.combine();
                assert!(res.is_ok());
                let secret_1 = res.unwrap();
                assert_eq!(secret, secret_1);

                let parts = &[
                    feldman_shares[i].clone(),
                    feldman_shares[j].clone(),
                    feldman_shares[k].clone(),
                ];

                let res = parts.combine();
                assert!(res.is_ok());
                let secret_1 = res.unwrap();
                assert_eq!(secret, secret_1);

                let parts = &[
                    ped_res.secret_shares()[i].clone(),
                    ped_res.secret_shares()[j].clone(),
                    ped_res.secret_shares()[k].clone(),
                ];

                let res = parts.combine();
                assert!(res.is_ok());
                let secret_1 = res.unwrap();
                assert_eq!(secret, secret_1);
            }
        }
    }
}

fn shamir_split<G: Group + GroupEncoding + Default>(
    threshold: usize,
    limit: usize,
    secret: G::Scalar,
    rng: &mut MockRng,
) -> VsssResult<FixedArrayVsss8Of15ShareSet<TestShare<G::Scalar>, ValueGroup<G>>> {
    let secret = IdentifierPrimeField::from(secret);
    FixedArrayVsss8Of15::<TestShare<G::Scalar>, ValueGroup<G>>::split_secret(
        threshold, limit, &secret, rng,
    )
}

fn feldman_split<G: Group + GroupEncoding + Default>(
    threshold: usize,
    limit: usize,
    secret: G::Scalar,
    rng: &mut MockRng,
) -> VsssResult<(
    FixedArrayVsss8Of15ShareSet<TestShare<G::Scalar>, ValueGroup<G>>,
    FixedArrayVsss8Of15FeldmanVerifierSet<TestShare<G::Scalar>, ValueGroup<G>>,
)> {
    let secret = IdentifierPrimeField::from(secret);
    FixedArrayVsss8Of15::split_secret_with_verifier(threshold, limit, &secret, None, rng)
}

fn pedersen_split<G: Group + GroupEncoding + Default>(
    threshold: usize,
    limit: usize,
    secret: G::Scalar,
    rng: &mut MockRng,
) -> VsssResult<FixedArrayPedersenResult8Of15<TestShare<G::Scalar>, ValueGroup<G>>> {
    let numbering = ParticipantIdGeneratorType::default();
    let options = PedersenOptions {
        secret: IdentifierPrimeField::from(secret),
        blinder: None,
        secret_generator: None,
        blinder_generator: None,
        participant_generators: &[numbering],
    };
    FixedArrayVsss8Of15::split_secret_with_blind_verifiers(threshold, limit, &options, rng)
}
