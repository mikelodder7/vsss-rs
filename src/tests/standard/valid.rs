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
        assert!(
            p_res
                .pedersen_verifier_set
                .verify_share_and_blinder(s, b)
                .is_ok()
        );
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
    let mut bad_share = shares[0];
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
        assert!(
            p_res
                .pedersen_verifier_set
                .verify_share_and_blinder(s, b)
                .is_ok()
        );
    }
    assert!(
        p_res
            .pedersen_verifier_set
            .verify_share_and_blinder(&bad_share, &bad_share)
            .is_err()
    );

    let res = (&shares[..2]).combine();
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, *secret_1);
}

#[cfg(any(feature = "alloc", feature = "std"))]
pub fn combine_all<G: Group + GroupEncoding + Default>() {
    use crate::*;
    use rand::{SeedableRng, rngs::StdRng};
    const THRESHOLD: usize = 3;
    const LIMIT: usize = 5;

    let mut rng = StdRng::from_seed([3u8; 32]);
    let secret = IdentifierPrimeField::from(G::Scalar::random(&mut rng));

    let res = shamir::split_secret::<TestShare<G::Scalar>>(THRESHOLD, LIMIT, &secret, &mut rng);
    assert!(res.is_ok());
    let shares = res.unwrap();

    let participant_generator = ParticipantIdGenerator::default();
    let participant_generators = [participant_generator];
    let participant_ids: Vec<_> = ParticipantIdGeneratorCollection::from(&participant_generators)
        .iter()
        .take(LIMIT)
        .collect();

    let res = shamir::split_secret_with_participant_ids_iter::<TestShare<G::Scalar>>(
        THRESHOLD,
        LIMIT,
        &secret,
        &mut rng,
        participant_ids.clone(),
    );
    assert!(res.is_ok());
    let shares_from_ids = res.unwrap();
    assert_eq!(secret, (&shares_from_ids[..THRESHOLD]).combine().unwrap());

    let res = shamir::split_secret_with_participant_generators_iter::<TestShare<G::Scalar>>(
        THRESHOLD,
        LIMIT,
        &secret,
        &mut rng,
        participant_generators,
    );
    assert!(res.is_ok());
    let shares_from_generators = res.unwrap();
    assert_eq!(
        secret,
        (&shares_from_generators[..THRESHOLD]).combine().unwrap()
    );

    let res = feldman::split_secret::<TestShare<G::Scalar>, ValueGroup<G>>(
        THRESHOLD, LIMIT, &secret, None, &mut rng,
    );
    assert!(res.is_ok());
    let (feldman_shares, verifier) = res.unwrap();

    let res = feldman::split_secret_with_participant_ids_iter::<TestShare<G::Scalar>, ValueGroup<G>>(
        THRESHOLD,
        LIMIT,
        &secret,
        None,
        &mut rng,
        participant_ids.clone(),
    );
    assert!(res.is_ok());
    let (shares_from_ids, verifier_from_ids) = res.unwrap();
    for share in &shares_from_ids {
        assert!(verifier_from_ids.verify_share(share).is_ok());
    }
    assert_eq!(secret, (&shares_from_ids[..THRESHOLD]).combine().unwrap());

    let res = feldman::split_secret_with_participant_generators_iter::<
        TestShare<G::Scalar>,
        ValueGroup<G>,
    >(
        THRESHOLD,
        LIMIT,
        &secret,
        None,
        &mut rng,
        [participant_generator],
    );
    assert!(res.is_ok());
    let (shares_from_generators, verifier_from_generators) = res.unwrap();
    for share in &shares_from_generators {
        assert!(verifier_from_generators.verify_share(share).is_ok());
    }
    assert_eq!(
        secret,
        (&shares_from_generators[..THRESHOLD]).combine().unwrap()
    );

    let res = pedersen::split_secret::<TestShare<G::Scalar>, ValueGroup<G>>(
        THRESHOLD, LIMIT, &secret, None, None, None, &mut rng,
    );
    assert!(res.is_ok());
    let ped_res = res.unwrap();

    let pedersen_options = PedersenOptions {
        secret: &secret,
        blinder: None,
        secret_generator: None,
        blinder_generator: None,
    };
    let res = pedersen::split_secret_with_participant_ids_iter::<TestShare<G::Scalar>, ValueGroup<G>>(
        THRESHOLD,
        LIMIT,
        &pedersen_options,
        &mut rng,
        participant_ids,
    );
    assert!(res.is_ok());
    let ped_from_ids = res.unwrap();
    for (share, blinder) in ped_from_ids
        .secret_shares()
        .iter()
        .zip(ped_from_ids.blinder_shares().iter())
    {
        assert!(
            ped_from_ids
                .pedersen_verifier_set()
                .verify_share_and_blinder(share, blinder)
                .is_ok()
        );
    }

    let res = pedersen::split_secret_with_participant_generators_iter::<
        TestShare<G::Scalar>,
        ValueGroup<G>,
    >(
        THRESHOLD,
        LIMIT,
        &pedersen_options,
        &mut rng,
        [participant_generator],
    );
    assert!(res.is_ok());
    let ped_from_generators = res.unwrap();
    for (share, blinder) in ped_from_generators
        .secret_shares()
        .iter()
        .zip(ped_from_generators.blinder_shares().iter())
    {
        assert!(
            ped_from_generators
                .pedersen_verifier_set()
                .verify_share_and_blinder(share, blinder)
                .is_ok()
        );
    }

    for (i, s) in shares.iter().enumerate() {
        assert!(verifier.verify_share(s).is_err());
        assert!(ped_res.feldman_verifier_set().verify_share(s).is_err());

        assert!(verifier.verify_share(&feldman_shares[i]).is_ok());
        assert!(
            ped_res
                .pedersen_verifier_set()
                .verify_share_and_blinder(&ped_res.secret_shares()[i], &ped_res.blinder_shares()[i])
                .is_ok()
        );
    }

    // There are 5 * 4 * 3 possible choices.
    // Try them all. This may take a while.
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

                let res = parts.combine();
                assert!(res.is_ok());
                let secret_1 = res.unwrap();
                assert_eq!(secret, secret_1);

                let parts = &[feldman_shares[i], feldman_shares[j], feldman_shares[k]];

                let res = parts.combine();
                assert!(res.is_ok());
                let secret_1 = res.unwrap();
                assert_eq!(secret, secret_1);

                let parts = &[
                    ped_res.secret_shares()[i],
                    ped_res.secret_shares()[j],
                    ped_res.secret_shares()[k],
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

type FeldmanSplitResult<G> = VsssResult<(
    FixedArrayVsss8Of15ShareSet<TestShare<<G as Group>::Scalar>, ValueGroup<G>>,
    FixedArrayVsss8Of15FeldmanVerifierSet<TestShare<<G as Group>::Scalar>, ValueGroup<G>>,
)>;

fn feldman_split<G: Group + GroupEncoding + Default>(
    threshold: usize,
    limit: usize,
    secret: G::Scalar,
    rng: &mut MockRng,
) -> FeldmanSplitResult<G> {
    let secret = IdentifierPrimeField::from(secret);
    FixedArrayVsss8Of15::split_secret_with_verifier(threshold, limit, &secret, None, rng)
}

fn pedersen_split<G: Group + GroupEncoding + Default>(
    threshold: usize,
    limit: usize,
    secret: G::Scalar,
    rng: &mut MockRng,
) -> VsssResult<FixedArrayPedersenResult8Of15<TestShare<G::Scalar>, ValueGroup<G>>> {
    let secret = IdentifierPrimeField::from(secret);
    let options = PedersenOptions {
        secret: &secret,
        blinder: None,
        secret_generator: None,
        blinder_generator: None,
    };
    FixedArrayVsss8Of15::split_secret_with_blind_verifiers(threshold, limit, &options, rng)
}
