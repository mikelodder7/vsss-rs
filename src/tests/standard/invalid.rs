/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::super::utils::MockRng;
use super::*;
use crate::pedersen::{GenericArrayPedersenResult, PedersenOptions};
use elliptic_curve::PrimeField;
use generic_array::typenum::{U1, U2, U3, U8};

pub fn split_invalid_args<S: Share, V: ShareVerifier<S>>() {
    let secret = S::Value::one();
    let mut rng = MockRng::default();
    assert!(FixedArrayVsss8Of15::<S, V>::split_secret(0, 0, &secret, &mut rng).is_err());
    assert!(FixedArrayVsss8Of15::<S, V>::split_secret(3, 2, &secret, &mut rng).is_err());
    assert!(FixedArrayVsss8Of15::<S, V>::split_secret(1, 8, &secret, &mut rng).is_err());

    assert!(
        FixedArrayVsss8Of15::<S, V>::split_secret_with_verifier(0, 0, &secret, None, &mut rng)
            .is_err()
    );
    assert!(
        FixedArrayVsss8Of15::<S, V>::split_secret_with_verifier(3, 2, &secret, None, &mut rng)
            .is_err()
    );
    assert!(
        FixedArrayVsss8Of15::<S, V>::split_secret_with_verifier(1, 8, &secret, None, &mut rng)
            .is_err()
    );

    let participant_generators = [ParticipantIdGeneratorType::default()];
    let options = PedersenOptions {
        secret,
        blinder: None,
        secret_generator: None,
        blinder_generator: None,
        participant_generators: &participant_generators,
    };
    assert!(
        GenericArrayPedersenResult::<S, V, U2, U3>::split_secret_with_blind_verifiers(
            0, 0, &options, &mut rng
        )
        .is_err()
    );
    assert!(
        GenericArrayPedersenResult::<S, V, U3, U2>::split_secret_with_blind_verifiers(
            3, 2, &options, &mut rng
        )
        .is_err()
    );
    assert!(
        GenericArrayPedersenResult::<S, V, U1, U8>::split_secret_with_blind_verifiers(
            1, 8, &options, &mut rng
        )
        .is_err()
    );
}

#[cfg(any(feature = "alloc", feature = "std"))]
pub fn combine_invalid_vec<F: PrimeField>() {
    let shares: [(IdentifierPrimeField<F>, IdentifierPrimeField<F>); 3] =
        std::array::from_fn(|_| (IdentifierPrimeField::zero(), IdentifierPrimeField::zero()));
    assert!(shares.combine().is_err());
}

pub fn combine_invalid<F: PrimeField>() {
    // No secret
    let mut share1 = (IdentifierPrimeField::zero(), IdentifierPrimeField::zero());
    let mut share2 = (
        IdentifierPrimeField::from(F::from(2u64)),
        IdentifierPrimeField::from(F::from(33u64)),
    );
    // Invalid identifier
    assert!([share1, share2].combine().is_err());
    // Duplicate shares
    *share1.identifier_mut() = IdentifierPrimeField::one();
    *share2.identifier_mut() = IdentifierPrimeField::one();
    assert!([share1, share2].combine().is_err());
}
