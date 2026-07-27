/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Secret splitting for Shamir Secret Sharing Scheme
//! and combine methods for field and group elements
use super::*;
use generic_array::{ArrayLength, GenericArray};
use hybrid_array::{Array, ArraySize};
use rand_core::CryptoRng;

/// A Polynomial that can create secret shares
pub trait Shamir<S>
where
    S: Share,
{
    /// The polynomial for the coefficients
    type InnerPolynomial: Polynomial<S>;
    /// The set of secret shares
    type ShareSet: WriteableShareSet<S>;

    /// Create shares from a secret.
    fn split_secret(
        threshold: usize,
        limit: usize,
        secret: &S::Value,
        rng: impl CryptoRng,
    ) -> VsssResult<Self::ShareSet> {
        check_params(threshold, limit)?;
        let generator = ParticipantIdGenerator::<S::Identifier>::default();
        Self::split_secret_with_participant_generators(threshold, limit, secret, rng, &[generator])
    }

    /// Create shares from a secret, writing into `out`.
    fn split_secret_in_place(
        threshold: usize,
        secret: &S::Value,
        rng: impl CryptoRng,
        out: &mut [S],
    ) -> VsssResult<()> {
        let generator = ParticipantIdGenerator::<S::Identifier>::default();
        Self::split_secret_with_participant_generators_in_place(
            threshold,
            secret,
            rng,
            &[generator],
            out,
        )
    }

    /// Create shares from a secret and participant number generators.
    /// `F` is the prime field
    fn split_secret_with_participant_generators(
        threshold: usize,
        limit: usize,
        secret: &S::Value,
        rng: impl CryptoRng,
        participant_generators: &[ParticipantIdGenerator<S::Identifier>],
    ) -> VsssResult<Self::ShareSet> {
        check_params(threshold, limit)?;
        let mut polynomial = Self::InnerPolynomial::create(threshold);
        polynomial.fill(secret, rng, threshold)?;
        let ss = create_shares_with_participant_generators(
            &polynomial,
            threshold,
            limit,
            participant_generators,
        )?;
        Ok(ss)
    }

    /// Create shares from a secret and participant number generators, writing into `out`.
    fn split_secret_with_participant_generators_in_place(
        threshold: usize,
        secret: &S::Value,
        rng: impl CryptoRng,
        participant_generators: &[ParticipantIdGenerator<S::Identifier>],
        out: &mut [S],
    ) -> VsssResult<()> {
        check_params(threshold, out.len())?;
        let mut polynomial = Self::InnerPolynomial::create(threshold);
        polynomial.fill(secret, rng, threshold)?;
        create_shares_from_polynomial_with_participant_generators_in_place(
            &polynomial,
            threshold,
            participant_generators,
            out,
        )
    }

    /// Create shares from a secret and participant number generators.
    #[deprecated(note = "renamed to split_secret_with_participant_generators")]
    fn split_secret_with_participant_generator(
        threshold: usize,
        limit: usize,
        secret: &S::Value,
        rng: impl CryptoRng,
        participant_generators: &[ParticipantIdGenerator<S::Identifier>],
    ) -> VsssResult<Self::ShareSet> {
        Self::split_secret_with_participant_generators(
            threshold,
            limit,
            secret,
            rng,
            participant_generators,
        )
    }

    /// Create shares from a secret and an iterator of participant identifiers.
    fn split_secret_with_participant_ids_iter(
        threshold: usize,
        limit: usize,
        secret: &S::Value,
        rng: impl CryptoRng,
        participant_ids: impl IntoIterator<Item = S::Identifier>,
    ) -> VsssResult<Self::ShareSet> {
        check_params(threshold, limit)?;
        let mut polynomial = Self::InnerPolynomial::create(threshold);
        polynomial.fill(secret, rng, threshold)?;
        create_shares_with_participant_ids_iter(&polynomial, threshold, limit, participant_ids)
    }

    /// Create shares from a secret and participant identifiers.
    fn split_secret_with_ids(
        threshold: usize,
        limit: usize,
        secret: &S::Value,
        rng: impl CryptoRng,
        participant_ids: impl IntoIterator<Item = S::Identifier>,
    ) -> VsssResult<Self::ShareSet> {
        Self::split_secret_with_participant_ids_iter(threshold, limit, secret, rng, participant_ids)
    }

    /// Create shares from a secret and an iterator of participant identifiers, writing into `out`.
    fn split_secret_with_participant_ids_iter_in_place(
        threshold: usize,
        secret: &S::Value,
        rng: impl CryptoRng,
        participant_ids: impl IntoIterator<Item = S::Identifier>,
        out: &mut [S],
    ) -> VsssResult<()> {
        check_params(threshold, out.len())?;
        let mut polynomial = Self::InnerPolynomial::create(threshold);
        polynomial.fill(secret, rng, threshold)?;
        create_shares_from_polynomial_in_place(&polynomial, threshold, participant_ids, out)
    }

    /// Create shares from a secret and participant identifiers, writing into `out`.
    fn split_secret_with_ids_in_place(
        threshold: usize,
        secret: &S::Value,
        rng: impl CryptoRng,
        participant_ids: impl IntoIterator<Item = S::Identifier>,
        out: &mut [S],
    ) -> VsssResult<()> {
        Self::split_secret_with_participant_ids_iter_in_place(
            threshold,
            secret,
            rng,
            participant_ids,
            out,
        )
    }
}

pub(crate) fn create_shares_with_participant_generators<P, S, SS>(
    polynomial: &P,
    threshold: usize,
    limit: usize,
    participant_generators: &[ParticipantIdGenerator<S::Identifier>],
) -> VsssResult<SS>
where
    P: Polynomial<S>,
    S: Share,
    SS: WriteableShareSet<S>,
{
    check_params(threshold, limit)?;
    validate_polynomial_params(polynomial, threshold, limit)?;
    // Generate the shares of (x, y) coordinates
    // x coordinates are in the range from [1, N+1). 0 is reserved for the secret
    let mut shares = SS::create(limit);
    if shares.as_mut().len() < limit {
        return Err(Error::InvalidSizeRequest);
    }
    create_shares_from_polynomial_with_participant_generators_in_place(
        polynomial,
        threshold,
        participant_generators,
        &mut shares.as_mut()[..limit],
    )?;
    Ok(shares)
}

/// Create shares from an existing polynomial and participant identifiers.
pub fn create_shares_from_polynomial<P, S, SS>(
    polynomial: &P,
    threshold: usize,
    limit: usize,
    participant_ids: impl IntoIterator<Item = S::Identifier>,
) -> VsssResult<SS>
where
    P: Polynomial<S>,
    S: Share,
    SS: WriteableShareSet<S>,
{
    create_shares_with_participant_ids_iter(polynomial, threshold, limit, participant_ids)
}

/// Create shares from an existing polynomial and participant identifiers.
pub fn shares_from_polynomial<P, S, SS>(
    polynomial: &P,
    threshold: usize,
    limit: usize,
    participant_ids: impl IntoIterator<Item = S::Identifier>,
) -> VsssResult<SS>
where
    P: Polynomial<S>,
    S: Share,
    SS: WriteableShareSet<S>,
{
    create_shares_from_polynomial(polynomial, threshold, limit, participant_ids)
}

/// Create shares from an existing polynomial and participant identifiers, writing into `out`.
pub fn create_shares_from_polynomial_in_place<P, S>(
    polynomial: &P,
    threshold: usize,
    participant_ids: impl IntoIterator<Item = S::Identifier>,
    out: &mut [S],
) -> VsssResult<()>
where
    P: Polynomial<S>,
    S: Share,
{
    validate_polynomial_params(polynomial, threshold, out.len())?;
    let mut participant_id_iter = participant_ids.into_iter();

    for s in out.iter_mut() {
        let id = participant_id_iter
            .next()
            .ok_or(Error::NotEnoughShareIdentifiers)?;
        let mut value = S::Value::default();
        polynomial.evaluate_in_place(&id, threshold, &mut value);
        *s = S::with_identifier_and_value(id, value);
    }
    Ok(())
}

/// Create shares from an existing polynomial and participant identifiers, writing into `out`.
pub fn shares_from_polynomial_in_place<P, S>(
    polynomial: &P,
    threshold: usize,
    participant_ids: impl IntoIterator<Item = S::Identifier>,
    out: &mut [S],
) -> VsssResult<()>
where
    P: Polynomial<S>,
    S: Share,
{
    create_shares_from_polynomial_in_place(polynomial, threshold, participant_ids, out)
}

pub(crate) fn create_shares_with_participant_ids_iter<P, S, SS>(
    polynomial: &P,
    threshold: usize,
    limit: usize,
    participant_ids: impl IntoIterator<Item = S::Identifier>,
) -> VsssResult<SS>
where
    P: Polynomial<S>,
    S: Share,
    SS: WriteableShareSet<S>,
{
    validate_polynomial_params(polynomial, threshold, limit)?;
    let mut shares = SS::create(limit);
    if shares.as_mut().len() < limit {
        return Err(Error::InvalidSizeRequest);
    }
    create_shares_from_polynomial_in_place(
        polynomial,
        threshold,
        participant_ids,
        &mut shares.as_mut()[..limit],
    )?;
    Ok(shares)
}

/// Create shares from an existing polynomial and participant number generators, writing into `out`.
pub fn create_shares_from_polynomial_with_participant_generators_in_place<P, S>(
    polynomial: &P,
    threshold: usize,
    participant_generators: &[ParticipantIdGenerator<S::Identifier>],
    out: &mut [S],
) -> VsssResult<()>
where
    P: Polynomial<S>,
    S: Share,
{
    let participant_id_collection = ParticipantIdGeneratorCollection::from(participant_generators);
    create_shares_from_polynomial_in_place(
        polynomial,
        threshold,
        participant_id_collection.iter(),
        out,
    )
}

/// Create shares from an existing polynomial and participant number generators, writing into `out`.
pub fn shares_from_polynomial_with_generators_in_place<P, S>(
    polynomial: &P,
    threshold: usize,
    participant_generators: &[ParticipantIdGenerator<S::Identifier>],
    out: &mut [S],
) -> VsssResult<()>
where
    P: Polynomial<S>,
    S: Share,
{
    create_shares_from_polynomial_with_participant_generators_in_place(
        polynomial,
        threshold,
        participant_generators,
        out,
    )
}

fn validate_polynomial_params<P, S>(
    polynomial: &P,
    threshold: usize,
    limit: usize,
) -> VsssResult<()>
where
    P: Polynomial<S>,
    S: Share,
{
    check_params(threshold, limit)?;
    if polynomial.coefficients().len() < threshold {
        return Err(Error::InvalidSizeRequest);
    }
    Ok(())
}

#[cfg(any(feature = "alloc", feature = "std"))]
pub(crate) fn create_shares_with_participant_generators_iter<'a, P, S, SS>(
    polynomial: &P,
    threshold: usize,
    limit: usize,
    participant_generators: impl IntoIterator<Item = ParticipantIdGenerator<'a, S::Identifier>>,
) -> VsssResult<SS>
where
    P: Polynomial<S>,
    S: Share,
    S::Identifier: 'a,
    SS: WriteableShareSet<S>,
{
    let participant_generators: Vec<_> = participant_generators.into_iter().collect();
    create_shares_with_participant_generators(
        polynomial,
        threshold,
        limit,
        participant_generators.as_slice(),
    )
}

pub(crate) fn check_params(threshold: usize, limit: usize) -> VsssResult<()> {
    if limit < threshold {
        return Err(Error::SharingLimitLessThanThreshold);
    }
    if threshold < 2 {
        return Err(Error::SharingMinThreshold);
    }
    Ok(())
}

impl<S: Share, const L: usize> Shamir<S> for [S; L] {
    type InnerPolynomial = [S; L];
    type ShareSet = [S; L];
}

impl<S: Share, L: ArrayLength> Shamir<S> for GenericArray<S, L> {
    type InnerPolynomial = GenericArray<S, L>;
    type ShareSet = GenericArray<S, L>;
}

impl<S: Share, L: ArraySize> Shamir<S> for Array<S, L> {
    type InnerPolynomial = Array<S, L>;
    type ShareSet = Array<S, L>;
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S: Share> Shamir<S> for Vec<S> {
    type InnerPolynomial = Vec<S>;
    type ShareSet = Vec<S>;
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret.
pub fn split_secret<S: Share>(
    threshold: usize,
    limit: usize,
    secret: &S::Value,
    rng: impl CryptoRng,
) -> VsssResult<Vec<S>> {
    StdVsssShamir::split_secret(threshold, limit, secret, rng)
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret, writing into `out`.
pub fn split_secret_in_place<S: Share>(
    threshold: usize,
    secret: &S::Value,
    rng: impl CryptoRng,
    out: &mut [S],
) -> VsssResult<()> {
    StdVsssShamir::split_secret_in_place(threshold, secret, rng, out)
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret and participant number generators.
pub fn split_secret_with_participant_generators<S: Share>(
    threshold: usize,
    limit: usize,
    secret: &S::Value,
    rng: impl CryptoRng,
    participant_generators: &[ParticipantIdGenerator<S::Identifier>],
) -> VsssResult<Vec<S>> {
    StdVsssShamir::split_secret_with_participant_generators(
        threshold,
        limit,
        secret,
        rng,
        participant_generators,
    )
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret and participant number generators, writing into `out`.
pub fn split_secret_with_participant_generators_in_place<S: Share>(
    threshold: usize,
    secret: &S::Value,
    rng: impl CryptoRng,
    participant_generators: &[ParticipantIdGenerator<S::Identifier>],
    out: &mut [S],
) -> VsssResult<()> {
    StdVsssShamir::split_secret_with_participant_generators_in_place(
        threshold,
        secret,
        rng,
        participant_generators,
        out,
    )
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret and participant number generators.
#[deprecated(note = "renamed to split_secret_with_participant_generators")]
pub fn split_secret_with_participant_generator<S: Share>(
    threshold: usize,
    limit: usize,
    secret: &S::Value,
    rng: impl CryptoRng,
    participant_generators: &[ParticipantIdGenerator<S::Identifier>],
) -> VsssResult<Vec<S>> {
    split_secret_with_participant_generators(threshold, limit, secret, rng, participant_generators)
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret and an iterator of participant identifiers.
pub fn split_secret_with_participant_ids_iter<S: Share>(
    threshold: usize,
    limit: usize,
    secret: &S::Value,
    rng: impl CryptoRng,
    participant_ids: impl IntoIterator<Item = S::Identifier>,
) -> VsssResult<Vec<S>> {
    StdVsssShamir::split_secret_with_participant_ids_iter(
        threshold,
        limit,
        secret,
        rng,
        participant_ids,
    )
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret and participant identifiers.
pub fn split_secret_with_ids<S: Share>(
    threshold: usize,
    limit: usize,
    secret: &S::Value,
    rng: impl CryptoRng,
    participant_ids: impl IntoIterator<Item = S::Identifier>,
) -> VsssResult<Vec<S>> {
    split_secret_with_participant_ids_iter(threshold, limit, secret, rng, participant_ids)
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret and an iterator of participant identifiers, writing into `out`.
pub fn split_secret_with_participant_ids_iter_in_place<S: Share>(
    threshold: usize,
    secret: &S::Value,
    rng: impl CryptoRng,
    participant_ids: impl IntoIterator<Item = S::Identifier>,
    out: &mut [S],
) -> VsssResult<()> {
    StdVsssShamir::split_secret_with_participant_ids_iter_in_place(
        threshold,
        secret,
        rng,
        participant_ids,
        out,
    )
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret and participant identifiers, writing into `out`.
pub fn split_secret_with_ids_in_place<S: Share>(
    threshold: usize,
    secret: &S::Value,
    rng: impl CryptoRng,
    participant_ids: impl IntoIterator<Item = S::Identifier>,
    out: &mut [S],
) -> VsssResult<()> {
    split_secret_with_participant_ids_iter_in_place(threshold, secret, rng, participant_ids, out)
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret and an iterator of participant number generators.
pub fn split_secret_with_participant_generators_iter<'a, S>(
    threshold: usize,
    limit: usize,
    secret: &S::Value,
    rng: impl CryptoRng,
    participant_generators: impl IntoIterator<Item = ParticipantIdGenerator<'a, S::Identifier>>,
) -> VsssResult<Vec<S>>
where
    S: Share,
    S::Identifier: 'a,
{
    check_params(threshold, limit)?;
    let mut polynomial = <Vec<S> as Polynomial<S>>::create(threshold);
    polynomial.fill(secret, rng, threshold)?;
    create_shares_with_participant_generators_iter(
        &polynomial,
        threshold,
        limit,
        participant_generators,
    )
}

#[cfg(any(feature = "alloc", feature = "std"))]
struct StdVsssShamir<S: Share> {
    _marker: core::marker::PhantomData<S>,
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S: Share> Shamir<S> for StdVsssShamir<S> {
    type InnerPolynomial = Vec<S>;
    type ShareSet = Vec<S>;
}

#[cfg(test)]
mod tests {
    use super::{
        Shamir, StdVsssShamir, check_params, create_shares_from_polynomial,
        create_shares_from_polynomial_in_place, shares_from_polynomial,
        shares_from_polynomial_in_place, shares_from_polynomial_with_generators_in_place,
        split_secret, split_secret_in_place, split_secret_with_ids, split_secret_with_ids_in_place,
        split_secret_with_participant_generators, split_secret_with_participant_generators_iter,
        split_secret_with_participant_ids_iter, split_secret_with_participant_ids_iter_in_place,
    };
    use crate::{
        Error, IdentifierPrimeField, ParticipantIdGenerator, PrimeFieldShare, ReadableShareSet,
        Share,
    };
    use k256::Scalar;
    use rand::{SeedableRng, rngs::StdRng};
    use std::vec::Vec;

    type TestShare = PrimeFieldShare<Scalar>;

    fn share(identifier: u64, value: u64) -> TestShare {
        TestShare::with_identifier_and_value(
            IdentifierPrimeField(Scalar::from(identifier)),
            IdentifierPrimeField(Scalar::from(value)),
        )
    }

    #[test]
    fn check_params_reports_threshold_and_limit_errors() {
        assert_eq!(check_params(1, 3), Err(Error::SharingMinThreshold));
        assert_eq!(
            check_params(3, 2),
            Err(Error::SharingLimitLessThanThreshold)
        );
        assert_eq!(check_params(2, 2), Ok(()));
    }

    #[test]
    fn shamir_free_functions_split_and_combine() {
        let mut rng = StdRng::from_seed([0x51u8; 32]);
        let secret = IdentifierPrimeField(Scalar::from(33u64));
        let shares = split_secret::<TestShare>(2, 3, &secret, &mut rng).unwrap();
        assert_eq!(shares.combine(), Ok(secret));

        let mut shares = [
            TestShare::default(),
            TestShare::default(),
            TestShare::default(),
        ];
        split_secret_in_place::<TestShare>(2, &secret, &mut rng, &mut shares).unwrap();
        assert_eq!(shares.combine(), Ok(secret));

        let ids = [10u64, 11, 12].map(|id| IdentifierPrimeField(Scalar::from(id)));
        let mut shares =
            split_secret_with_participant_ids_iter::<TestShare>(2, 3, &secret, &mut rng, ids)
                .unwrap();
        assert_eq!(shares[0].identifier.0, Scalar::from(10u64));
        assert_eq!(shares.combine(), Ok(secret));

        let ids = [13u64, 14, 15].map(|id| IdentifierPrimeField(Scalar::from(id)));
        split_secret_with_participant_ids_iter_in_place::<TestShare>(
            2,
            &secret,
            &mut rng,
            ids,
            &mut shares,
        )
        .unwrap();
        assert_eq!(shares[0].identifier.0, Scalar::from(13u64));
        assert_eq!(shares.combine(), Ok(secret));

        let generator = ParticipantIdGenerator::Sequential {
            start: IdentifierPrimeField(Scalar::from(20u64)),
            increment: IdentifierPrimeField(Scalar::from(1u64)),
            count: 3,
        };
        let shares = split_secret_with_participant_generators::<TestShare>(
            2,
            3,
            &secret,
            &mut rng,
            &[generator],
        )
        .unwrap();
        assert_eq!(shares[0].identifier.0, Scalar::from(20u64));
        assert_eq!(shares.combine(), Ok(secret));

        let polynomial = [share(0, 33), share(2, 0)];
        let mut shares = [
            TestShare::default(),
            TestShare::default(),
            TestShare::default(),
        ];
        create_shares_from_polynomial_in_place(
            &polynomial,
            2,
            [1u64, 2, 3].map(|id| IdentifierPrimeField(Scalar::from(id))),
            &mut shares,
        )
        .unwrap();
        assert_eq!(shares[0], share(1, 35));
        assert_eq!(shares.combine(), Ok(secret));

        let shares: Vec<TestShare> = create_shares_from_polynomial(
            &polynomial,
            2,
            3,
            [4u64, 5, 6].map(|id| IdentifierPrimeField(Scalar::from(id))),
        )
        .unwrap();
        assert_eq!(shares[0], share(4, 41));
    }

    #[test]
    fn shamir_iterator_generator_wrapper_and_errors_work() {
        let mut rng = StdRng::from_seed([0x52u8; 32]);
        let secret = IdentifierPrimeField(Scalar::from(33u64));
        let generator = ParticipantIdGenerator::Sequential {
            start: IdentifierPrimeField(Scalar::from(30u64)),
            increment: IdentifierPrimeField(Scalar::from(1u64)),
            count: 3,
        };
        let shares = split_secret_with_participant_generators_iter::<TestShare>(
            2,
            3,
            &secret,
            &mut rng,
            [generator],
        )
        .unwrap();
        assert_eq!(shares[0].identifier.0, Scalar::from(30u64));
        assert_eq!(shares.combine(), Ok(secret));

        assert_eq!(
            split_secret_with_participant_ids_iter::<TestShare>(
                2,
                3,
                &secret,
                &mut rng,
                [IdentifierPrimeField(Scalar::from(1u64))]
            ),
            Err(Error::NotEnoughShareIdentifiers)
        );
        assert_eq!(
            <StdVsssShamir<TestShare> as Shamir<TestShare>>::split_secret(1, 3, &secret, &mut rng),
            Err(Error::SharingMinThreshold)
        );
    }

    #[test]
    fn simplified_shamir_entrypoints_match_long_form_apis() {
        let mut rng = StdRng::from_seed([0x53u8; 32]);
        let secret = IdentifierPrimeField(Scalar::from(44u64));
        let ids = [3u64, 4, 5].map(|id| IdentifierPrimeField(Scalar::from(id)));
        let mut shares = split_secret_with_ids::<TestShare>(2, 3, &secret, &mut rng, ids).unwrap();
        assert_eq!(shares[0].identifier.0, Scalar::from(3u64));
        assert_eq!(shares.combine(), Ok(secret));

        let ids = [6u64, 7, 8].map(|id| IdentifierPrimeField(Scalar::from(id)));
        split_secret_with_ids_in_place::<TestShare>(2, &secret, &mut rng, ids, &mut shares)
            .unwrap();
        assert_eq!(shares[0].identifier.0, Scalar::from(6u64));
        assert_eq!(shares.combine(), Ok(secret));

        let polynomial = [share(0, 44), share(2, 0)];
        let generated: Vec<TestShare> = shares_from_polynomial(
            &polynomial,
            2,
            3,
            [1u64, 2, 3].map(|id| IdentifierPrimeField(Scalar::from(id))),
        )
        .unwrap();
        assert_eq!(generated[0], share(1, 46));

        shares_from_polynomial_in_place(
            &polynomial,
            2,
            [4u64, 5, 6].map(|id| IdentifierPrimeField(Scalar::from(id))),
            &mut shares,
        )
        .unwrap();
        assert_eq!(shares[0], share(4, 52));

        let generator = ParticipantIdGenerator::Sequential {
            start: IdentifierPrimeField(Scalar::from(9u64)),
            increment: IdentifierPrimeField(Scalar::from(1u64)),
            count: 3,
        };
        shares_from_polynomial_with_generators_in_place(&polynomial, 2, &[generator], &mut shares)
            .unwrap();
        assert_eq!(shares[0], share(9, 62));
    }
}
