/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Feldman's Verifiable secret sharing scheme.
//! see <https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf>.
use crate::shamir::{
    create_shares_with_participant_generators, create_shares_with_participant_generators_iter,
    create_shares_with_participant_ids_iter,
};
use crate::*;
use core::{
    marker::PhantomData,
    ops::{Add, Sub},
};
use generic_array::{
    ArrayLength, GenericArray,
    typenum::{Add1, B1, Sub1},
};
use hybrid_array::{Array, ArraySize};
use rand_core::CryptoRng;

/// A secret sharing scheme that uses feldman commitments as verifiers
/// (see [FeldmanVSS](https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf))
pub trait Feldman<S, V>: Shamir<S>
where
    S: Share,
    V: ShareVerifier<S>,
{
    /// The verifier set
    type VerifierSet: FeldmanVerifierSet<S, V>;

    /// Create shares from a secret.
    /// `generator` is a share verifier for computing feldman verifiers.
    /// If [`None`], the default generator is used.
    fn split_secret_with_verifier(
        threshold: usize,
        limit: usize,
        secret: &S::Value,
        generator: Option<V>,
        rng: impl CryptoRng,
    ) -> VsssResult<(Self::ShareSet, Self::VerifierSet)> {
        Self::split_secret_with_participant_generators_and_verifiers(
            threshold,
            limit,
            secret,
            generator,
            rng,
            &[ParticipantIdGenerator::<S::Identifier>::default()],
        )
    }

    /// Create shares from a secret and participant number generators.
    /// `generator` is a share verifier for computing feldman verifiers.
    /// If [`None`], the default generator is used.
    fn split_secret_with_participant_generators_and_verifiers(
        threshold: usize,
        limit: usize,
        secret: &S::Value,
        generator: Option<V>,
        rng: impl CryptoRng,
        participant_generators: &[ParticipantIdGenerator<S::Identifier>],
    ) -> VsssResult<(Self::ShareSet, Self::VerifierSet)> {
        check_params(threshold, limit)?;
        let g = generator.unwrap_or_else(V::one);
        if g.is_zero().into() {
            return Err(Error::InvalidGenerator(
                "Generator cannot be the identity element",
            ));
        }
        let mut polynomial = Self::InnerPolynomial::create(threshold);
        polynomial.fill(secret, rng, threshold)?;
        let mut verifier_set = Self::VerifierSet::empty_feldman_set_with_capacity(threshold, g);
        // Generate the verifiable commitments to the polynomial for the shares
        // Each share is multiple of the polynomial and the specified generator point.
        // {g^p0, g^p1, g^p2, ..., g^pn}
        let coefficients = polynomial.coefficients();
        let verifiers = verifier_set.verifiers_mut();
        verifiers[0] = g * coefficients[0].value();
        for i in 1..threshold {
            verifiers[i] = g * coefficients[i].identifier();
        }
        let shares = create_shares_with_participant_generators(
            &polynomial,
            threshold,
            limit,
            participant_generators,
        )?;
        Ok((shares, verifier_set))
    }

    /// Create shares from a secret and participant number generators.
    /// `generator` is a share verifier for computing feldman verifiers.
    /// If [`None`], the default generator is used.
    #[deprecated(note = "renamed to split_secret_with_participant_generators_and_verifiers")]
    fn split_secret_with_participant_generator_and_verifiers(
        threshold: usize,
        limit: usize,
        secret: &S::Value,
        generator: Option<V>,
        rng: impl CryptoRng,
        participant_generators: &[ParticipantIdGenerator<S::Identifier>],
    ) -> VsssResult<(Self::ShareSet, Self::VerifierSet)> {
        Self::split_secret_with_participant_generators_and_verifiers(
            threshold,
            limit,
            secret,
            generator,
            rng,
            participant_generators,
        )
    }

    /// Create shares from a secret and an iterator of participant identifiers.
    /// `generator` is a share verifier for computing feldman verifiers.
    /// If [`None`], the default generator is used.
    fn split_secret_with_participant_ids_iter_and_verifiers(
        threshold: usize,
        limit: usize,
        secret: &S::Value,
        generator: Option<V>,
        rng: impl CryptoRng,
        participant_ids: impl IntoIterator<Item = S::Identifier>,
    ) -> VsssResult<(Self::ShareSet, Self::VerifierSet)> {
        check_params(threshold, limit)?;
        let g = generator.unwrap_or_else(V::one);
        if g.is_zero().into() {
            return Err(Error::InvalidGenerator(
                "Generator cannot be the identity element",
            ));
        }
        let mut polynomial = Self::InnerPolynomial::create(threshold);
        polynomial.fill(secret, rng, threshold)?;
        let mut verifier_set = Self::VerifierSet::empty_feldman_set_with_capacity(threshold, g);
        let coefficients = polynomial.coefficients();
        let verifiers = verifier_set.verifiers_mut();
        verifiers[0] = g * coefficients[0].value();
        for i in 1..threshold {
            verifiers[i] = g * coefficients[i].identifier();
        }
        let shares = create_shares_with_participant_ids_iter(
            &polynomial,
            threshold,
            limit,
            participant_ids,
        )?;
        Ok((shares, verifier_set))
    }
}

/// A default feldman implementation using [`GenericArray`]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub struct GenericArrayFeldmanVsss<S, V, THRESHOLD, SHARES>
where
    S: Share,
    V: ShareVerifier<S>,
    SHARES: ArrayLength,
    THRESHOLD: Add<B1> + ArrayLength,
    Add1<THRESHOLD>: ArrayLength + Sub<B1, Output = THRESHOLD>,
    Sub1<Add1<THRESHOLD>>: ArrayLength,
{
    /// Marker for the share type
    pub marker: PhantomData<(S, V, Add1<THRESHOLD>, SHARES)>,
}

impl<S, V, THRESHOLD, SHARES> Shamir<S> for GenericArrayFeldmanVsss<S, V, THRESHOLD, SHARES>
where
    S: Share,
    V: ShareVerifier<S>,
    SHARES: ArrayLength,
    THRESHOLD: Add<B1> + ArrayLength,
    Add1<THRESHOLD>: ArrayLength + Sub<B1, Output = THRESHOLD>,
    Sub1<Add1<THRESHOLD>>: ArrayLength,
{
    type InnerPolynomial = GenericArray<S, THRESHOLD>;
    type ShareSet = GenericArray<S, SHARES>;
}

impl<S, V, THRESHOLD, SHARES> Feldman<S, V> for GenericArrayFeldmanVsss<S, V, THRESHOLD, SHARES>
where
    S: Share,
    V: ShareVerifier<S>,
    SHARES: ArrayLength,
    THRESHOLD: Add<B1> + ArrayLength,
    Add1<THRESHOLD>: ArrayLength + Sub<B1, Output = THRESHOLD>,
    Sub1<Add1<THRESHOLD>>: ArrayLength,
{
    type VerifierSet = GenericArray<V, Add1<THRESHOLD>>;
}

/// A default feldman implementation using [`Array`]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub struct HybridArrayFeldmanVsss<S, V, THRESHOLD, SHARES>
where
    S: Share,
    V: ShareVerifier<S>,
    SHARES: ArraySize,
    THRESHOLD: Add<B1> + ArraySize,
    Add1<THRESHOLD>: ArraySize + Sub<B1, Output = THRESHOLD>,
    Sub1<Add1<THRESHOLD>>: ArraySize,
{
    /// Marker for the share type
    pub marker: PhantomData<(S, V, Add1<THRESHOLD>, SHARES)>,
}

impl<S, V, THRESHOLD, SHARES> Shamir<S> for HybridArrayFeldmanVsss<S, V, THRESHOLD, SHARES>
where
    S: Share,
    V: ShareVerifier<S>,
    SHARES: ArraySize,
    THRESHOLD: Add<B1> + ArraySize,
    Add1<THRESHOLD>: ArraySize + Sub<B1, Output = THRESHOLD>,
    Sub1<Add1<THRESHOLD>>: ArraySize,
{
    type InnerPolynomial = Array<S, THRESHOLD>;
    type ShareSet = Array<S, SHARES>;
}

impl<S, V, THRESHOLD, SHARES> Feldman<S, V> for HybridArrayFeldmanVsss<S, V, THRESHOLD, SHARES>
where
    S: Share,
    V: ShareVerifier<S>,
    SHARES: ArraySize,
    THRESHOLD: Add<B1> + ArraySize,
    Add1<THRESHOLD>: ArraySize + Sub<B1, Output = THRESHOLD>,
    Sub1<Add1<THRESHOLD>>: ArraySize,
{
    type VerifierSet = Array<V, Add1<THRESHOLD>>;
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret.
/// `generator` is the point to use for computing feldman verifiers.
/// If None, the default generator is used.
pub fn split_secret<S, V>(
    threshold: usize,
    limit: usize,
    secret: &S::Value,
    generator: Option<V>,
    rng: impl CryptoRng,
) -> VsssResult<(Vec<S>, Vec<V>)>
where
    S: Share,
    V: ShareVerifier<S>,
{
    StdVsss::split_secret_with_verifier(threshold, limit, secret, generator, rng)
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret and participant number generators.
pub fn split_secret_with_participant_generators<S, V>(
    threshold: usize,
    limit: usize,
    secret: &S::Value,
    generator: Option<V>,
    rng: impl CryptoRng,
    participant_generators: &[ParticipantIdGenerator<S::Identifier>],
) -> VsssResult<(Vec<S>, Vec<V>)>
where
    S: Share,
    V: ShareVerifier<S>,
{
    StdVsss::split_secret_with_participant_generators_and_verifiers(
        threshold,
        limit,
        secret,
        generator,
        rng,
        participant_generators,
    )
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret and participant number generators.
#[deprecated(note = "renamed to split_secret_with_participant_generators")]
pub fn split_secret_with_participant_generator<S, V>(
    threshold: usize,
    limit: usize,
    secret: &S::Value,
    generator: Option<V>,
    rng: impl CryptoRng,
    participant_generators: &[ParticipantIdGenerator<S::Identifier>],
) -> VsssResult<(Vec<S>, Vec<V>)>
where
    S: Share,
    V: ShareVerifier<S>,
{
    split_secret_with_participant_generators(
        threshold,
        limit,
        secret,
        generator,
        rng,
        participant_generators,
    )
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret and an iterator of participant identifiers.
pub fn split_secret_with_participant_ids_iter<S, V>(
    threshold: usize,
    limit: usize,
    secret: &S::Value,
    generator: Option<V>,
    rng: impl CryptoRng,
    participant_ids: impl IntoIterator<Item = S::Identifier>,
) -> VsssResult<(Vec<S>, Vec<V>)>
where
    S: Share,
    V: ShareVerifier<S>,
{
    StdVsss::split_secret_with_participant_ids_iter_and_verifiers(
        threshold,
        limit,
        secret,
        generator,
        rng,
        participant_ids,
    )
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret and an iterator of participant number generators.
pub fn split_secret_with_participant_generators_iter<'a, S, V>(
    threshold: usize,
    limit: usize,
    secret: &S::Value,
    generator: Option<V>,
    rng: impl CryptoRng,
    participant_generators: impl IntoIterator<Item = ParticipantIdGenerator<'a, S::Identifier>>,
) -> VsssResult<(Vec<S>, Vec<V>)>
where
    S: Share,
    S::Identifier: 'a,
    V: ShareVerifier<S>,
{
    check_params(threshold, limit)?;
    let g = generator.unwrap_or_else(V::one);
    if g.is_zero().into() {
        return Err(Error::InvalidGenerator(
            "Generator cannot be the identity element",
        ));
    }
    let mut polynomial = <Vec<S> as Polynomial<S>>::create(threshold);
    polynomial.fill(secret, rng, threshold)?;
    let mut verifier_set =
        <Vec<V> as FeldmanVerifierSet<S, V>>::empty_feldman_set_with_capacity(threshold, g);
    let coefficients = polynomial.coefficients();
    let verifiers = verifier_set.verifiers_mut();
    verifiers[0] = g * coefficients[0].value();
    for i in 1..threshold {
        verifiers[i] = g * coefficients[i].identifier();
    }
    let shares = create_shares_with_participant_generators_iter(
        &polynomial,
        threshold,
        limit,
        participant_generators,
    )?;
    Ok((shares, verifier_set))
}

#[cfg(test)]
mod tests {
    use super::{
        Feldman, GenericArrayFeldmanVsss, HybridArrayFeldmanVsss, split_secret,
        split_secret_with_participant_generators, split_secret_with_participant_generators_iter,
    };
    use crate::{
        Error, FeldmanVerifierSet, IdentifierPrimeField, ParticipantIdGenerator, PrimeFieldShare,
        ReadableShareSet, StdVsss, ValueGroup,
    };
    use generic_array::typenum::{U2 as GenericU2, U3 as GenericU3};
    use hybrid_array::typenum::{U2 as HybridU2, U3 as HybridU3};
    use k256::{ProjectivePoint, Scalar};
    use rand::{SeedableRng, rngs::StdRng};

    type TestShare = PrimeFieldShare<Scalar>;
    type TestVerifier = ValueGroup<ProjectivePoint>;

    #[test]
    fn feldman_free_functions_verify_and_combine() {
        let mut rng = StdRng::from_seed([0x31u8; 32]);
        let secret = IdentifierPrimeField(Scalar::from(42u64));
        let generator = TestVerifier::generator();

        let (shares, verifiers) =
            split_secret::<TestShare, TestVerifier>(2, 3, &secret, Some(generator), &mut rng)
                .unwrap();
        assert_eq!(shares.combine(), Ok(secret));
        for share in &shares {
            verifiers.verify_share(share).unwrap();
        }

        let participant_generator = ParticipantIdGenerator::Sequential {
            start: IdentifierPrimeField(Scalar::from(10u64)),
            increment: IdentifierPrimeField(Scalar::from(1u64)),
            count: 3,
        };
        let (shares, verifiers) =
            split_secret_with_participant_generators::<TestShare, TestVerifier>(
                2,
                3,
                &secret,
                Some(generator),
                &mut rng,
                &[participant_generator],
            )
            .unwrap();
        assert_eq!(shares[0].identifier.0, Scalar::from(10u64));
        assert_eq!(shares.combine(), Ok(secret));
        verifiers.verify_share(&shares[0]).unwrap();
    }

    #[test]
    fn feldman_generic_hybrid_and_generator_iter_entrypoints_work() {
        let mut rng = StdRng::from_seed([0x33u8; 32]);
        let secret = IdentifierPrimeField(Scalar::from(42u64));
        let generator = TestVerifier::generator();

        let (generic_shares, generic_verifiers) =
            <GenericArrayFeldmanVsss<TestShare, TestVerifier, GenericU2, GenericU3> as Feldman<
                TestShare,
                TestVerifier,
            >>::split_secret_with_verifier(2, 3, &secret, Some(generator), &mut rng)
            .unwrap();
        assert_eq!(generic_shares.combine(), Ok(secret));
        generic_verifiers.verify_share(&generic_shares[0]).unwrap();

        let (hybrid_shares, hybrid_verifiers) =
            <HybridArrayFeldmanVsss<TestShare, TestVerifier, HybridU2, HybridU3> as Feldman<
                TestShare,
                TestVerifier,
            >>::split_secret_with_participant_ids_iter_and_verifiers(
                2,
                3,
                &secret,
                Some(generator),
                &mut rng,
                [1u64, 2, 3].map(|id| IdentifierPrimeField(Scalar::from(id))),
            )
            .unwrap();
        assert_eq!(hybrid_shares.combine(), Ok(secret));
        hybrid_verifiers.verify_share(&hybrid_shares[0]).unwrap();

        let participant_generator = ParticipantIdGenerator::Sequential {
            start: IdentifierPrimeField(Scalar::from(20u64)),
            increment: IdentifierPrimeField(Scalar::from(1u64)),
            count: 3,
        };
        let (shares, verifiers) =
            split_secret_with_participant_generators_iter::<TestShare, TestVerifier>(
                2,
                3,
                &secret,
                Some(generator),
                &mut rng,
                [participant_generator],
            )
            .unwrap();
        assert_eq!(shares[0].identifier.0, Scalar::from(20u64));
        assert_eq!(shares.combine(), Ok(secret));
        verifiers.verify_share(&shares[0]).unwrap();
    }

    #[test]
    fn feldman_trait_and_free_functions_return_errors_for_bad_inputs() {
        let mut rng = StdRng::from_seed([0x32u8; 32]);
        let secret = IdentifierPrimeField(Scalar::from(42u64));
        assert_eq!(
            split_secret::<TestShare, TestVerifier>(
                2,
                3,
                &secret,
                Some(TestVerifier::identity()),
                &mut rng
            ),
            Err(Error::InvalidGenerator(
                "Generator cannot be the identity element"
            ))
        );
        assert_eq!(
            <StdVsss<TestShare, TestVerifier> as Feldman<TestShare, TestVerifier>>::split_secret_with_participant_ids_iter_and_verifiers(
                2,
                3,
                &secret,
                Some(TestVerifier::generator()),
                &mut rng,
                [IdentifierPrimeField(Scalar::from(1u64))]
            ),
            Err(Error::NotEnoughShareIdentifiers)
        );
        assert_eq!(
            split_secret::<TestShare, TestVerifier>(
                1,
                3,
                &secret,
                Some(TestVerifier::generator()),
                &mut rng
            ),
            Err(Error::SharingMinThreshold)
        );
        assert_eq!(
            split_secret_with_participant_generators_iter::<TestShare, TestVerifier>(
                2,
                3,
                &secret,
                Some(TestVerifier::identity()),
                &mut rng,
                [ParticipantIdGenerator::default()]
            ),
            Err(Error::InvalidGenerator(
                "Generator cannot be the identity element"
            ))
        );
    }
}
