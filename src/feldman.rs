/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Feldman's Verifiable secret sharing scheme.
//! see <https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf>.
use crate::shamir::create_shares_with_participant_generator;
use crate::*;
use core::{
    marker::PhantomData,
    ops::{Add, Sub},
};
use generic_array::{
    typenum::{Add1, Sub1, B1},
    ArrayLength, GenericArray,
};
use rand_core::{CryptoRng, RngCore};

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
        rng: impl RngCore + CryptoRng,
    ) -> VsssResult<(Self::ShareSet, Self::VerifierSet)> {
        Self::split_secret_with_participant_generator_and_verifiers(
            threshold,
            limit,
            secret,
            generator,
            rng,
            &[ParticipantIdGeneratorType::<S::Identifier>::default()],
        )
    }

    /// Create shares from a secret and participant number generators.
    /// `generator` is a share verifier for computing feldman verifiers.
    /// If [`None`], the default generator is used.
    fn split_secret_with_participant_generator_and_verifiers(
        threshold: usize,
        limit: usize,
        secret: &S::Value,
        generator: Option<V>,
        rng: impl RngCore + CryptoRng,
        participant_generators: &[ParticipantIdGeneratorType<S::Identifier>],
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
        let shares = create_shares_with_participant_generator(
            &polynomial,
            threshold,
            limit,
            participant_generators,
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

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret.
/// `generator` is the point to use for computing feldman verifiers.
/// If None, the default generator is used.
pub fn split_secret<S, V>(
    threshold: usize,
    limit: usize,
    secret: &S::Value,
    generator: Option<V>,
    rng: impl RngCore + CryptoRng,
) -> VsssResult<(Vec<S>, Vec<V>)>
where
    S: Share,
    V: ShareVerifier<S>,
{
    StdVsss::split_secret_with_verifier(threshold, limit, secret, generator, rng)
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret and a participant number generator.
pub fn split_secret_with_participant_generator<S, V>(
    threshold: usize,
    limit: usize,
    secret: &S::Value,
    generator: Option<V>,
    rng: impl RngCore + CryptoRng,
    participant_generators: &[ParticipantIdGeneratorType<S::Identifier>],
) -> VsssResult<(Vec<S>, Vec<V>)>
where
    S: Share,
    V: ShareVerifier<S>,
{
    StdVsss::split_secret_with_participant_generator_and_verifiers(
        threshold,
        limit,
        secret,
        generator,
        rng,
        participant_generators,
    )
}
