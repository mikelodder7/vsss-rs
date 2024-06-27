/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Secret splitting for Shamir Secret Sharing Scheme
//! and combine methods for field and group elements
use super::*;
use generic_array::{ArrayLength, GenericArray};
use rand_core::{CryptoRng, RngCore};

/// A Polynomial that can create secret shares
pub trait Shamir<F, I, S>
where
    F: PrimeField,
    I: ShareIdentifier,
    S: Share<Identifier = I>,
{
    /// The polynomial for the coefficients
    type InnerPolynomial: Polynomial<F>;
    /// The set of secret shares
    type ShareSet: WriteableShareSet<I, S>;

    /// Create shares from a secret.
    /// `F` is the prime field
    fn split_secret(
        threshold: usize,
        limit: usize,
        secret: F,
        rng: impl RngCore + CryptoRng,
    ) -> VsssResult<Self::ShareSet> {
        check_params(threshold, limit)?;
        let mut polynomial = Self::InnerPolynomial::create(threshold);
        polynomial.fill(secret, rng, threshold)?;
        let ss = create_shares(&polynomial, threshold, limit)?;
        polynomial
            .coefficients_mut()
            .iter_mut()
            .for_each(|c| *c = F::ZERO);
        Ok(ss)
    }

    /// Create shares from a secret and a participant number generator.
    /// `F` is the prime field
    fn split_secret_with_participant_generator<P: ParticipantNumberGenerator<F>>(
        threshold: usize,
        limit: usize,
        secret: F,
        rng: impl RngCore + CryptoRng,
        participant_generator: P,
    ) -> VsssResult<Self::ShareSet> {
        check_params(threshold, limit)?;
        let mut polynomial = Self::InnerPolynomial::create(threshold);
        polynomial.fill(secret, rng, threshold)?;
        let ss = create_shares_with_participant_generator(
            &polynomial,
            threshold,
            limit,
            &participant_generator,
        )?;
        polynomial
            .coefficients_mut()
            .iter_mut()
            .for_each(|c| *c = F::ZERO);
        Ok(ss)
    }
}

pub(crate) fn create_shares_with_participant_generator<F, P, I, S, SS, PP>(
    polynomial: &P,
    threshold: usize,
    limit: usize,
    participant_generator: &PP,
) -> VsssResult<SS>
where
    F: PrimeField,
    P: Polynomial<F>,
    I: ShareIdentifier,
    S: Share<Identifier = I>,
    SS: WriteableShareSet<I, S>,
    PP: ParticipantNumberGenerator<F>,
{
    // Generate the shares of (x, y) coordinates
    // x coordinates are in the range from [1, N+1). 0 is reserved for the secret
    let mut shares = SS::create(limit);
    let indexer = shares.as_mut();

    for (i, s) in indexer.iter_mut().enumerate().take(limit) {
        let x = participant_generator.get_participant_id(i);
        if x.is_zero().into() {
            return Err(Error::SharingInvalidIdentifier);
        }
        let y = polynomial.evaluate(x, threshold);
        let id = I::from_field_element(x)?;
        let share = S::from_field_element(id, y)?;
        *s = share;
    }
    Ok(shares)
}

/// Create the shares for the specified polynomial
pub(crate) fn create_shares<F, P, I, S, SS>(
    polynomial: &P,
    threshold: usize,
    limit: usize,
) -> VsssResult<SS>
where
    F: PrimeField,
    P: Polynomial<F>,
    I: ShareIdentifier,
    S: Share<Identifier = I>,
    SS: WriteableShareSet<I, S>,
{
    // Generate the shares of (x, y) coordinates
    // x coordinates are incremental from [1, N+1). 0 is reserved for the secret
    let mut shares = SS::create(limit);
    let indexer = shares.as_mut();

    let mut x = 1u64;
    for i in indexer.iter_mut().take(limit) {
        let xp = F::from(x);
        let y = polynomial.evaluate(xp, threshold);
        let id = I::from_field_element(xp)?;
        let share = S::from_field_element(id, y)?;
        *i = share;
        x += 1;
    }
    Ok(shares)
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

impl<F: PrimeField, I: ShareIdentifier, S: Share<Identifier = I>, const L: usize> Shamir<F, I, S>
    for [S; L]
{
    type InnerPolynomial = [F; L];
    type ShareSet = [S; L];
}

impl<F, I, S, L> Shamir<F, I, S> for GenericArray<S, L>
where
    F: PrimeField,
    I: ShareIdentifier,
    S: Share<Identifier = I>,
    L: ArrayLength,
{
    type InnerPolynomial = GenericArray<F, L>;
    type ShareSet = GenericArray<S, L>;
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<F: PrimeField, I: ShareIdentifier, S: Share<Identifier = I>> Shamir<F, I, S> for Vec<F> {
    type InnerPolynomial = Vec<F>;
    type ShareSet = Vec<S>;
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret.
pub fn split_secret<F: PrimeField, I: ShareIdentifier, S: Share<Identifier = I>>(
    threshold: usize,
    limit: usize,
    secret: F,
    rng: impl RngCore + CryptoRng,
) -> VsssResult<Vec<S>> {
    StdVsssShamir::split_secret(threshold, limit, secret, rng)
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret and a participant number generator.
pub fn split_secret_with_participant_generator<F, I, S, P>(
    threshold: usize,
    limit: usize,
    secret: F,
    rng: impl RngCore + CryptoRng,
    participant_generator: P,
) -> VsssResult<Vec<S>>
where
    F: PrimeField,
    I: ShareIdentifier,
    S: Share<Identifier = I>,
    P: ParticipantNumberGenerator<F>,
{
    StdVsssShamir::split_secret_with_participant_generator(
        threshold,
        limit,
        secret,
        rng,
        participant_generator,
    )
}

#[cfg(any(feature = "alloc", feature = "std"))]
struct StdVsssShamir<F: PrimeField, I: ShareIdentifier, S: Share<Identifier = I>> {
    _marker: (core::marker::PhantomData<F>, core::marker::PhantomData<S>),
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<F: PrimeField, I: ShareIdentifier, S: Share<Identifier = I>> Shamir<F, I, S>
    for StdVsssShamir<F, I, S>
{
    type InnerPolynomial = Vec<F>;
    type ShareSet = Vec<S>;
}
