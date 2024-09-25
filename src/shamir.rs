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
        rng: impl RngCore + CryptoRng,
    ) -> VsssResult<Self::ShareSet> {
        check_params(threshold, limit)?;
        let generator = ParticipantIdGeneratorType::<S::Identifier>::default();
        Self::split_secret_with_participant_generator(threshold, limit, secret, rng, &[generator])
    }

    /// Create shares from a secret and a participant number generator.
    /// `F` is the prime field
    fn split_secret_with_participant_generator(
        threshold: usize,
        limit: usize,
        secret: &S::Value,
        rng: impl RngCore + CryptoRng,
        participant_generators: &[ParticipantIdGeneratorType<S::Identifier>],
    ) -> VsssResult<Self::ShareSet> {
        check_params(threshold, limit)?;
        let mut polynomial = Self::InnerPolynomial::create(threshold);
        polynomial.fill(secret, rng, threshold)?;
        let ss = create_shares_with_participant_generator(
            &polynomial,
            threshold,
            limit,
            participant_generators,
        )?;
        Ok(ss)
    }
}

pub(crate) fn create_shares_with_participant_generator<P, S, SS>(
    polynomial: &P,
    threshold: usize,
    limit: usize,
    participant_generators: &[ParticipantIdGeneratorType<S::Identifier>],
) -> VsssResult<SS>
where
    P: Polynomial<S>,
    S: Share,
    SS: WriteableShareSet<S>,
{
    // Generate the shares of (x, y) coordinates
    // x coordinates are in the range from [1, N+1). 0 is reserved for the secret
    let mut shares = SS::create(limit);
    let indexer = shares.as_mut();

    let mut participant_id_iter = participant_generators
        .iter()
        .map(|g| g.try_into_generator());
    let mut current = participant_id_iter
        .next()
        .ok_or(Error::SharingInvalidIdentifier)??;

    for s in indexer.iter_mut().take(limit) {
        let id = match current.next() {
            Some(x) => x,
            None => {
                current = participant_id_iter
                    .next()
                    .ok_or(Error::SharingInvalidIdentifier)??;
                current.next().ok_or(Error::SharingInvalidIdentifier)?
            }
        };
        if id.is_zero().into() {
            return Err(Error::SharingInvalidIdentifier);
        }
        let value = polynomial.evaluate(&id, threshold);
        let share = S::with_identifier_and_value(id, value);
        *s = share;
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

impl<S: Share, const L: usize> Shamir<S> for [S; L] {
    type InnerPolynomial = [S; L];
    type ShareSet = [S; L];
}

impl<S: Share, L: ArrayLength> Shamir<S> for GenericArray<S, L> {
    type InnerPolynomial = GenericArray<S, L>;
    type ShareSet = GenericArray<S, L>;
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
    rng: impl RngCore + CryptoRng,
) -> VsssResult<Vec<S>> {
    StdVsssShamir::split_secret(threshold, limit, secret, rng)
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret and a participant number generator.
pub fn split_secret_with_participant_generator<S: Share>(
    threshold: usize,
    limit: usize,
    secret: &S::Value,
    rng: impl RngCore + CryptoRng,
    participant_generators: &[ParticipantIdGeneratorType<S::Identifier>],
) -> VsssResult<Vec<S>> {
    StdVsssShamir::split_secret_with_participant_generator(
        threshold,
        limit,
        secret,
        rng,
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
