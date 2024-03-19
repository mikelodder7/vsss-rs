/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Feldman's Verifiable secret sharing scheme.
//! (see <https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf>.
use crate::shamir::create_shares_with_participant_generator;
use crate::*;
use elliptic_curve::{ff::Field, group::Group};
use rand_core::{CryptoRng, RngCore};

/// A secret sharing scheme that uses feldman commitments as verifiers
/// (see https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf)
pub trait Feldman<G, I, S>: Shamir<G::Scalar, I, S>
where
    G: Group + GroupEncoding + Default,
    I: ShareIdentifier,
    S: Share<Identifier = I>,
{
    /// The verifier set
    type VerifierSet: FeldmanVerifierSet<G>;

    /// Create shares from a secret.
    /// `F` is the prime field
    /// `generator` is the generator point to use for computing feldman verifiers.
    /// If [`None`], the default generator is used.
    fn split_secret_with_verifier(
        threshold: usize,
        limit: usize,
        secret: G::Scalar,
        generator: Option<G>,
        rng: impl RngCore + CryptoRng,
    ) -> VsssResult<(Self::ShareSet, Self::VerifierSet)> {
        check_params(threshold, limit)?;
        let g = generator.unwrap_or_else(G::generator);
        if g.is_identity().into() {
            return Err(Error::InvalidGenerator);
        }
        let mut polynomial = Self::InnerPolynomial::create(threshold);
        polynomial.fill(secret, rng, threshold)?;
        let mut verifier_set = Self::VerifierSet::empty_feldman_set_with_capacity(threshold, g);
        // Generate the verifiable commitments to the polynomial for the shares
        // Each share is multiple of the polynomial and the specified generator point.
        // {g^p0, g^p1, g^p2, ..., g^pn}
        let coefficients = polynomial.coefficients();
        verifier_set
            .verifiers_mut()
            .iter_mut()
            .take(threshold)
            .enumerate()
            .for_each(|(i, vs)| {
                *vs = g * coefficients[i];
            });
        let shares = create_shares(&polynomial, threshold, limit)?;
        polynomial
            .coefficients_mut()
            .iter_mut()
            .take(threshold)
            .for_each(|c| *c = G::Scalar::ZERO);
        Ok((shares, verifier_set))
    }

    /// Create shares from a secret and a participant number generator.
    /// `F` is the prime field
    /// `generator` is the generator point to use for computing feldman verifiers.
    /// If [`None`], the default generator is used.
    fn split_secret_with_participant_generator_and_verifiers<
        P: ParticipantNumberGenerator<G::Scalar>,
    >(
        threshold: usize,
        limit: usize,
        secret: G::Scalar,
        generator: Option<G>,
        rng: impl RngCore + CryptoRng,
        participant_generator: P,
    ) -> VsssResult<(Self::ShareSet, Self::VerifierSet)> {
        check_params(threshold, limit)?;
        let g = generator.unwrap_or_else(G::generator);
        if g.is_identity().into() {
            return Err(Error::InvalidGenerator);
        }
        let mut polynomial = Self::InnerPolynomial::create(threshold);
        polynomial.fill(secret, rng, threshold)?;
        let mut verifier_set = Self::VerifierSet::empty_feldman_set_with_capacity(threshold, g);
        // Generate the verifiable commitments to the polynomial for the shares
        // Each share is multiple of the polynomial and the specified generator point.
        // {g^p0, g^p1, g^p2, ..., g^pn}
        let coefficients = polynomial.coefficients();
        verifier_set
            .verifiers_mut()
            .iter_mut()
            .take(threshold)
            .enumerate()
            .for_each(|(i, vs)| {
                *vs = g * coefficients[i];
            });
        let shares = create_shares_with_participant_generator(
            &polynomial,
            threshold,
            limit,
            &participant_generator,
        )?;
        polynomial
            .coefficients_mut()
            .iter_mut()
            .take(threshold)
            .for_each(|c| *c = G::Scalar::ZERO);
        Ok((shares, verifier_set))
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret.
/// `generator` is the point to use for computing feldman verifiers.
/// If None, the default generator is used.
pub fn split_secret<G, I, S>(
    threshold: usize,
    limit: usize,
    secret: G::Scalar,
    generator: Option<G>,
    rng: impl RngCore + CryptoRng,
) -> VsssResult<(Vec<S>, Vec<G>)>
where
    G: Group + GroupEncoding + Default,
    I: ShareIdentifier,
    S: Share<Identifier = I>,
{
    StdVsss::split_secret_with_verifier(threshold, limit, secret, generator, rng)
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret and a participant number generator.
pub fn split_secret_with_participant_generator<G, I, S, P>(
    threshold: usize,
    limit: usize,
    secret: G::Scalar,
    generator: Option<G>,
    rng: impl RngCore + CryptoRng,
    participant_generator: P,
) -> VsssResult<(Vec<S>, Vec<G>)>
where
    G: Group + GroupEncoding + Default,
    I: ShareIdentifier,
    S: Share<Identifier = I>,
    P: ParticipantNumberGenerator<G::Scalar>,
{
    StdVsss::split_secret_with_participant_generator_and_verifiers(
        threshold,
        limit,
        secret,
        generator,
        rng,
        participant_generator,
    )
}
