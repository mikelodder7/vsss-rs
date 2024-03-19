/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Pedersen's Verifiable secret sharing scheme.
//! (see <https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF>)
//!
//! Pedersen returns both Pedersen verifiers and Feldman verifiers for the purpose
//! that both may be needed for other protocols like Gennaro's DKG. Otherwise,
//! the Feldman verifiers may be discarded.
use crate::shamir::create_shares_with_participant_generator;
use crate::*;
use elliptic_curve::{ff::Field, group::Group};
use rand_core::{CryptoRng, RngCore};

/// A secret sharing scheme that uses pedersen commitments as verifiers
/// (see https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF)
pub trait Pedersen<G, I, S>: Shamir<G::Scalar, I, S>
where
    G: Group + GroupEncoding + Default,
    I: ShareIdentifier,
    S: Share<Identifier = I>,
{
    /// The feldman verifier set
    type FeldmanVerifierSet: FeldmanVerifierSet<G>;
    /// The pedersen verifier set
    type PedersenVerifierSet: PedersenVerifierSet<G>;
    /// The result from running `split_secret_with_verifier`
    type PedersenResult: PedersenResult<
        G,
        I,
        S,
        ShareSet = <Self as Shamir<G::Scalar, I, S>>::ShareSet,
        FeldmanVerifierSet = Self::FeldmanVerifierSet,
        PedersenVerifierSet = Self::PedersenVerifierSet,
    >;

    /// Create shares from a secret.
    /// `blinder` is the blinding factor.
    /// If [`None`], a random value is generated in G::Scalar.
    /// `secret_generator` is the generator point to use for shares.
    /// If [`None`], the default generator is used.
    /// `blinder_generator` is the generator point to use for blinder shares.
    /// If [`None`], a random generator is used
    ///
    /// Returns the secret shares, blinder, blinder shares, and the verifiers
    fn split_secret_with_blind_verifier(
        threshold: usize,
        limit: usize,
        secret: G::Scalar,
        blinder: Option<G::Scalar>,
        secret_generator: Option<G>,
        blinder_generator: Option<G>,
        mut rng: impl RngCore + CryptoRng,
    ) -> VsssResult<Self::PedersenResult> {
        check_params(threshold, limit)?;
        let g = secret_generator.unwrap_or_else(G::generator);
        let h = blinder_generator.unwrap_or_else(|| G::random(&mut rng));
        if (g.is_identity() | h.is_identity()).into() {
            return Err(Error::InvalidGenerator);
        }
        let blinder = blinder.unwrap_or_else(|| G::Scalar::random(&mut rng));

        let mut secret_polynomial = Self::InnerPolynomial::create(threshold);
        let mut blinder_polynomial = Self::InnerPolynomial::create(threshold);
        secret_polynomial.fill(secret, &mut rng, threshold)?;
        blinder_polynomial.fill(blinder, &mut rng, threshold)?;

        let mut feldman_verifier_set =
            Self::FeldmanVerifierSet::empty_feldman_set_with_capacity(threshold, g);
        let mut pedersen_verifier_set =
            Self::PedersenVerifierSet::empty_pedersen_set_with_capacity(threshold, g, h);
        // Generate the verifiable commitments to the polynomial for the shares
        // Each share is multiple of the polynomial and the specified generator point.
        // {g^p0, g^p1, g^p2, ..., g^pn}
        let secret_coefficients = secret_polynomial.coefficients();
        let blinder_coefficients = blinder_polynomial.coefficients();
        for (i, (fvs, pvs)) in feldman_verifier_set
            .verifiers_mut()
            .iter_mut()
            .zip(pedersen_verifier_set.blind_verifiers_mut().iter_mut())
            .take(threshold)
            .enumerate()
        {
            *fvs = g * secret_coefficients[i];
            *pvs = *fvs + h * blinder_coefficients[i];
        }
        let secret_shares = create_shares(&secret_polynomial, threshold, limit)?;
        let blinder_shares = create_shares(&blinder_polynomial, threshold, limit)?;
        secret_polynomial
            .coefficients_mut()
            .iter_mut()
            .take(threshold)
            .for_each(|s| *s = G::Scalar::ZERO);
        blinder_polynomial
            .coefficients_mut()
            .iter_mut()
            .take(threshold)
            .for_each(|s| *s = G::Scalar::ZERO);
        Ok(Self::PedersenResult::new(
            blinder,
            secret_shares,
            blinder_shares,
            feldman_verifier_set,
            pedersen_verifier_set,
        ))
    }

    /// Create shares from a secret and a participant number generator.
    /// `blinder` is the blinding factor.
    /// If [`None`], a random value is generated in G::Scalar.
    /// `secret_generator` is the generator point to use for shares.
    /// If [`None`], the default generator is used.
    /// `blinder_generator` is the generator point to use for blinder shares.
    /// If [`None`], a random generator is used
    ///
    /// Returns the secret shares, blinder, blinder shares, and the verifiers
    fn split_secret_with_participant_generator_and_blind_verifiers<
        P: ParticipantNumberGenerator<G::Scalar>,
    >(
        threshold: usize,
        limit: usize,
        secret: G::Scalar,
        blinder: Option<G::Scalar>,
        secret_generator: Option<G>,
        blinder_generator: Option<G>,
        mut rng: impl RngCore + CryptoRng,
        participant_generator: P,
    ) -> VsssResult<Self::PedersenResult> {
        check_params(threshold, limit)?;
        let g = secret_generator.unwrap_or_else(G::generator);
        let h = blinder_generator.unwrap_or_else(|| G::random(&mut rng));
        if (g.is_identity() | h.is_identity()).into() {
            return Err(Error::InvalidGenerator);
        }
        let blinder = blinder.unwrap_or_else(|| G::Scalar::random(&mut rng));

        let mut secret_polynomial = Self::InnerPolynomial::create(threshold);
        let mut blinder_polynomial = Self::InnerPolynomial::create(threshold);
        secret_polynomial.fill(secret, &mut rng, threshold)?;
        blinder_polynomial.fill(blinder, &mut rng, threshold)?;

        let mut feldman_verifier_set =
            Self::FeldmanVerifierSet::empty_feldman_set_with_capacity(threshold, g);
        let mut pedersen_verifier_set =
            Self::PedersenVerifierSet::empty_pedersen_set_with_capacity(threshold, g, h);
        // Generate the verifiable commitments to the polynomial for the shares
        // Each share is multiple of the polynomial and the specified generator point.
        // {g^p0, g^p1, g^p2, ..., g^pn}
        let secret_coefficients = secret_polynomial.coefficients();
        let blinder_coefficients = blinder_polynomial.coefficients();
        for (i, (fvs, pvs)) in feldman_verifier_set
            .verifiers_mut()
            .iter_mut()
            .zip(pedersen_verifier_set.blind_verifiers_mut().iter_mut())
            .take(threshold)
            .enumerate()
        {
            *fvs = g * secret_coefficients[i];
            *pvs = *fvs + h * blinder_coefficients[i];
        }
        let secret_shares = create_shares_with_participant_generator(
            &secret_polynomial,
            threshold,
            limit,
            &participant_generator,
        )?;
        let blinder_shares = create_shares_with_participant_generator(
            &blinder_polynomial,
            threshold,
            limit,
            &participant_generator,
        )?;
        secret_polynomial
            .coefficients_mut()
            .iter_mut()
            .take(threshold)
            .for_each(|s| *s = G::Scalar::ZERO);
        blinder_polynomial
            .coefficients_mut()
            .iter_mut()
            .take(threshold)
            .for_each(|s| *s = G::Scalar::ZERO);
        Ok(Self::PedersenResult::new(
            blinder,
            secret_shares,
            blinder_shares,
            feldman_verifier_set,
            pedersen_verifier_set,
        ))
    }
}

/// A result output from splitting a secret with [`Pedersen`]
pub trait PedersenResult<G, I, S>: Sized
where
    G: Group + GroupEncoding + Default,
    I: ShareIdentifier,
    S: Share<Identifier = I>,
{
    /// The secret shares
    type ShareSet: ReadableShareSet<I, S>;
    /// The feldman verifier set
    type FeldmanVerifierSet: FeldmanVerifierSet<G>;
    /// The pedersen verifier set
    type PedersenVerifierSet: PedersenVerifierSet<G>;

    /// Create a new result
    fn new(
        blinder: G::Scalar,
        secret_shares: Self::ShareSet,
        blinder_shares: Self::ShareSet,
        feldman_verifier_set: Self::FeldmanVerifierSet,
        pedersen_verifier_set: Self::PedersenVerifierSet,
    ) -> Self;

    /// The blinder used by split secret
    fn blinder(&self) -> G::Scalar;

    /// The secret shares generated by split secret
    fn secret_shares(&self) -> &Self::ShareSet;

    /// The blinder shares generated by split secret
    fn blinder_shares(&self) -> &Self::ShareSet;

    /// The feldman verifier set for verifying secrets w/o blinders
    fn feldman_verifier_set(&self) -> &Self::FeldmanVerifierSet;

    /// The pedersen verifier set for verifying secrets w/blinders
    fn pedersen_verifier_set(&self) -> &Self::PedersenVerifierSet;
}

/// The std result to use when an allocator is available
#[cfg(any(feature = "alloc", feature = "std"))]
pub struct StdPedersenResult<G, I, S>
where
    G: Group + GroupEncoding + Default,
    I: ShareIdentifier,
    S: Share<Identifier = I>,
{
    /// The blinder used to create pedersen commitments
    pub(crate) blinder: G::Scalar,
    /// The secret shares
    pub(crate) secret_shares: Vec<S>,
    /// The blinder shares
    pub(crate) blinder_shares: Vec<S>,
    /// The feldman verifiers
    pub(crate) feldman_verifier_set: Vec<G>,
    /// The pedersen verifiers
    pub(crate) pedersen_verifier_set: Vec<G>,
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<G, I, S> PedersenResult<G, I, S> for StdPedersenResult<G, I, S>
where
    G: Group + GroupEncoding + Default,
    I: ShareIdentifier,
    S: Share<Identifier = I>,
{
    type ShareSet = Vec<S>;
    type FeldmanVerifierSet = Vec<G>;
    type PedersenVerifierSet = Vec<G>;

    fn new(
        blinder: G::Scalar,
        secret_shares: Self::ShareSet,
        blinder_shares: Self::ShareSet,
        feldman_verifier_set: Self::FeldmanVerifierSet,
        pedersen_verifier_set: Self::PedersenVerifierSet,
    ) -> Self {
        Self {
            blinder,
            secret_shares,
            blinder_shares,
            feldman_verifier_set,
            pedersen_verifier_set,
        }
    }

    fn blinder(&self) -> G::Scalar {
        self.blinder
    }

    fn secret_shares(&self) -> &Self::ShareSet {
        &self.secret_shares
    }

    fn blinder_shares(&self) -> &Self::ShareSet {
        &self.blinder_shares
    }

    fn feldman_verifier_set(&self) -> &Self::FeldmanVerifierSet {
        &self.feldman_verifier_set
    }

    fn pedersen_verifier_set(&self) -> &Self::PedersenVerifierSet {
        &self.pedersen_verifier_set
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret. [`G::Scalar`] is the prime field blinding is the blinding factor.
/// If None, a random value is generated in [`G::Scalar`].
/// `share_generator` is the generator point to use for shares.
/// If None, the default generator is used.
/// `blind_factor_generator` is the generator point to use for blinding factor shares.
/// If None, a random generator is used
pub fn split_secret<G, I, S>(
    threshold: usize,
    limit: usize,
    secret: G::Scalar,
    blinding: Option<G::Scalar>,
    share_generator: Option<G>,
    blind_factor_generator: Option<G>,
    rng: impl RngCore + CryptoRng,
) -> VsssResult<StdPedersenResult<G, I, S>>
where
    G: Group + GroupEncoding + Default,
    I: ShareIdentifier,
    S: Share<Identifier = I>,
{
    StdVsss::split_secret_with_blind_verifier(
        threshold,
        limit,
        secret,
        blinding,
        share_generator,
        blind_factor_generator,
        rng,
    )
}
