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
use core::ops::{Add, Sub};
use generic_array::{
    typenum::{Add1, Sub1, B1, U2},
    ArrayLength, GenericArray,
};
use rand_core::{CryptoRng, RngCore};

/// Options for Pedersen secret sharing
#[derive(Debug)]
pub struct PedersenOptions<'a, S: Share, V: ShareVerifier<S>> {
    /// The secret to split
    pub secret: S::Value,
    /// The blinding factor
    pub blinder: Option<S::Value>,
    /// The generator to use for share verifiers
    pub secret_generator: Option<V>,
    /// The generator to use for blinder verifiers
    pub blinder_generator: Option<V>,
    /// The participant id generators to use for shares
    pub participant_generators: &'a [ParticipantIdGeneratorType<'a, S::Identifier>],
}

/// A secret sharing scheme that uses pedersen commitments as verifiers
/// (see https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF)
pub trait Pedersen<S, V>: Shamir<S>
where
    S: Share,
    V: ShareVerifier<S>,
{
    /// The feldman verifier set
    type FeldmanVerifierSet: FeldmanVerifierSet<S, V>;
    /// The pedersen verifier set
    type PedersenVerifierSet: PedersenVerifierSet<S, V>;
    /// The result from running `split_secret_with_verifier`
    type PedersenResult: PedersenResult<
        S,
        V,
        ShareSet = <Self as Shamir<S>>::ShareSet,
        FeldmanVerifierSet = Self::FeldmanVerifierSet,
        PedersenVerifierSet = Self::PedersenVerifierSet,
    >;

    /// Create shares from a secret and options.
    /// `blinder` is the blinding factor.
    /// If [`None`], a random value is generated in S::Value.
    /// `secret_generator` is the generator point to use for shares.
    /// If [`None`], the default generator is used.
    /// `blinder_generator` is the generator point to use for blinder shares.
    /// If [`None`], a random generator is used
    ///
    /// Returns the secret shares, blinder, blinder shares, and the verifiers
    fn split_secret_with_blind_verifiers(
        threshold: usize,
        limit: usize,
        options: &PedersenOptions<S, V>,
        mut rng: impl RngCore + CryptoRng,
    ) -> VsssResult<Self::PedersenResult> {
        check_params(threshold, limit)?;
        let g = options.secret_generator.unwrap_or_else(V::one);
        let h = options
            .blinder_generator
            .unwrap_or_else(|| V::random(&mut rng));
        if (g.is_zero() | h.is_zero()).into() {
            return Err(Error::InvalidGenerator(
                "Pedersen generators cannot be zero",
            ));
        }
        if g == h {
            return Err(Error::InvalidGenerator(
                "Pedersen generators cannot be the same",
            ));
        }
        let blinder = options
            .blinder
            .clone()
            .unwrap_or_else(|| S::Value::random(&mut rng));

        let mut secret_polynomial = Self::InnerPolynomial::create(threshold);
        let mut blinder_polynomial = Self::InnerPolynomial::create(threshold);
        secret_polynomial.fill(&options.secret, &mut rng, threshold)?;
        blinder_polynomial.fill(&blinder, &mut rng, threshold)?;

        let mut feldman_verifier_set =
            Self::FeldmanVerifierSet::empty_feldman_set_with_capacity(threshold, g);
        let mut pedersen_verifier_set =
            Self::PedersenVerifierSet::empty_pedersen_set_with_capacity(threshold, g, h);
        // Generate the verifiable commitments to the polynomial for the shares
        // Each share is multiple of the polynomial and the specified generator point.
        // {g^p0, g^p1, g^p2, ..., g^pn}
        let secret_coefficients = secret_polynomial.coefficients();
        let blinder_coefficients = blinder_polynomial.coefficients();
        let feldman_verifiers = feldman_verifier_set.verifiers_mut();
        let pedersen_verifiers = pedersen_verifier_set.blind_verifiers_mut();

        feldman_verifiers[0] = g * secret_coefficients[0].value();
        pedersen_verifiers[0] = feldman_verifiers[0] + h * blinder_coefficients[0].value();

        for i in 1..threshold {
            feldman_verifiers[i] = g * secret_coefficients[i].identifier();
            pedersen_verifiers[i] = feldman_verifiers[i] + h * blinder_coefficients[i].identifier();
        }
        let secret_shares = create_shares_with_participant_generator(
            &secret_polynomial,
            threshold,
            limit,
            options.participant_generators,
        )?;
        let blinder_shares = create_shares_with_participant_generator(
            &blinder_polynomial,
            threshold,
            limit,
            options.participant_generators,
        )?;
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
pub trait PedersenResult<S, V>: Sized
where
    S: Share,
    V: ShareVerifier<S>,
{
    /// The secret shares
    type ShareSet: ReadableShareSet<S>;
    /// The feldman verifier set
    type FeldmanVerifierSet: FeldmanVerifierSet<S, V>;
    /// The pedersen verifier set
    type PedersenVerifierSet: PedersenVerifierSet<S, V>;

    /// Create a new result
    fn new(
        blinder: S::Value,
        secret_shares: Self::ShareSet,
        blinder_shares: Self::ShareSet,
        feldman_verifier_set: Self::FeldmanVerifierSet,
        pedersen_verifier_set: Self::PedersenVerifierSet,
    ) -> Self;

    /// The blinder used by split secret
    fn blinder(&self) -> &S::Value;

    /// The secret shares generated by split secret
    fn secret_shares(&self) -> &Self::ShareSet;

    /// The blinder shares generated by split secret
    fn blinder_shares(&self) -> &Self::ShareSet;

    /// The feldman verifier set for verifying secrets w/o blinders
    fn feldman_verifier_set(&self) -> &Self::FeldmanVerifierSet;

    /// The pedersen verifier set for verifying secrets w/blinders
    fn pedersen_verifier_set(&self) -> &Self::PedersenVerifierSet;
}

type Add2<A> = <A as Add<U2>>::Output;
type Sub2<A> = <A as Sub<U2>>::Output;
/// The result to use when the sizes are known or computed at compile time
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GenericArrayPedersenResult<S, V, THRESHOLD, SHARES>
where
    S: Share,
    V: ShareVerifier<S>,
    SHARES: ArrayLength,
    THRESHOLD: Add<B1> + Add<U2> + ArrayLength,
    Add1<THRESHOLD>: ArrayLength + Sub<B1, Output = THRESHOLD>,
    Add2<THRESHOLD>: ArrayLength + Sub<U2, Output = THRESHOLD>,
    Sub1<Add1<THRESHOLD>>: ArrayLength,
    Sub2<Add2<THRESHOLD>>: ArrayLength,
{
    /// The blinder used to create pedersen commitments
    pub(crate) blinder: S::Value,
    /// The secret shares
    pub(crate) secret_shares: GenericArray<S, SHARES>,
    /// The blinder shares
    pub(crate) blinder_shares: GenericArray<S, SHARES>,
    /// The feldman verifiers
    pub(crate) feldman_verifier_set: GenericArray<V, Add1<THRESHOLD>>,
    /// The pedersen verifiers
    pub(crate) pedersen_verifier_set: GenericArray<V, Add2<THRESHOLD>>,
}

impl<S, V, THRESHOLD, SHARES> PedersenResult<S, V>
    for GenericArrayPedersenResult<S, V, THRESHOLD, SHARES>
where
    S: Share,
    V: ShareVerifier<S>,
    SHARES: ArrayLength,
    THRESHOLD: Add<B1> + Add<U2> + ArrayLength,
    Add1<THRESHOLD>: ArrayLength + Sub<B1, Output = THRESHOLD>,
    Add2<THRESHOLD>: ArrayLength + Sub<U2, Output = THRESHOLD>,
    Sub1<Add1<THRESHOLD>>: ArrayLength,
    Sub2<Add2<THRESHOLD>>: ArrayLength,
{
    type ShareSet = GenericArray<S, SHARES>;
    type FeldmanVerifierSet = GenericArray<V, Add1<THRESHOLD>>;
    type PedersenVerifierSet = GenericArray<V, Add2<THRESHOLD>>;

    fn new(
        blinder: S::Value,
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

    fn blinder(&self) -> &S::Value {
        &self.blinder
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

impl<S, V, THRESHOLD, SHARES> Shamir<S> for GenericArrayPedersenResult<S, V, THRESHOLD, SHARES>
where
    S: Share,
    V: ShareVerifier<S>,
    SHARES: ArrayLength,
    THRESHOLD: Add<B1> + Add<U2> + ArrayLength,
    Add1<THRESHOLD>: ArrayLength + Sub<B1, Output = THRESHOLD>,
    Add2<THRESHOLD>: ArrayLength + Sub<U2, Output = THRESHOLD>,
    Sub1<Add1<THRESHOLD>>: ArrayLength,
    Sub2<Add2<THRESHOLD>>: ArrayLength,
{
    type InnerPolynomial = GenericArray<S, THRESHOLD>;
    type ShareSet = GenericArray<S, SHARES>;
}

impl<S, V, THRESHOLD, SHARES> Pedersen<S, V> for GenericArrayPedersenResult<S, V, THRESHOLD, SHARES>
where
    S: Share,
    V: ShareVerifier<S>,
    SHARES: ArrayLength,
    THRESHOLD: Add<B1> + Add<U2> + ArrayLength,
    Add1<THRESHOLD>: ArrayLength + Sub<B1, Output = THRESHOLD>,
    Add2<THRESHOLD>: ArrayLength + Sub<U2, Output = THRESHOLD>,
    Sub1<Add1<THRESHOLD>>: ArrayLength,
    Sub2<Add2<THRESHOLD>>: ArrayLength,
{
    type FeldmanVerifierSet = GenericArray<V, Add1<THRESHOLD>>;
    type PedersenVerifierSet = GenericArray<V, Add2<THRESHOLD>>;
    type PedersenResult = Self;
}

/// The result to use when an allocator is available
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Clone)]
pub struct StdPedersenResult<S, V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    /// The blinder used to create pedersen commitments
    pub(crate) blinder: S::Value,
    /// The secret shares
    pub(crate) secret_shares: Vec<S>,
    /// The blinder shares
    pub(crate) blinder_shares: Vec<S>,
    /// The feldman verifiers
    pub(crate) feldman_verifier_set: Vec<V>,
    /// The pedersen verifiers
    pub(crate) pedersen_verifier_set: Vec<V>,
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S, V> Shamir<S> for StdPedersenResult<S, V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    type InnerPolynomial = Vec<S>;
    type ShareSet = Vec<S>;
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S, V> Pedersen<S, V> for StdPedersenResult<S, V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    type FeldmanVerifierSet = Vec<V>;
    type PedersenVerifierSet = Vec<V>;
    type PedersenResult = Self;
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S, V> PedersenResult<S, V> for StdPedersenResult<S, V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    type ShareSet = Vec<S>;
    type FeldmanVerifierSet = Vec<V>;
    type PedersenVerifierSet = Vec<V>;

    fn new(
        blinder: S::Value,
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

    fn blinder(&self) -> &S::Value {
        &self.blinder
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
/// Create shares from a secret.
/// If None, a random value is generated in [`S::Value`].
/// `share_generator` is the generator to use for shares.
/// If None, the default generator is used.
/// `blind_factor_generator` is the generator point to use for blinding factor shares.
/// If None, a random generator is used
pub fn split_secret<S, V>(
    threshold: usize,
    limit: usize,
    secret: &S::Value,
    blinding: Option<S::Value>,
    share_generator: Option<V>,
    blind_factor_generator: Option<V>,
    rng: impl RngCore + CryptoRng,
) -> VsssResult<StdPedersenResult<S, V>>
where
    S: Share,
    V: ShareVerifier<S>,
{
    StdVsss::split_secret_with_blind_verifiers(
        threshold,
        limit,
        &PedersenOptions {
            secret: secret.clone(),
            blinder: blinding,
            secret_generator: share_generator,
            blinder_generator: blind_factor_generator,
            participant_generators: &[ParticipantIdGeneratorType::default()],
        },
        rng,
    )
}
