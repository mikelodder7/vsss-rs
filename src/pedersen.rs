/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Pedersen's verifiable secret sharing scheme.
//! See <https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF>.
//!
//! Pedersen returns both Pedersen verifiers and Feldman verifiers because both
//! may be needed for other protocols, such as Gennaro's DKG. Otherwise,
//! the Feldman verifiers may be discarded.
use crate::*;
use core::ops::{Add, Sub};
use generic_array::{
    ArrayLength, GenericArray,
    typenum::{Add1, B1, Sub1, U2},
};
use hybrid_array::{Array, ArraySize};
use rand_core::CryptoRng;

/// Options for Pedersen secret sharing
#[derive(Debug)]
pub struct PedersenOptions<'a, S: Share, V: ShareVerifier<S>> {
    /// The secret to split
    pub secret: &'a S::Value,
    /// The blinding factor
    pub blinder: Option<S::Value>,
    /// The generator to use for share verifiers
    pub secret_generator: Option<V>,
    /// The generator to use for blinder verifiers
    pub blinder_generator: Option<V>,
}

/// A secret sharing scheme that uses Pedersen commitments as verifiers.
/// See [PedersenVSS](https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF).
#[allow(async_fn_in_trait)]
pub trait Pedersen<S, V>: Shamir<S>
where
    S: Share,
    V: ShareVerifier<S>,
{
    /// The Feldman verifier set
    type FeldmanVerifierSet: FeldmanVerifierSet<S, V>;
    /// The Pedersen verifier set
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
    /// If [`None`], a random value is generated in `S::Value`.
    /// `secret_generator` is the generator point to use for shares.
    /// If [`None`], the default generator is used.
    /// `blinder_generator` is the generator point to use for blinder shares.
    /// If [`None`], a random generator is used.
    ///
    /// Returns the secret shares, blinder, blinder shares, and verifiers.
    fn split_secret_with_blind_verifiers(
        threshold: usize,
        limit: usize,
        options: &PedersenOptions<S, V>,
        rng: impl CryptoRng,
    ) -> VsssResult<Self::PedersenResult> {
        Self::split_secret_with_participant_generators_and_blind_verifiers(
            threshold,
            limit,
            options,
            rng,
            &[ParticipantIdGenerator::<S::Identifier>::default()],
        )
    }

    /// Create shares from a secret, participant number generators, and options.
    fn split_secret_with_participant_generators_and_blind_verifiers(
        threshold: usize,
        limit: usize,
        options: &PedersenOptions<S, V>,
        mut rng: impl CryptoRng,
        participant_generators: &[ParticipantIdGenerator<S::Identifier>],
    ) -> VsssResult<Self::PedersenResult> {
        let participant_id_collection =
            ParticipantIdGeneratorCollection::from(participant_generators);
        Self::split_secret_with_participant_ids_iter_and_blind_verifiers(
            threshold,
            limit,
            options,
            &mut rng,
            participant_id_collection.iter(),
        )
    }

    /// Create shares from a secret, participant identifier iterator, and options.
    fn split_secret_with_participant_ids_iter_and_blind_verifiers(
        threshold: usize,
        limit: usize,
        options: &PedersenOptions<S, V>,
        mut rng: impl CryptoRng,
        participant_ids: impl IntoIterator<Item = S::Identifier>,
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
        secret_polynomial.fill(options.secret, &mut rng, threshold)?;
        blinder_polynomial.fill(&blinder, &mut rng, threshold)?;

        let mut feldman_verifier_set =
            Self::FeldmanVerifierSet::empty_feldman_set_with_capacity(threshold, g);
        let mut pedersen_verifier_set =
            Self::PedersenVerifierSet::empty_pedersen_set_with_capacity(threshold, g, h);
        // Generate the verifiable commitments to the polynomial for the shares.
        // Each commitment is computed from a polynomial coefficient and the specified generator.
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
        let mut secret_shares = Self::ShareSet::create(limit);
        let mut blinder_shares = Self::ShareSet::create(limit);

        let mut participant_id_iter = participant_ids.into_iter();

        for (secret_share, blinder_share) in secret_shares
            .as_mut()
            .iter_mut()
            .zip(blinder_shares.as_mut().iter_mut())
            .take(limit)
        {
            let id = participant_id_iter
                .next()
                .ok_or(Error::NotEnoughShareIdentifiers)?;
            let mut secret_value = S::Value::default();
            let mut blinder_value = S::Value::default();
            secret_polynomial.evaluate_in_place(&id, threshold, &mut secret_value);
            blinder_polynomial.evaluate_in_place(&id, threshold, &mut blinder_value);
            *secret_share = S::with_identifier_and_value(id.clone(), secret_value);
            *blinder_share = S::with_identifier_and_value(id, blinder_value);
        }
        Ok(Self::PedersenResult::new(
            blinder,
            secret_shares,
            blinder_shares,
            feldman_verifier_set,
            pedersen_verifier_set,
        ))
    }

    /// Create shares from a secret, an asynchronous stream of participant identifiers,
    /// and options.
    ///
    /// Exactly `limit` identifiers are consumed. Returns
    /// [`Error::NotEnoughShareIdentifiers`] if the stream ends early.
    #[cfg(feature = "stream")]
    async fn split_secret_with_participant_ids_stream_and_blind_verifiers(
        threshold: usize,
        limit: usize,
        options: &PedersenOptions<'_, S, V>,
        rng: impl CryptoRng,
        participant_ids: impl futures_core::Stream<Item = S::Identifier>,
    ) -> VsssResult<Self::PedersenResult> {
        check_params(threshold, limit)?;
        let participant_ids =
            collect_stream_exact(limit, participant_ids, Error::NotEnoughShareIdentifiers).await?;
        Self::split_secret_with_participant_ids_iter_and_blind_verifiers(
            threshold,
            limit,
            options,
            rng,
            participant_ids,
        )
    }

    /// Create shares from a secret, participant identifiers, and options.
    fn split_secret_with_ids_and_blind_verifiers(
        threshold: usize,
        limit: usize,
        options: &PedersenOptions<S, V>,
        rng: impl CryptoRng,
        participant_ids: impl IntoIterator<Item = S::Identifier>,
    ) -> VsssResult<Self::PedersenResult> {
        Self::split_secret_with_participant_ids_iter_and_blind_verifiers(
            threshold,
            limit,
            options,
            rng,
            participant_ids,
        )
    }
}

/// The result of splitting a secret with [`Pedersen`].
pub trait PedersenResult<S, V>: Sized
where
    S: Share,
    V: ShareVerifier<S>,
{
    /// The secret shares
    type ShareSet: ReadableShareSet<S>;
    /// The Feldman verifier set
    type FeldmanVerifierSet: FeldmanVerifierSet<S, V>;
    /// The Pedersen verifier set
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

    /// The Feldman verifier set for verifying secrets without blinders
    fn feldman_verifier_set(&self) -> &Self::FeldmanVerifierSet;

    /// The Pedersen verifier set for verifying secrets with blinders
    fn pedersen_verifier_set(&self) -> &Self::PedersenVerifierSet;
}

type Add2<A> = <A as Add<U2>>::Output;
type Sub2<A> = <A as Sub<U2>>::Output;
/// The result to use when the sizes are known or computed at compile time
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
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
    /// The blinder used to create Pedersen commitments
    pub(crate) blinder: S::Value,
    /// The secret shares
    pub(crate) secret_shares: GenericArray<S, SHARES>,
    /// The blinder shares
    pub(crate) blinder_shares: GenericArray<S, SHARES>,
    /// The Feldman verifiers
    pub(crate) feldman_verifier_set: GenericArray<V, Add1<THRESHOLD>>,
    /// The Pedersen verifiers
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

/// The result to use when the sizes are known or computed at compile time
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub struct HybridArrayPedersenResult<S, V, THRESHOLD, SHARES>
where
    S: Share,
    V: ShareVerifier<S>,
    SHARES: ArraySize,
    THRESHOLD: Add<B1> + Add<U2> + ArraySize,
    Add1<THRESHOLD>: ArraySize + Sub<B1, Output = THRESHOLD>,
    Add2<THRESHOLD>: ArraySize + Sub<U2, Output = THRESHOLD>,
    Sub1<Add1<THRESHOLD>>: ArraySize,
    Sub2<Add2<THRESHOLD>>: ArraySize,
{
    /// The blinder used to create Pedersen commitments
    pub(crate) blinder: S::Value,
    /// The secret shares
    pub(crate) secret_shares: Array<S, SHARES>,
    /// The blinder shares
    pub(crate) blinder_shares: Array<S, SHARES>,
    /// The Feldman verifiers
    pub(crate) feldman_verifier_set: Array<V, Add1<THRESHOLD>>,
    /// The Pedersen verifiers
    pub(crate) pedersen_verifier_set: Array<V, Add2<THRESHOLD>>,
}

impl<S, V, THRESHOLD, SHARES> PedersenResult<S, V>
    for HybridArrayPedersenResult<S, V, THRESHOLD, SHARES>
where
    S: Share,
    V: ShareVerifier<S>,
    SHARES: ArraySize,
    THRESHOLD: Add<B1> + Add<U2> + ArraySize,
    Add1<THRESHOLD>: ArraySize + Sub<B1, Output = THRESHOLD>,
    Add2<THRESHOLD>: ArraySize + Sub<U2, Output = THRESHOLD>,
    Sub1<Add1<THRESHOLD>>: ArraySize,
    Sub2<Add2<THRESHOLD>>: ArraySize,
{
    type ShareSet = Array<S, SHARES>;
    type FeldmanVerifierSet = Array<V, Add1<THRESHOLD>>;
    type PedersenVerifierSet = Array<V, Add2<THRESHOLD>>;

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

impl<S, V, THRESHOLD, SHARES> Shamir<S> for HybridArrayPedersenResult<S, V, THRESHOLD, SHARES>
where
    S: Share,
    V: ShareVerifier<S>,
    SHARES: ArraySize,
    THRESHOLD: Add<B1> + Add<U2> + ArraySize,
    Add1<THRESHOLD>: ArraySize + Sub<B1, Output = THRESHOLD>,
    Add2<THRESHOLD>: ArraySize + Sub<U2, Output = THRESHOLD>,
    Sub1<Add1<THRESHOLD>>: ArraySize,
    Sub2<Add2<THRESHOLD>>: ArraySize,
{
    type InnerPolynomial = Array<S, THRESHOLD>;
    type ShareSet = Array<S, SHARES>;
}

impl<S, V, THRESHOLD, SHARES> Pedersen<S, V> for HybridArrayPedersenResult<S, V, THRESHOLD, SHARES>
where
    S: Share,
    V: ShareVerifier<S>,
    SHARES: ArraySize,
    THRESHOLD: Add<B1> + Add<U2> + ArraySize,
    Add1<THRESHOLD>: ArraySize + Sub<B1, Output = THRESHOLD>,
    Add2<THRESHOLD>: ArraySize + Sub<U2, Output = THRESHOLD>,
    Sub1<Add1<THRESHOLD>>: ArraySize,
    Sub2<Add2<THRESHOLD>>: ArraySize,
{
    type FeldmanVerifierSet = Array<V, Add1<THRESHOLD>>;
    type PedersenVerifierSet = Array<V, Add2<THRESHOLD>>;
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
    /// The blinder used to create Pedersen commitments
    pub(crate) blinder: S::Value,
    /// The secret shares
    pub(crate) secret_shares: Vec<S>,
    /// The blinder shares
    pub(crate) blinder_shares: Vec<S>,
    /// The Feldman verifiers
    pub(crate) feldman_verifier_set: Vec<V>,
    /// The Pedersen verifiers
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
///
/// If [`None`], a random value is generated in [`Share::Value`].
/// `share_generator` is the generator to use for shares.
/// If [`None`], the default generator is used.
/// `blind_factor_generator` is the generator point to use for blinding factor shares.
/// If [`None`], a random generator is used.
pub fn split_secret<S, V>(
    threshold: usize,
    limit: usize,
    secret: &S::Value,
    blinding: Option<S::Value>,
    share_generator: Option<V>,
    blind_factor_generator: Option<V>,
    rng: impl CryptoRng,
) -> VsssResult<StdPedersenResult<S, V>>
where
    S: Share,
    V: ShareVerifier<S>,
{
    StdVsss::split_secret_with_blind_verifiers(
        threshold,
        limit,
        &PedersenOptions {
            secret,
            blinder: blinding,
            secret_generator: share_generator,
            blinder_generator: blind_factor_generator,
        },
        rng,
    )
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret with participant number generators.
pub fn split_secret_with_participant_generators<S, V>(
    threshold: usize,
    limit: usize,
    options: &PedersenOptions<S, V>,
    rng: impl CryptoRng,
    participant_generators: &[ParticipantIdGenerator<S::Identifier>],
) -> VsssResult<StdPedersenResult<S, V>>
where
    S: Share,
    V: ShareVerifier<S>,
{
    StdVsss::split_secret_with_participant_generators_and_blind_verifiers(
        threshold,
        limit,
        options,
        rng,
        participant_generators,
    )
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret with an iterator of participant number generators.
pub fn split_secret_with_participant_generators_iter<'a, S, V>(
    threshold: usize,
    limit: usize,
    options: &PedersenOptions<S, V>,
    rng: impl CryptoRng,
    participant_generators: impl IntoIterator<Item = ParticipantIdGenerator<'a, S::Identifier>>,
) -> VsssResult<StdPedersenResult<S, V>>
where
    S: Share,
    S::Identifier: 'a,
    V: ShareVerifier<S>,
{
    let participant_generators: Vec<_> = participant_generators.into_iter().collect();
    split_secret_with_participant_generators(
        threshold,
        limit,
        options,
        rng,
        participant_generators.as_slice(),
    )
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret with an iterator of participant identifiers.
pub fn split_secret_with_participant_ids_iter<S, V>(
    threshold: usize,
    limit: usize,
    options: &PedersenOptions<S, V>,
    rng: impl CryptoRng,
    participant_ids: impl IntoIterator<Item = S::Identifier>,
) -> VsssResult<StdPedersenResult<S, V>>
where
    S: Share,
    V: ShareVerifier<S>,
{
    StdVsss::split_secret_with_participant_ids_iter_and_blind_verifiers(
        threshold,
        limit,
        options,
        rng,
        participant_ids,
    )
}

#[cfg(feature = "stream")]
#[cfg_attr(docsrs, doc(cfg(feature = "stream")))]
/// Create shares from a secret with an asynchronous stream of participant identifiers.
///
/// Exactly `limit` identifiers are consumed. Returns
/// [`Error::NotEnoughShareIdentifiers`] if the stream ends early.
pub async fn split_secret_with_participant_ids_stream<S, V>(
    threshold: usize,
    limit: usize,
    options: &PedersenOptions<'_, S, V>,
    rng: impl CryptoRng,
    participant_ids: impl futures_core::Stream<Item = S::Identifier>,
) -> VsssResult<StdPedersenResult<S, V>>
where
    S: Share,
    V: ShareVerifier<S>,
{
    StdVsss::split_secret_with_participant_ids_stream_and_blind_verifiers(
        threshold,
        limit,
        options,
        rng,
        participant_ids,
    )
    .await
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret with participant identifiers.
pub fn split_secret_with_ids<S, V>(
    threshold: usize,
    limit: usize,
    options: &PedersenOptions<S, V>,
    rng: impl CryptoRng,
    participant_ids: impl IntoIterator<Item = S::Identifier>,
) -> VsssResult<StdPedersenResult<S, V>>
where
    S: Share,
    V: ShareVerifier<S>,
{
    split_secret_with_participant_ids_iter(threshold, limit, options, rng, participant_ids)
}

#[cfg(test)]
mod tests {
    use super::{
        GenericArrayPedersenResult, HybridArrayPedersenResult, Pedersen, PedersenOptions,
        PedersenResult, split_secret, split_secret_with_ids,
        split_secret_with_participant_generators_iter, split_secret_with_participant_ids_iter,
    };
    use crate::{
        Error, FeldmanVerifierSet, IdentifierPrimeField, ParticipantIdGenerator,
        PedersenVerifierSet, PrimeFieldShare, ReadableShareSet, Share, StdVsss, ValueGroup,
    };
    use generic_array::{
        GenericArray,
        typenum::{U2 as GenericU2, U3 as GenericU3, U4 as GenericU4},
    };
    use hybrid_array::{
        Array,
        typenum::{U2 as HybridU2, U3 as HybridU3, U4 as HybridU4},
    };
    use k256::{ProjectivePoint, Scalar};
    use rand::{SeedableRng, rngs::StdRng};

    type TestShare = PrimeFieldShare<Scalar>;
    type TestVerifier = ValueGroup<ProjectivePoint>;

    fn share(identifier: u64, value: u64) -> TestShare {
        TestShare::with_identifier_and_value(
            IdentifierPrimeField(Scalar::from(identifier)),
            IdentifierPrimeField(Scalar::from(value)),
        )
    }

    fn verifier(value: u64) -> TestVerifier {
        ValueGroup(ProjectivePoint::GENERATOR * Scalar::from(value))
    }

    fn test_options<'a>(
        secret: &'a IdentifierPrimeField<Scalar>,
    ) -> PedersenOptions<'a, TestShare, TestVerifier> {
        PedersenOptions {
            secret,
            blinder: Some(IdentifierPrimeField(Scalar::from(9u64))),
            secret_generator: Some(TestVerifier::generator()),
            blinder_generator: Some(ValueGroup(ProjectivePoint::GENERATOR * Scalar::from(2u64))),
        }
    }

    #[test]
    fn pedersen_free_functions_verify_combine_and_expose_result_fields() {
        let mut rng = StdRng::from_seed([0x41u8; 32]);
        let secret = IdentifierPrimeField(Scalar::from(55u64));
        let result = split_secret::<TestShare, TestVerifier>(
            2,
            3,
            &secret,
            Some(IdentifierPrimeField(Scalar::from(9u64))),
            Some(TestVerifier::generator()),
            Some(ValueGroup(ProjectivePoint::GENERATOR * Scalar::from(2u64))),
            &mut rng,
        )
        .unwrap();

        assert_eq!(result.blinder(), &IdentifierPrimeField(Scalar::from(9u64)));
        assert_eq!(result.secret_shares().combine(), Ok(secret));
        assert_eq!(
            result.blinder_shares().combine(),
            Ok(IdentifierPrimeField(Scalar::from(9u64)))
        );
        for (share, blinder) in result
            .secret_shares()
            .iter()
            .zip(result.blinder_shares().iter())
        {
            result.feldman_verifier_set().verify_share(share).unwrap();
            result
                .pedersen_verifier_set()
                .verify_share_and_blinder(share, blinder)
                .unwrap();
        }
    }

    #[test]
    fn pedersen_iterator_wrappers_accept_ids_and_generators() {
        let mut rng = StdRng::from_seed([0x42u8; 32]);
        let secret = IdentifierPrimeField(Scalar::from(55u64));
        let options = test_options(&secret);

        let by_ids = split_secret_with_participant_ids_iter::<TestShare, TestVerifier>(
            2,
            3,
            &options,
            &mut rng,
            [1u64, 2, 3].map(|id| IdentifierPrimeField(Scalar::from(id))),
        )
        .unwrap();
        assert_eq!(by_ids.secret_shares().combine(), Ok(secret));

        let participant_generator = ParticipantIdGenerator::Sequential {
            start: IdentifierPrimeField(Scalar::from(20u64)),
            increment: IdentifierPrimeField(Scalar::from(1u64)),
            count: 3,
        };
        let by_generators =
            split_secret_with_participant_generators_iter::<TestShare, TestVerifier>(
                2,
                3,
                &options,
                &mut rng,
                [participant_generator],
            )
            .unwrap();
        assert_eq!(
            by_generators.secret_shares()[0].identifier.0,
            Scalar::from(20u64)
        );
        assert_eq!(by_generators.secret_shares().combine(), Ok(secret));
    }

    #[test]
    fn simplified_pedersen_id_entrypoints_work() {
        let mut rng = StdRng::from_seed([0x44u8; 32]);
        let secret = IdentifierPrimeField(Scalar::from(55u64));
        let options = test_options(&secret);
        let ids = [5u64, 6, 7].map(|id| IdentifierPrimeField(Scalar::from(id)));

        let result =
            split_secret_with_ids::<TestShare, TestVerifier>(2, 3, &options, &mut rng, ids)
                .unwrap();
        assert_eq!(result.secret_shares()[0].identifier.0, Scalar::from(5u64));
        assert_eq!(result.secret_shares().combine(), Ok(secret));

        let ids = [8u64, 9, 10].map(|id| IdentifierPrimeField(Scalar::from(id)));
        let result = <StdVsss<TestShare, TestVerifier> as Pedersen<
            TestShare,
            TestVerifier,
        >>::split_secret_with_ids_and_blind_verifiers(2, 3, &options, &mut rng, ids)
        .unwrap();
        assert_eq!(result.secret_shares()[0].identifier.0, Scalar::from(8u64));
        assert_eq!(result.secret_shares().combine(), Ok(secret));
    }

    #[test]
    fn pedersen_generic_and_hybrid_results_expose_all_fields() {
        let secret = IdentifierPrimeField(Scalar::from(55u64));
        let blinder = IdentifierPrimeField(Scalar::from(9u64));
        let secret_shares = GenericArray::<TestShare, GenericU3>::from_array([
            share(1, 55),
            share(2, 55),
            share(3, 55),
        ]);
        let blinder_shares = GenericArray::<TestShare, GenericU3>::from_array([
            share(1, 9),
            share(2, 9),
            share(3, 9),
        ]);
        let feldman_verifier_set = GenericArray::<TestVerifier, GenericU3>::from_array([
            TestVerifier::generator(),
            verifier(55),
            verifier(1),
        ]);
        let pedersen_verifier_set = GenericArray::<TestVerifier, GenericU4>::from_array([
            TestVerifier::generator(),
            verifier(2),
            verifier(73),
            verifier(1),
        ]);
        let generic =
            GenericArrayPedersenResult::<TestShare, TestVerifier, GenericU2, GenericU3>::new(
                blinder,
                secret_shares,
                blinder_shares,
                feldman_verifier_set,
                pedersen_verifier_set,
            );

        assert_eq!(generic.blinder(), &blinder);
        assert_eq!(generic.secret_shares().combine(), Ok(secret));
        assert_eq!(generic.blinder_shares().combine(), Ok(blinder));
        assert_eq!(
            <GenericArray<TestVerifier, GenericU3> as FeldmanVerifierSet<
                TestShare,
                TestVerifier,
            >>::generator(generic.feldman_verifier_set()),
            TestVerifier::generator()
        );
        assert_eq!(
            <GenericArray<TestVerifier, GenericU4> as PedersenVerifierSet<
                TestShare,
                TestVerifier,
            >>::blinder_generator(generic.pedersen_verifier_set()),
            verifier(2)
        );

        let secret_shares = Array::<TestShare, HybridU3>::from_fn(|i| share(i as u64 + 1, 55));
        let blinder_shares = Array::<TestShare, HybridU3>::from_fn(|i| share(i as u64 + 1, 9));
        let feldman_verifier_set = Array::<TestVerifier, HybridU3>::from_fn(|i| match i {
            0 => TestVerifier::generator(),
            1 => verifier(55),
            _ => verifier(1),
        });
        let pedersen_verifier_set = Array::<TestVerifier, HybridU4>::from_fn(|i| match i {
            0 => TestVerifier::generator(),
            1 => verifier(2),
            2 => verifier(73),
            _ => verifier(1),
        });
        let hybrid = HybridArrayPedersenResult::<TestShare, TestVerifier, HybridU2, HybridU3>::new(
            blinder,
            secret_shares,
            blinder_shares,
            feldman_verifier_set,
            pedersen_verifier_set,
        );

        assert_eq!(hybrid.blinder(), &blinder);
        assert_eq!(hybrid.secret_shares().combine(), Ok(secret));
        assert_eq!(hybrid.blinder_shares().combine(), Ok(blinder));
        assert_eq!(
            <Array<TestVerifier, HybridU3> as FeldmanVerifierSet<
                TestShare,
                TestVerifier,
            >>::generator(hybrid.feldman_verifier_set()),
            TestVerifier::generator()
        );
        assert_eq!(
            <Array<TestVerifier, HybridU4> as PedersenVerifierSet<
                TestShare,
                TestVerifier,
            >>::blinder_generator(hybrid.pedersen_verifier_set()),
            verifier(2)
        );
    }

    #[test]
    fn pedersen_returns_errors_for_invalid_generators_and_missing_ids() {
        let mut rng = StdRng::from_seed([0x43u8; 32]);
        let secret = IdentifierPrimeField(Scalar::from(55u64));
        let err = split_secret::<TestShare, TestVerifier>(
            2,
            3,
            &secret,
            Some(IdentifierPrimeField(Scalar::from(9u64))),
            Some(TestVerifier::identity()),
            Some(ValueGroup(ProjectivePoint::GENERATOR * Scalar::from(2u64))),
            &mut rng,
        )
        .unwrap_err();
        assert_eq!(
            err,
            Error::InvalidGenerator("Pedersen generators cannot be zero")
        );

        let mut options = test_options(&secret);
        options.blinder_generator = Some(TestVerifier::generator());
        let err = split_secret_with_participant_ids_iter::<TestShare, TestVerifier>(
            2,
            3,
            &options,
            &mut rng,
            [IdentifierPrimeField(Scalar::from(1u64))],
        )
        .unwrap_err();
        assert_eq!(
            err,
            Error::InvalidGenerator("Pedersen generators cannot be the same")
        );

        let options = test_options(&secret);
        let err = <StdVsss<TestShare, TestVerifier> as Pedersen<TestShare, TestVerifier>>::split_secret_with_participant_ids_iter_and_blind_verifiers(
                2,
                3,
                &options,
                &mut rng,
                [IdentifierPrimeField(Scalar::from(1u64))]
            )
            .unwrap_err();
        assert_eq!(err, Error::NotEnoughShareIdentifiers);
    }

    #[cfg(feature = "stream")]
    #[test]
    fn pedersen_stream_entrypoint_verifies_and_combines() {
        use crate::tests::utils::{TestStream, block_on};

        let mut rng = StdRng::from_seed([0x44u8; 32]);
        let secret = IdentifierPrimeField(Scalar::from(55u64));
        let options = test_options(&secret);
        let ids = [5u64, 6, 7].map(|id| IdentifierPrimeField(Scalar::from(id)));
        let result = block_on(super::split_secret_with_participant_ids_stream::<
            TestShare,
            TestVerifier,
        >(
            2, 3, &options, &mut rng, TestStream::new(ids.into_iter())
        ))
        .unwrap();

        assert_eq!(result.secret_shares().combine(), Ok(secret));
        for (share, blinder_share) in result
            .secret_shares()
            .iter()
            .zip(result.blinder_shares().iter())
        {
            result
                .pedersen_verifier_set()
                .verify_share_and_blinder(share, blinder_share)
                .unwrap();
        }
    }
}
