//! Sets are used for storing shares and other data associated with
//! secret sharing operations like splitting, combining, and verifying
//! Sizes greater than 32 should probably use Vec instead of fixed sizes
//! due to stack allocations
use crate::*;
use core::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};
use generic_array::{ArrayLength, GenericArray};
use hybrid_array::{Array, ArraySize};

/// Represents a readable data store for secret shares
pub trait ReadableShareSet<S>: AsRef<[S]>
where
    S: Share,
{
    /// Convert the given shares into a field element
    fn combine(&self) -> VsssResult<S::Value> {
        let mut secret = S::Value::default();
        self.combine_in_place(&mut secret)?;
        Ok(secret)
    }

    /// Convert the given shares into a field element, writing into `out`.
    fn combine_in_place(&self, out: &mut S::Value) -> VsssResult<()> {
        let shares = self.as_ref();
        validate_share_set(shares)?;
        interpolate_in_place(shares, out)
    }
}

/// Validate that a share set has enough shares, non-zero identifiers, and no duplicate identifiers.
pub fn validate_share_set<S>(shares: &[S]) -> VsssResult<()>
where
    S: Share,
{
    if shares.len() < 2 {
        return Err(Error::SharingMinThreshold);
    }
    for s in shares {
        if s.identifier().is_zero().into() {
            return Err(Error::SharingInvalidIdentifier);
        }
    }
    if dup_checker(shares) {
        return Err(Error::SharingDuplicateIdentifier);
    }
    Ok(())
}

/// Represents a data store for secret shares
pub trait WriteableShareSet<S>: ReadableShareSet<S> + AsMut<[S]>
where
    S: Share,
{
    /// Create a new writeable share set
    fn create(size_hint: usize) -> Self;
}

impl<S, B: AsRef<[S]>> ReadableShareSet<S> for B where S: Share {}

fn interpolate_in_place<S>(shares: &[S], secret: &mut S::Value) -> VsssResult<()>
where
    S: Share,
{
    *secret = S::Value::default();
    // Calculate lagrange interpolation
    for (i, x_i) in shares.iter().enumerate() {
        let mut num = S::Identifier::one();
        let mut den = S::Identifier::one();
        for (j, x_j) in shares.iter().enumerate() {
            if i == j {
                continue;
            }

            // x_j / (x_j - x_i) * ...
            let d = x_j.identifier().as_ref().clone() - x_i.identifier().as_ref().clone();
            *den.as_mut() *= d;
            *num.as_mut() *= x_j.identifier().as_ref();
        }

        let den = den.invert()?;
        let basis: S::Identifier = (num.as_ref().clone() * den.as_ref()).into();
        let t = x_i.value().clone() * &basis;
        *secret.as_mut() += t.as_ref();
    }

    Ok(())
}

impl<S, const L: usize> WriteableShareSet<S> for [S; L]
where
    S: Share,
{
    fn create(_size_hint: usize) -> Self {
        core::array::from_fn(|_| S::default())
    }
}

impl<S, L> WriteableShareSet<S> for GenericArray<S, L>
where
    S: Share,
    L: ArrayLength,
{
    fn create(_size_hint: usize) -> Self {
        Self::try_from_iter((0..L::to_usize()).map(|_| S::default())).unwrap()
    }
}

impl<S, L> WriteableShareSet<S> for Array<S, L>
where
    S: Share,
    L: ArraySize,
{
    fn create(_size_hint: usize) -> Self {
        Self::try_from_iter((0..L::to_usize()).map(|_| S::default())).unwrap()
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S> WriteableShareSet<S> for Vec<S>
where
    S: Share,
{
    fn create(size_hint: usize) -> Self {
        (0..size_hint).map(|_| S::default()).collect()
    }
}

fn dup_checker<S>(set: &[S]) -> bool
where
    S: Share,
{
    for (i, x_i) in set.iter().enumerate() {
        for x_j in set.iter().skip(i + 1) {
            if x_i.identifier() == x_j.identifier() {
                return true;
            }
        }
    }
    false
}

/// Objects that represent the ability to verify shamir shares using
/// Feldman verifiers
pub trait FeldmanVerifierSet<S, G>: Sized
where
    S: Share,
    G: ShareVerifier<S>,
{
    /// Create a new verifier set
    fn empty_feldman_set_with_capacity(size_hint: usize, generator: G) -> Self;

    /// Create a verifier set from an existing set of verifiers and generator
    fn feldman_set_with_generator_and_verifiers(generator: G, verifiers: &[G]) -> Self {
        let mut set = Self::empty_feldman_set_with_capacity(verifiers.len(), generator);
        set.verifiers_mut().copy_from_slice(verifiers);
        set
    }

    /// The generator used for the verifiers
    fn generator(&self) -> G;

    /// The verifiers
    fn verifiers(&self) -> &[G];

    /// The verifiers as writeable
    fn verifiers_mut(&mut self) -> &mut [G];

    /// Evaluate this verifier set at a share identifier.
    fn evaluate_verifier_at(&self, identifier: &S::Identifier) -> VsssResult<G> {
        if identifier.is_zero().into() {
            return Err(Error::InvalidShare);
        }
        if self.generator().is_zero().into() {
            return Err(Error::InvalidGenerator("Generator is identity"));
        }

        evaluate_commitments_at::<S, G>(self.verifiers(), identifier)
    }

    /// Verify a share with this set
    fn verify_share(&self, share: &S) -> VsssResult<()> {
        if share.value().is_zero().into() {
            return Err(Error::InvalidShare);
        }

        let rhs = self.evaluate_verifier_at(share.identifier())?;
        let s = share.value();
        let lhs = self.generator() * s;

        let res: G = rhs - lhs;

        if res.is_zero().into() {
            Ok(())
        } else {
            Err(Error::InvalidShare)
        }
    }
}

/// Objects that represent the ability to verify shamir shares using
/// Pedersen verifiers
pub trait PedersenVerifierSet<S, G>: Sized
where
    S: Share,
    G: ShareVerifier<S>,
{
    /// Create a new verifier set
    fn empty_pedersen_set_with_capacity(
        size_hint: usize,
        secret_generator: G,
        blinder_generator: G,
    ) -> Self;

    /// Create a verifier set from an existing set of verifiers and generators
    fn pedersen_set_with_generators_and_verifiers(
        secret_generator: G,
        blinder_generator: G,
        verifiers: &[G],
    ) -> Self {
        let mut set = Self::empty_pedersen_set_with_capacity(
            verifiers.len(),
            secret_generator,
            blinder_generator,
        );
        set.blind_verifiers_mut().copy_from_slice(verifiers);
        set
    }

    /// The generator used for the verifiers of secrets
    fn secret_generator(&self) -> G;

    /// The generator used for the verifiers of blinders
    fn blinder_generator(&self) -> G;

    /// The verifiers
    fn blind_verifiers(&self) -> &[G];

    /// The verifiers as writeable
    fn blind_verifiers_mut(&mut self) -> &mut [G];

    /// Evaluate this verifier set at a share identifier.
    fn evaluate_verifier_at(&self, identifier: &S::Identifier) -> VsssResult<G> {
        if identifier.is_zero().into() {
            return Err(Error::InvalidShare);
        }
        let blind_generator = self.blinder_generator();
        let generator = self.secret_generator();

        if generator == G::default() || blind_generator == G::default() {
            return Err(Error::InvalidGenerator(
                "Generator or Blind generator is an identity",
            ));
        }

        evaluate_commitments_at::<S, G>(self.blind_verifiers(), identifier)
    }

    /// Verify a share and blinder with this set
    fn verify_share_and_blinder(&self, share: &S, blinder: &S) -> VsssResult<()> {
        if (share.value().is_zero() | blinder.value().is_zero()).into() {
            return Err(Error::InvalidShare);
        }

        let secret = share.value();
        let blinder = blinder.value();
        let rhs = self.evaluate_verifier_at(share.identifier())?;
        let blind_generator = self.blinder_generator();
        let generator = self.secret_generator();

        let g: G = generator * secret;
        let h: G = blind_generator * blinder;

        let res = rhs - g - h;

        if res == G::default() {
            Ok(())
        } else {
            Err(Error::InvalidShare)
        }
    }
}

fn evaluate_commitments_at<S, G>(commitments: &[G], identifier: &S::Identifier) -> VsssResult<G>
where
    S: Share,
    G: ShareVerifier<S>,
{
    if commitments.is_empty() {
        return Err(Error::InvalidSizeRequest);
    }

    let mut i = S::Identifier::one();
    // FUTURE: execute this sum of products as a constant-time simultaneous
    // multiple point multiplication.
    let mut rhs = commitments[0];
    for v in &commitments[1..] {
        *i.as_mut() *= identifier.as_ref();
        rhs += *v * i.clone();
    }
    Ok(rhs)
}

impl<S: Share, G: ShareVerifier<S>, const L: usize> FeldmanVerifierSet<S, G> for [G; L] {
    fn empty_feldman_set_with_capacity(_size_hint: usize, generator: G) -> Self {
        let mut t = [G::default(); L];
        t[0] = generator;
        t
    }

    fn generator(&self) -> G {
        self[0]
    }

    fn verifiers(&self) -> &[G] {
        &self[1..]
    }

    fn verifiers_mut(&mut self) -> &mut [G] {
        self[1..].as_mut()
    }
}

impl<S: Share, G: ShareVerifier<S>, L: ArrayLength> FeldmanVerifierSet<S, G>
    for GenericArray<G, L>
{
    fn empty_feldman_set_with_capacity(_size_hint: usize, generator: G) -> Self {
        let mut t = Self::default();
        t[0] = generator;
        t
    }

    fn generator(&self) -> G {
        self[0]
    }

    fn verifiers(&self) -> &[G] {
        &self[1..]
    }

    fn verifiers_mut(&mut self) -> &mut [G] {
        self[1..].as_mut()
    }
}

impl<S: Share, G: ShareVerifier<S>, L: ArraySize> FeldmanVerifierSet<S, G> for Array<G, L> {
    fn empty_feldman_set_with_capacity(_size_hint: usize, generator: G) -> Self {
        let mut t = Self::default();
        t[0] = generator;
        t
    }

    fn generator(&self) -> G {
        self[0]
    }

    fn verifiers(&self) -> &[G] {
        &self[1..]
    }

    fn verifiers_mut(&mut self) -> &mut [G] {
        self[1..].as_mut()
    }
}

/// A wrapper around a fixed size array of verifiers
/// Allows for convenient type aliasing
/// ```
/// use vsss_rs::{DefaultShare, IdentifierPrimeField, ShareVerifierGroup, ArrayFeldmanVerifierSet};
///
/// type K256Share = DefaultShare<IdentifierPrimeField<k256::Scalar>, IdentifierPrimeField<k256::Scalar>>;
/// type K256FeldmanVerifierSet = ArrayFeldmanVerifierSet<K256Share, ShareVerifierGroup<k256::ProjectivePoint>, 3>;
/// ```
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct ArrayFeldmanVerifierSet<S, V, const L: usize>
where
    S: Share,
    V: ShareVerifier<S>,
{
    /// The inner array set to threshold + 1
    pub inner: [V; L],
    /// Marker for phantom data
    pub _marker: PhantomData<S>,
}

impl<S, V, const L: usize> From<[V; L]> for ArrayFeldmanVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn from(inner: [V; L]) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }
}

impl<S, V, const L: usize> From<&[V; L]> for ArrayFeldmanVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn from(inner: &[V; L]) -> Self {
        Self {
            inner: *inner,
            _marker: PhantomData,
        }
    }
}

impl<S, V, const L: usize> From<ArrayFeldmanVerifierSet<S, V, L>> for [V; L]
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn from(set: ArrayFeldmanVerifierSet<S, V, L>) -> Self {
        set.inner
    }
}

impl<S, V, const L: usize> From<&ArrayFeldmanVerifierSet<S, V, L>> for [V; L]
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn from(set: &ArrayFeldmanVerifierSet<S, V, L>) -> Self {
        set.inner
    }
}

impl<S, V, const L: usize> Deref for ArrayFeldmanVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
{
    type Target = [V; L];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<S, V, const L: usize> DerefMut for ArrayFeldmanVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<S, V, const L: usize> Default for ArrayFeldmanVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    [V; L]: Default,
{
    fn default() -> Self {
        Self {
            inner: Default::default(),
            _marker: PhantomData,
        }
    }
}

impl<S, V, const L: usize> FeldmanVerifierSet<S, V> for ArrayFeldmanVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn empty_feldman_set_with_capacity(size_hint: usize, generator: V) -> Self {
        Self {
            inner: <[V; L] as FeldmanVerifierSet<S, V>>::empty_feldman_set_with_capacity(
                size_hint, generator,
            ),
            _marker: PhantomData,
        }
    }

    fn generator(&self) -> V {
        <[V; L]>::generator(&self.inner)
    }

    fn verifiers(&self) -> &[V] {
        <[V; L]>::verifiers(&self.inner)
    }

    fn verifiers_mut(&mut self) -> &mut [V] {
        <[V; L]>::verifiers_mut(&mut self.inner)
    }
}

/// A wrapper around a generic array of verifiers
/// Allows for convenient type aliasing
/// ```
/// use vsss_rs::{DefaultShare, IdentifierPrimeField, ValueGroup, GenericArrayFeldmanVerifierSet};
/// use generic_array::typenum::U3;
///
/// type K256Share = DefaultShare<IdentifierPrimeField<k256::Scalar>, IdentifierPrimeField<k256::Scalar>>;
/// type K256FeldmanVerifierSet = GenericArrayFeldmanVerifierSet<K256Share, ValueGroup<k256::ProjectivePoint>, U3>;
/// ```
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct GenericArrayFeldmanVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArrayLength,
{
    /// The inner generic array set to threshold + 1
    pub inner: GenericArray<V, L>,
    /// Marker for phantom data
    pub _marker: PhantomData<S>,
}

impl<S, V, L> From<GenericArray<V, L>> for GenericArrayFeldmanVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArrayLength,
{
    fn from(inner: GenericArray<V, L>) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }
}

impl<S, V, L> From<&GenericArray<V, L>> for GenericArrayFeldmanVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArrayLength,
{
    fn from(inner: &GenericArray<V, L>) -> Self {
        Self {
            inner: inner.clone(),
            _marker: PhantomData,
        }
    }
}

impl<S, V, L> From<GenericArrayFeldmanVerifierSet<S, V, L>> for GenericArray<V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArrayLength,
{
    fn from(set: GenericArrayFeldmanVerifierSet<S, V, L>) -> Self {
        set.inner
    }
}

impl<S, V, L> From<&GenericArrayFeldmanVerifierSet<S, V, L>> for GenericArray<V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArrayLength,
{
    fn from(set: &GenericArrayFeldmanVerifierSet<S, V, L>) -> Self {
        set.inner.clone()
    }
}

impl<S, V, L> Deref for GenericArrayFeldmanVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArrayLength,
{
    type Target = GenericArray<V, L>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<S, V, L> DerefMut for GenericArrayFeldmanVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArrayLength,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<S, V, L> Default for GenericArrayFeldmanVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArrayLength,
    GenericArray<V, L>: Default,
{
    fn default() -> Self {
        Self {
            inner: Default::default(),
            _marker: PhantomData,
        }
    }
}

impl<S, V, L> FeldmanVerifierSet<S, V> for GenericArrayFeldmanVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArrayLength,
{
    fn empty_feldman_set_with_capacity(size_hint: usize, generator: V) -> Self {
        Self {
            inner:
                <GenericArray<V, L> as FeldmanVerifierSet<S, V>>::empty_feldman_set_with_capacity(
                    size_hint, generator,
                ),
            _marker: PhantomData,
        }
    }

    fn generator(&self) -> V {
        <GenericArray<V, L>>::generator(&self.inner)
    }

    fn verifiers(&self) -> &[V] {
        <GenericArray<V, L>>::verifiers(&self.inner)
    }

    fn verifiers_mut(&mut self) -> &mut [V] {
        <GenericArray<V, L>>::verifiers_mut(&mut self.inner)
    }
}

/// A wrapper around a hybrid array of verifiers
/// Allows for convenient type aliasing
/// ```
/// use vsss_rs::{DefaultShare, IdentifierPrimeField, ValueGroup, HybridArrayFeldmanVerifierSet};
/// use hybrid_array::typenum::U3;
///
/// type K256Share = DefaultShare<IdentifierPrimeField<k256::Scalar>, IdentifierPrimeField<k256::Scalar>>;
/// type K256FeldmanVerifierSet = HybridArrayFeldmanVerifierSet<K256Share, ValueGroup<k256::ProjectivePoint>, U3>;
/// ```
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct HybridArrayFeldmanVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArraySize,
{
    /// The inner hybrid array set to threshold + 1
    pub inner: Array<V, L>,
    /// Marker for phantom data
    pub _marker: PhantomData<S>,
}

impl<S, V, L> From<Array<V, L>> for HybridArrayFeldmanVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArraySize,
{
    fn from(inner: Array<V, L>) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }
}

impl<S, V, L> From<&Array<V, L>> for HybridArrayFeldmanVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArraySize,
{
    fn from(inner: &Array<V, L>) -> Self {
        Self {
            inner: inner.clone(),
            _marker: PhantomData,
        }
    }
}

impl<S, V, L> From<HybridArrayFeldmanVerifierSet<S, V, L>> for Array<V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArraySize,
{
    fn from(set: HybridArrayFeldmanVerifierSet<S, V, L>) -> Self {
        set.inner
    }
}

impl<S, V, L> From<&HybridArrayFeldmanVerifierSet<S, V, L>> for Array<V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArraySize,
{
    fn from(set: &HybridArrayFeldmanVerifierSet<S, V, L>) -> Self {
        set.inner.clone()
    }
}

impl<S, V, L> Deref for HybridArrayFeldmanVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArraySize,
{
    type Target = Array<V, L>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<S, V, L> DerefMut for HybridArrayFeldmanVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArraySize,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<S, V, L> Default for HybridArrayFeldmanVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArraySize,
    Array<V, L>: Default,
{
    fn default() -> Self {
        Self {
            inner: Default::default(),
            _marker: PhantomData,
        }
    }
}

impl<S, V, L> FeldmanVerifierSet<S, V> for HybridArrayFeldmanVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArraySize,
{
    fn empty_feldman_set_with_capacity(size_hint: usize, generator: V) -> Self {
        Self {
            inner: <Array<V, L> as FeldmanVerifierSet<S, V>>::empty_feldman_set_with_capacity(
                size_hint, generator,
            ),
            _marker: PhantomData,
        }
    }

    fn generator(&self) -> V {
        <Array<V, L>>::generator(&self.inner)
    }

    fn verifiers(&self) -> &[V] {
        <Array<V, L>>::verifiers(&self.inner)
    }

    fn verifiers_mut(&mut self) -> &mut [V] {
        <Array<V, L>>::verifiers_mut(&mut self.inner)
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S: Share, G: ShareVerifier<S>> FeldmanVerifierSet<S, G> for Vec<G> {
    fn empty_feldman_set_with_capacity(size_hint: usize, generator: G) -> Self {
        vec![generator; size_hint + 1]
    }

    fn generator(&self) -> G {
        self[0]
    }

    fn verifiers(&self) -> &[G] {
        &self[1..]
    }

    fn verifiers_mut(&mut self) -> &mut [G] {
        self[1..].as_mut()
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// A wrapper around a Vec of verifiers
/// Allows for convenient type aliasing
/// ```
/// #[cfg(any(feature = "alloc", feature = "std"))]
/// {
///     use vsss_rs::{DefaultShare, IdentifierPrimeField, ValueGroup, VecFeldmanVerifierSet};
///     type K256Share = DefaultShare<IdentifierPrimeField<k256::Scalar>, IdentifierPrimeField<k256::Scalar>>;
///     type K256FeldmanVerifierSet = VecFeldmanVerifierSet<K256Share, ValueGroup<k256::ProjectivePoint>>;
/// }
/// ```
#[derive(Debug, Clone, Default)]
#[repr(transparent)]
pub struct VecFeldmanVerifierSet<S, V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    /// The inner vec set to threshold + 1
    pub inner: Vec<V>,
    /// Marker for phantom data
    pub _marker: PhantomData<S>,
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S, V> From<Vec<V>> for VecFeldmanVerifierSet<S, V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn from(value: Vec<V>) -> Self {
        Self {
            inner: value,
            _marker: PhantomData,
        }
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S, V> From<&Vec<V>> for VecFeldmanVerifierSet<S, V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn from(value: &Vec<V>) -> Self {
        Self {
            inner: value.clone(),
            _marker: PhantomData,
        }
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S, V> From<VecFeldmanVerifierSet<S, V>> for Vec<V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn from(value: VecFeldmanVerifierSet<S, V>) -> Self {
        value.inner
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S, V> From<&VecFeldmanVerifierSet<S, V>> for Vec<V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn from(value: &VecFeldmanVerifierSet<S, V>) -> Self {
        value.inner.clone()
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S, V> Deref for VecFeldmanVerifierSet<S, V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    type Target = Vec<V>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S, V> DerefMut for VecFeldmanVerifierSet<S, V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S, V> FeldmanVerifierSet<S, V> for VecFeldmanVerifierSet<S, V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn empty_feldman_set_with_capacity(size_hint: usize, generator: V) -> Self {
        Self {
            inner: <Vec<V> as FeldmanVerifierSet<S, V>>::empty_feldman_set_with_capacity(
                size_hint, generator,
            ),
            _marker: PhantomData,
        }
    }

    fn generator(&self) -> V {
        <Vec<V>>::generator(&self.inner)
    }

    fn verifiers(&self) -> &[V] {
        <Vec<V>>::verifiers(&self.inner)
    }

    fn verifiers_mut(&mut self) -> &mut [V] {
        <Vec<V>>::verifiers_mut(&mut self.inner)
    }
}

impl<S: Share, G: ShareVerifier<S>, const L: usize> PedersenVerifierSet<S, G> for [G; L] {
    fn empty_pedersen_set_with_capacity(
        _size_hint: usize,
        secret_generator: G,
        blinder_generator: G,
    ) -> Self {
        let mut t = [G::default(); L];
        t[0] = secret_generator;
        t[1] = blinder_generator;
        t
    }

    fn secret_generator(&self) -> G {
        self[0]
    }

    fn blinder_generator(&self) -> G {
        self[1]
    }

    fn blind_verifiers(&self) -> &[G] {
        &self[2..]
    }

    fn blind_verifiers_mut(&mut self) -> &mut [G] {
        self[2..].as_mut()
    }
}

/// A wrapper around arrays of verifiers
/// Allows for convenient type aliasing
/// ```
/// use vsss_rs::{DefaultShare, IdentifierPrimeField, ValueGroup, ArrayPedersenVerifierSet};
/// type K256Share = DefaultShare<IdentifierPrimeField<k256::Scalar>, IdentifierPrimeField<k256::Scalar>>;
/// type K256PedersenVerifierSet = ArrayPedersenVerifierSet<K256Share, ValueGroup<k256::ProjectivePoint>, 4>;
/// ```
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct ArrayPedersenVerifierSet<S, V, const L: usize>
where
    S: Share,
    V: ShareVerifier<S>,
{
    /// The inner array set to threshold + 2
    pub inner: [V; L],
    /// Marker for phantom data
    pub _marker: PhantomData<S>,
}

impl<S, V, const L: usize> From<[V; L]> for ArrayPedersenVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn from(inner: [V; L]) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }
}

impl<S, V, const L: usize> From<&[V; L]> for ArrayPedersenVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn from(inner: &[V; L]) -> Self {
        Self {
            inner: *inner,
            _marker: PhantomData,
        }
    }
}

impl<S, V, const L: usize> From<ArrayPedersenVerifierSet<S, V, L>> for [V; L]
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn from(set: ArrayPedersenVerifierSet<S, V, L>) -> Self {
        set.inner
    }
}

impl<S, V, const L: usize> From<&ArrayPedersenVerifierSet<S, V, L>> for [V; L]
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn from(set: &ArrayPedersenVerifierSet<S, V, L>) -> Self {
        set.inner
    }
}

impl<S, V, const L: usize> Deref for ArrayPedersenVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
{
    type Target = [V; L];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<S, V, const L: usize> DerefMut for ArrayPedersenVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<S, V, const L: usize> Default for ArrayPedersenVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    [V; L]: Default,
{
    fn default() -> Self {
        Self {
            inner: Default::default(),
            _marker: PhantomData,
        }
    }
}

impl<S, V, const L: usize> PedersenVerifierSet<S, V> for ArrayPedersenVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn empty_pedersen_set_with_capacity(
        size_hint: usize,
        secret_generator: V,
        blinder_generator: V,
    ) -> Self {
        Self {
            inner: <[V; L] as PedersenVerifierSet<S, V>>::empty_pedersen_set_with_capacity(
                size_hint,
                secret_generator,
                blinder_generator,
            ),
            _marker: PhantomData,
        }
    }

    fn secret_generator(&self) -> V {
        <[V; L]>::secret_generator(&self.inner)
    }

    fn blinder_generator(&self) -> V {
        <[V; L]>::blinder_generator(&self.inner)
    }

    fn blind_verifiers(&self) -> &[V] {
        <[V; L]>::blind_verifiers(&self.inner)
    }

    fn blind_verifiers_mut(&mut self) -> &mut [V] {
        <[V; L]>::blind_verifiers_mut(&mut self.inner)
    }
}

impl<S: Share, G: ShareVerifier<S>, L: ArrayLength> PedersenVerifierSet<S, G>
    for GenericArray<G, L>
{
    fn empty_pedersen_set_with_capacity(
        _size_hint: usize,
        secret_generator: G,
        blinder_generator: G,
    ) -> Self {
        let mut t = Self::default();
        t[0] = secret_generator;
        t[1] = blinder_generator;
        t
    }

    fn secret_generator(&self) -> G {
        self[0]
    }

    fn blinder_generator(&self) -> G {
        self[1]
    }

    fn blind_verifiers(&self) -> &[G] {
        &self[2..]
    }

    fn blind_verifiers_mut(&mut self) -> &mut [G] {
        self[2..].as_mut()
    }
}

impl<S: Share, G: ShareVerifier<S>, L: ArraySize> PedersenVerifierSet<S, G> for Array<G, L> {
    fn empty_pedersen_set_with_capacity(
        _size_hint: usize,
        secret_generator: G,
        blinder_generator: G,
    ) -> Self {
        let mut t = Self::default();
        t[0] = secret_generator;
        t[1] = blinder_generator;
        t
    }

    fn secret_generator(&self) -> G {
        self[0]
    }

    fn blinder_generator(&self) -> G {
        self[1]
    }

    fn blind_verifiers(&self) -> &[G] {
        &self[2..]
    }

    fn blind_verifiers_mut(&mut self) -> &mut [G] {
        self[2..].as_mut()
    }
}

/// A wrapper around a generic array of verifiers
/// Allows for convenient type aliasing
/// ```
/// use vsss_rs::{DefaultShare, IdentifierPrimeField, ValueGroup, GenericArrayPedersenVerifierSet};
/// use generic_array::typenum::U4;
/// type K256Share = DefaultShare<IdentifierPrimeField<k256::Scalar>, IdentifierPrimeField<k256::Scalar>>;
/// type K256PedersenVerifierSet = GenericArrayPedersenVerifierSet<K256Share, ValueGroup<k256::ProjectivePoint>, U4>;
/// ```
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct GenericArrayPedersenVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArrayLength,
{
    /// The inner generic array set to threshold + 2
    pub inner: GenericArray<V, L>,
    /// Marker for phantom data
    pub _marker: PhantomData<S>,
}

impl<S, V, L> From<GenericArray<V, L>> for GenericArrayPedersenVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArrayLength,
{
    fn from(inner: GenericArray<V, L>) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }
}

impl<S, V, L> From<&GenericArray<V, L>> for GenericArrayPedersenVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArrayLength,
{
    fn from(inner: &GenericArray<V, L>) -> Self {
        Self {
            inner: inner.clone(),
            _marker: PhantomData,
        }
    }
}

impl<S, V, L> From<GenericArrayPedersenVerifierSet<S, V, L>> for GenericArray<V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArrayLength,
{
    fn from(set: GenericArrayPedersenVerifierSet<S, V, L>) -> Self {
        set.inner
    }
}

impl<S, V, L> From<&GenericArrayPedersenVerifierSet<S, V, L>> for GenericArray<V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArrayLength,
{
    fn from(set: &GenericArrayPedersenVerifierSet<S, V, L>) -> Self {
        set.inner.clone()
    }
}

impl<S, V, L> Deref for GenericArrayPedersenVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArrayLength,
{
    type Target = GenericArray<V, L>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<S, V, L> DerefMut for GenericArrayPedersenVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArrayLength,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<S, V, L> Default for GenericArrayPedersenVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArrayLength,
    GenericArray<V, L>: Default,
{
    fn default() -> Self {
        Self {
            inner: Default::default(),
            _marker: PhantomData,
        }
    }
}

impl<S, V, L> PedersenVerifierSet<S, V> for GenericArrayPedersenVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArrayLength,
{
    fn empty_pedersen_set_with_capacity(
        size_hint: usize,
        secret_generator: V,
        blinder_generator: V,
    ) -> Self {
        Self {
            inner:
                <GenericArray<V, L> as PedersenVerifierSet<S, V>>::empty_pedersen_set_with_capacity(
                    size_hint,
                    secret_generator,
                    blinder_generator,
                ),
            _marker: PhantomData,
        }
    }

    fn secret_generator(&self) -> V {
        <GenericArray<V, L>>::secret_generator(&self.inner)
    }

    fn blinder_generator(&self) -> V {
        <GenericArray<V, L>>::blinder_generator(&self.inner)
    }

    fn blind_verifiers(&self) -> &[V] {
        <GenericArray<V, L>>::blind_verifiers(&self.inner)
    }

    fn blind_verifiers_mut(&mut self) -> &mut [V] {
        <GenericArray<V, L>>::blind_verifiers_mut(&mut self.inner)
    }
}

/// A wrapper around a hybrid array of verifiers
/// Allows for convenient type aliasing
/// ```
/// use vsss_rs::{DefaultShare, IdentifierPrimeField, ValueGroup, HybridArrayPedersenVerifierSet};
/// use hybrid_array::typenum::U4;
/// type K256Share = DefaultShare<IdentifierPrimeField<k256::Scalar>, IdentifierPrimeField<k256::Scalar>>;
/// type K256PedersenVerifierSet = HybridArrayPedersenVerifierSet<K256Share, ValueGroup<k256::ProjectivePoint>, U4>;
/// ```
pub struct HybridArrayPedersenVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArraySize,
{
    /// The inner hybrid array set to threshold + 2
    pub inner: Array<V, L>,
    /// Marker for phantom data
    pub _marker: PhantomData<S>,
}

impl<S, V, L> From<Array<V, L>> for HybridArrayPedersenVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArraySize,
{
    fn from(inner: Array<V, L>) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }
}

impl<S, V, L> From<&Array<V, L>> for HybridArrayPedersenVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArraySize,
{
    fn from(inner: &Array<V, L>) -> Self {
        Self {
            inner: inner.clone(),
            _marker: PhantomData,
        }
    }
}

impl<S, V, L> From<HybridArrayPedersenVerifierSet<S, V, L>> for Array<V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArraySize,
{
    fn from(set: HybridArrayPedersenVerifierSet<S, V, L>) -> Self {
        set.inner
    }
}

impl<S, V, L> From<&HybridArrayPedersenVerifierSet<S, V, L>> for Array<V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArraySize,
{
    fn from(set: &HybridArrayPedersenVerifierSet<S, V, L>) -> Self {
        set.inner.clone()
    }
}

impl<S, V, L> Deref for HybridArrayPedersenVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArraySize,
{
    type Target = Array<V, L>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<S, V, L> DerefMut for HybridArrayPedersenVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArraySize,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<S, V, L> Default for HybridArrayPedersenVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArraySize,
    Array<V, L>: Default,
{
    fn default() -> Self {
        Self {
            inner: Default::default(),
            _marker: PhantomData,
        }
    }
}

impl<S, V, L> PedersenVerifierSet<S, V> for HybridArrayPedersenVerifierSet<S, V, L>
where
    S: Share,
    V: ShareVerifier<S>,
    L: ArraySize,
{
    fn empty_pedersen_set_with_capacity(
        size_hint: usize,
        secret_generator: V,
        blinder_generator: V,
    ) -> Self {
        Self {
            inner: <Array<V, L> as PedersenVerifierSet<S, V>>::empty_pedersen_set_with_capacity(
                size_hint,
                secret_generator,
                blinder_generator,
            ),
            _marker: PhantomData,
        }
    }

    fn secret_generator(&self) -> V {
        <Array<V, L>>::secret_generator(&self.inner)
    }

    fn blinder_generator(&self) -> V {
        <Array<V, L>>::blinder_generator(&self.inner)
    }

    fn blind_verifiers(&self) -> &[V] {
        <Array<V, L>>::blind_verifiers(&self.inner)
    }

    fn blind_verifiers_mut(&mut self) -> &mut [V] {
        <Array<V, L>>::blind_verifiers_mut(&mut self.inner)
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S: Share, V: ShareVerifier<S>> PedersenVerifierSet<S, V> for Vec<V> {
    fn empty_pedersen_set_with_capacity(
        size_hint: usize,
        secret_generator: V,
        blinder_generator: V,
    ) -> Self {
        let mut t = vec![blinder_generator; size_hint + 2];
        t[0] = secret_generator;
        t
    }

    fn secret_generator(&self) -> V {
        self[0]
    }

    fn blinder_generator(&self) -> V {
        self[1]
    }

    fn blind_verifiers(&self) -> &[V] {
        &self[2..]
    }

    fn blind_verifiers_mut(&mut self) -> &mut [V] {
        self[2..].as_mut()
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// A wrapper around a Vec of verifiers
/// Allows for convenient type aliasing
/// ```
/// #[cfg(any(feature = "alloc", feature = "std"))]
/// {
///    use vsss_rs::{DefaultShare, IdentifierPrimeField, ValueGroup, VecPedersenVerifierSet};
///   type K256Share = DefaultShare<IdentifierPrimeField<k256::Scalar>, IdentifierPrimeField<k256::Scalar>>;
///  type K256PedersenVerifierSet = VecPedersenVerifierSet<K256Share, ValueGroup<k256::ProjectivePoint>>;
/// }
/// ```
#[derive(Debug, Clone, Default)]
#[repr(transparent)]
pub struct VecPedersenVerifierSet<S, V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    /// The inner vec set to threshold + 2
    pub inner: Vec<V>,
    /// Marker for phantom data
    pub _marker: PhantomData<S>,
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S, V> From<Vec<V>> for VecPedersenVerifierSet<S, V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn from(inner: Vec<V>) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S, V> From<&Vec<V>> for VecPedersenVerifierSet<S, V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn from(inner: &Vec<V>) -> Self {
        Self {
            inner: (*inner).clone(),
            _marker: PhantomData,
        }
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S, V> From<VecPedersenVerifierSet<S, V>> for Vec<V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn from(set: VecPedersenVerifierSet<S, V>) -> Self {
        set.inner
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S, V> From<&VecPedersenVerifierSet<S, V>> for Vec<V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn from(set: &VecPedersenVerifierSet<S, V>) -> Self {
        set.inner.clone()
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S, V> Deref for VecPedersenVerifierSet<S, V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    type Target = Vec<V>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S, V> DerefMut for VecPedersenVerifierSet<S, V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S, V> PedersenVerifierSet<S, V> for VecPedersenVerifierSet<S, V>
where
    S: Share,
    V: ShareVerifier<S>,
{
    fn empty_pedersen_set_with_capacity(
        size_hint: usize,
        secret_generator: V,
        blinder_generator: V,
    ) -> Self {
        Self {
            inner: <Vec<V> as PedersenVerifierSet<S, V>>::empty_pedersen_set_with_capacity(
                size_hint,
                secret_generator,
                blinder_generator,
            ),
            _marker: PhantomData,
        }
    }

    fn secret_generator(&self) -> V {
        <Vec<V>>::secret_generator(&self.inner)
    }

    fn blinder_generator(&self) -> V {
        <Vec<V>>::blinder_generator(&self.inner)
    }

    fn blind_verifiers(&self) -> &[V] {
        <Vec<V>>::blind_verifiers(&self.inner)
    }

    fn blind_verifiers_mut(&mut self) -> &mut [V] {
        <Vec<V>>::blind_verifiers_mut(&mut self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ArrayFeldmanVerifierSet, ArrayPedersenVerifierSet, FeldmanVerifierSet,
        GenericArrayFeldmanVerifierSet, GenericArrayPedersenVerifierSet,
        HybridArrayFeldmanVerifierSet, HybridArrayPedersenVerifierSet, PedersenVerifierSet,
        ReadableShareSet, VecFeldmanVerifierSet, VecPedersenVerifierSet, WriteableShareSet,
        validate_share_set,
    };
    use crate::{Error, IdentifierPrimeField, PrimeFieldShare, Share, ShareElement, ValueGroup};
    use generic_array::{
        GenericArray,
        typenum::{U3 as GenericU3, U4 as GenericU4},
    };
    use hybrid_array::{
        Array,
        typenum::{U3 as HybridU3, U4 as HybridU4},
    };
    use k256::{ProjectivePoint, Scalar};
    use std::{vec, vec::Vec};

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

    #[test]
    fn writable_share_sets_create_default_storage() {
        let array = <[TestShare; 3] as WriteableShareSet<TestShare>>::create(99);
        assert_eq!(array.len(), 3);

        let generic =
            <GenericArray<TestShare, GenericU3> as WriteableShareSet<TestShare>>::create(99);
        assert_eq!(generic.len(), 3);

        let hybrid = <Array<TestShare, HybridU3> as WriteableShareSet<TestShare>>::create(99);
        assert_eq!(hybrid.len(), 3);

        let vec = <Vec<TestShare> as WriteableShareSet<TestShare>>::create(4);
        assert_eq!(vec.len(), 4);
    }

    #[test]
    fn verifier_set_wrappers_default_deref_and_owned_conversions_work() {
        let mut array_feldman = ArrayFeldmanVerifierSet::<TestShare, TestVerifier, 3>::default();
        assert_eq!(array_feldman.len(), 3);
        array_feldman[0] = verifier(1);
        assert_eq!(array_feldman.generator(), verifier(1));

        let mut generic_feldman =
            GenericArrayFeldmanVerifierSet::<TestShare, TestVerifier, GenericU3>::default();
        assert_eq!(generic_feldman.len(), 3);
        generic_feldman[0] = verifier(2);
        let generic_inner = GenericArray::<TestVerifier, GenericU3>::from(generic_feldman);
        let generic_feldman =
            GenericArrayFeldmanVerifierSet::<TestShare, TestVerifier, GenericU3>::from(
                generic_inner,
            );
        assert_eq!(generic_feldman.generator(), verifier(2));

        let mut hybrid_feldman =
            HybridArrayFeldmanVerifierSet::<TestShare, TestVerifier, HybridU3>::default();
        assert_eq!(hybrid_feldman.len(), 3);
        hybrid_feldman[0] = verifier(3);
        let hybrid_inner = Array::<TestVerifier, HybridU3>::from(hybrid_feldman);
        let hybrid_feldman =
            HybridArrayFeldmanVerifierSet::<TestShare, TestVerifier, HybridU3>::from(hybrid_inner);
        assert_eq!(hybrid_feldman.generator(), verifier(3));

        let mut array_pedersen = ArrayPedersenVerifierSet::<TestShare, TestVerifier, 4>::default();
        assert_eq!(array_pedersen.len(), 4);
        array_pedersen[0] = verifier(4);
        array_pedersen[1] = verifier(5);
        assert_eq!(array_pedersen.secret_generator(), verifier(4));
        assert_eq!(array_pedersen.blinder_generator(), verifier(5));

        let mut generic_pedersen =
            GenericArrayPedersenVerifierSet::<TestShare, TestVerifier, GenericU4>::default();
        generic_pedersen[0] = verifier(6);
        generic_pedersen[1] = verifier(7);
        let generic_inner = GenericArray::<TestVerifier, GenericU4>::from(generic_pedersen);
        let generic_pedersen =
            GenericArrayPedersenVerifierSet::<TestShare, TestVerifier, GenericU4>::from(
                generic_inner,
            );
        assert_eq!(generic_pedersen.secret_generator(), verifier(6));
        assert_eq!(generic_pedersen.blinder_generator(), verifier(7));

        let mut hybrid_pedersen =
            HybridArrayPedersenVerifierSet::<TestShare, TestVerifier, HybridU4>::default();
        hybrid_pedersen[0] = verifier(8);
        hybrid_pedersen[1] = verifier(9);
        let hybrid_inner = Array::<TestVerifier, HybridU4>::from(hybrid_pedersen);
        let hybrid_pedersen =
            HybridArrayPedersenVerifierSet::<TestShare, TestVerifier, HybridU4>::from(hybrid_inner);
        assert_eq!(hybrid_pedersen.secret_generator(), verifier(8));
        assert_eq!(hybrid_pedersen.blinder_generator(), verifier(9));
    }

    #[test]
    fn vec_verifier_wrappers_default_empty_and_deref_mut_work() {
        let mut feldman = VecFeldmanVerifierSet::<TestShare, TestVerifier>::default();
        assert_eq!(feldman.len(), 0);
        feldman.push(verifier(1));
        feldman.push(verifier(2));
        assert_eq!(feldman.generator(), verifier(1));
        assert_eq!(feldman.verifiers(), &[verifier(2)]);

        let mut feldman =
            VecFeldmanVerifierSet::<TestShare, TestVerifier>::empty_feldman_set_with_capacity(
                2,
                verifier(3),
            );
        assert_eq!(feldman.len(), 3);
        assert_eq!(feldman.generator(), verifier(3));
        feldman.verifiers_mut()[0] = verifier(4);
        assert_eq!(feldman.verifiers(), &[verifier(4), verifier(3)]);

        let mut pedersen = VecPedersenVerifierSet::<TestShare, TestVerifier>::default();
        assert_eq!(pedersen.len(), 0);
        pedersen.push(verifier(5));
        pedersen.push(verifier(6));
        pedersen.push(verifier(7));
        assert_eq!(pedersen.secret_generator(), verifier(5));
        assert_eq!(pedersen.blinder_generator(), verifier(6));
        assert_eq!(pedersen.blind_verifiers(), &[verifier(7)]);

        let mut pedersen =
            VecPedersenVerifierSet::<TestShare, TestVerifier>::empty_pedersen_set_with_capacity(
                2,
                verifier(8),
                verifier(9),
            );
        assert_eq!(pedersen.len(), 4);
        assert_eq!(pedersen.secret_generator(), verifier(8));
        assert_eq!(pedersen.blinder_generator(), verifier(9));
        assert_eq!(pedersen.blind_verifiers(), &[verifier(9), verifier(9)]);
        pedersen.blind_verifiers_mut()[1] = verifier(10);
        assert_eq!(pedersen.blind_verifiers(), &[verifier(9), verifier(10)]);
    }

    #[test]
    fn readable_share_set_combine_handles_success_and_errors() {
        let good = vec![share(1, 7), share(2, 7), share(3, 7)];
        assert_eq!(validate_share_set(&good), Ok(()));
        assert_eq!(good.combine(), Ok(IdentifierPrimeField(Scalar::from(7u64))));

        let mut out = IdentifierPrimeField(Scalar::from(99u64));
        assert_eq!(good.combine_in_place(&mut out), Ok(()));
        assert_eq!(out, IdentifierPrimeField(Scalar::from(7u64)));

        let mut out = IdentifierPrimeField(Scalar::from(99u64));
        assert_eq!(
            vec![share(1, 7)].combine_in_place(&mut out),
            Err(Error::SharingMinThreshold)
        );
        assert_eq!(out, IdentifierPrimeField(Scalar::from(99u64)));

        assert_eq!(vec![share(1, 7)].combine(), Err(Error::SharingMinThreshold));
        assert_eq!(
            validate_share_set(&[share(1, 7)]),
            Err(Error::SharingMinThreshold)
        );
        assert_eq!(
            vec![share(0, 7), share(2, 7)].combine(),
            Err(Error::SharingInvalidIdentifier)
        );
        assert_eq!(
            vec![share(1, 7), share(1, 8)].combine(),
            Err(Error::SharingDuplicateIdentifier)
        );
    }

    #[test]
    fn feldman_array_backed_sets_expose_generator_and_verifiers() {
        let inner = [verifier(9), verifier(1), verifier(2)];
        let mut array_set: ArrayFeldmanVerifierSet<TestShare, TestVerifier, 3> = inner.into();
        assert_eq!(array_set.generator(), verifier(9));
        assert_eq!(array_set.verifiers(), &[verifier(1), verifier(2)]);
        array_set.verifiers_mut()[0] = verifier(3);
        assert_eq!(<[TestVerifier; 3]>::from(array_set)[1], verifier(3));

        let from_ref: ArrayFeldmanVerifierSet<TestShare, TestVerifier, 3> = (&inner).into();
        assert_eq!(<[TestVerifier; 3]>::from(&from_ref), inner);

        let empty =
            ArrayFeldmanVerifierSet::<TestShare, TestVerifier, 3>::empty_feldman_set_with_capacity(
                2,
                verifier(4),
            );
        assert_eq!(empty.generator(), verifier(4));
    }

    #[test]
    fn feldman_generic_hybrid_and_vec_sets_round_trip_storage() {
        let generic_inner = GenericArray::<TestVerifier, GenericU3>::from_array([
            verifier(9),
            verifier(1),
            verifier(2),
        ]);
        let generic_set: GenericArrayFeldmanVerifierSet<TestShare, TestVerifier, GenericU3> =
            (&generic_inner).into();
        assert_eq!(generic_set.generator(), verifier(9));
        assert_eq!(
            GenericArray::<TestVerifier, GenericU3>::from(generic_set.clone()),
            generic_inner
        );
        assert_eq!(
            GenericArray::<TestVerifier, GenericU3>::from(&generic_set),
            generic_inner
        );

        let hybrid_inner = Array::<TestVerifier, HybridU3>::from_fn(|i| verifier(i as u64 + 1));
        let hybrid_set: HybridArrayFeldmanVerifierSet<TestShare, TestVerifier, HybridU3> =
            (&hybrid_inner).into();
        assert_eq!(hybrid_set.generator(), verifier(1));
        assert_eq!(
            Array::<TestVerifier, HybridU3>::from(&hybrid_set),
            hybrid_inner
        );

        let vec_inner = vec![verifier(9), verifier(1), verifier(2)];
        let mut vec_set: VecFeldmanVerifierSet<TestShare, TestVerifier> = (&vec_inner).into();
        assert_eq!(vec_set.generator(), verifier(9));
        vec_set.verifiers_mut()[1] = verifier(5);
        assert_eq!(Vec::<TestVerifier>::from(&vec_set)[2], verifier(5));
        assert_eq!(
            Vec::<TestVerifier>::from(VecFeldmanVerifierSet::<TestShare, TestVerifier>::from(
                vec_inner.clone()
            )),
            vec_inner
        );
    }

    #[test]
    fn pedersen_array_and_vec_sets_expose_generators_and_verifiers() {
        let inner = [verifier(9), verifier(8), verifier(1), verifier(2)];
        let mut array_set: ArrayPedersenVerifierSet<TestShare, TestVerifier, 4> = inner.into();
        assert_eq!(array_set.secret_generator(), verifier(9));
        assert_eq!(array_set.blinder_generator(), verifier(8));
        assert_eq!(array_set.blind_verifiers(), &[verifier(1), verifier(2)]);
        array_set.blind_verifiers_mut()[0] = verifier(3);
        assert_eq!(<[TestVerifier; 4]>::from(array_set)[2], verifier(3));
        let from_ref: ArrayPedersenVerifierSet<TestShare, TestVerifier, 4> = (&inner).into();
        assert_eq!(<[TestVerifier; 4]>::from(&from_ref), inner);

        let vec_inner = vec![verifier(9), verifier(8), verifier(1), verifier(2)];
        let mut vec_set: VecPedersenVerifierSet<TestShare, TestVerifier> = (&vec_inner).into();
        assert_eq!(vec_set.secret_generator(), verifier(9));
        assert_eq!(vec_set.blinder_generator(), verifier(8));
        vec_set.blind_verifiers_mut()[1] = verifier(6);
        assert_eq!(Vec::<TestVerifier>::from(&vec_set)[3], verifier(6));
        assert_eq!(
            Vec::<TestVerifier>::from(VecPedersenVerifierSet::<TestShare, TestVerifier>::from(
                vec_inner.clone()
            )),
            vec_inner
        );
    }

    #[test]
    fn pedersen_generic_and_hybrid_sets_round_trip_storage() {
        let generic_inner = GenericArray::<TestVerifier, GenericU4>::from_array([
            verifier(9),
            verifier(8),
            verifier(1),
            verifier(2),
        ]);
        let mut generic_set: GenericArrayPedersenVerifierSet<TestShare, TestVerifier, GenericU4> =
            (&generic_inner).into();
        assert_eq!(generic_set.secret_generator(), verifier(9));
        assert_eq!(generic_set.blinder_generator(), verifier(8));
        assert_eq!(generic_set.blind_verifiers(), &[verifier(1), verifier(2)]);
        generic_set.blind_verifiers_mut()[0] = verifier(5);
        assert_eq!(
            GenericArray::<TestVerifier, GenericU4>::from(&generic_set)[2],
            verifier(5)
        );
        assert_eq!(
            GenericArray::<TestVerifier, GenericU4>::from(GenericArrayPedersenVerifierSet::<
                TestShare,
                TestVerifier,
                GenericU4,
            >::from(generic_inner)),
            generic_inner
        );
        let empty = GenericArrayPedersenVerifierSet::<TestShare, TestVerifier, GenericU4>::empty_pedersen_set_with_capacity(
            2,
            verifier(7),
            verifier(6),
        );
        assert_eq!(empty.secret_generator(), verifier(7));
        assert_eq!(empty.blinder_generator(), verifier(6));

        let hybrid_inner = Array::<TestVerifier, HybridU4>::from_fn(|i| verifier(i as u64 + 1));
        let mut hybrid_set: HybridArrayPedersenVerifierSet<TestShare, TestVerifier, HybridU4> =
            (&hybrid_inner).into();
        assert_eq!(hybrid_set.secret_generator(), verifier(1));
        assert_eq!(hybrid_set.blinder_generator(), verifier(2));
        hybrid_set.blind_verifiers_mut()[1] = verifier(9);
        assert_eq!(
            Array::<TestVerifier, HybridU4>::from(&hybrid_set)[3],
            verifier(9)
        );
        assert_eq!(
            Array::<TestVerifier, HybridU4>::from(HybridArrayPedersenVerifierSet::<
                TestShare,
                TestVerifier,
                HybridU4,
            >::from(hybrid_inner)),
            hybrid_inner
        );
        let empty = HybridArrayPedersenVerifierSet::<TestShare, TestVerifier, HybridU4>::empty_pedersen_set_with_capacity(
            2,
            verifier(5),
            verifier(4),
        );
        assert_eq!(empty.secret_generator(), verifier(5));
        assert_eq!(empty.blinder_generator(), verifier(4));
    }

    #[test]
    fn verifier_sets_return_errors_for_invalid_inputs() {
        let invalid_share = share(0, 7);
        let feldman = VecFeldmanVerifierSet::<TestShare, TestVerifier>::from(vec![
            TestVerifier::identity(),
            verifier(1),
        ]);
        assert_eq!(
            feldman.verify_share(&invalid_share),
            Err(Error::InvalidShare)
        );

        let invalid_generator = VecFeldmanVerifierSet::<TestShare, TestVerifier>::from(vec![
            TestVerifier::identity(),
            verifier(1),
        ]);
        assert_eq!(
            invalid_generator.verify_share(&share(1, 7)),
            Err(Error::InvalidGenerator("Generator is identity"))
        );

        let pedersen = VecPedersenVerifierSet::<TestShare, TestVerifier>::from(vec![
            TestVerifier::identity(),
            verifier(8),
            verifier(1),
        ]);
        assert_eq!(
            pedersen.verify_share_and_blinder(&share(1, 7), &share(1, 3)),
            Err(Error::InvalidGenerator(
                "Generator or Blind generator is an identity"
            ))
        );
    }

    #[test]
    fn verifier_sets_evaluate_at_identifier() {
        let id = IdentifierPrimeField(Scalar::from(3u64));
        let feldman = VecFeldmanVerifierSet::<TestShare, TestVerifier>::from(vec![
            verifier(1),
            verifier(5),
            verifier(2),
        ]);
        assert_eq!(feldman.evaluate_verifier_at(&id), Ok(verifier(11)));
        assert_eq!(
            feldman.evaluate_verifier_at(&IdentifierPrimeField::zero()),
            Err(Error::InvalidShare)
        );

        let pedersen = VecPedersenVerifierSet::<TestShare, TestVerifier>::from(vec![
            verifier(1),
            verifier(2),
            verifier(5),
            verifier(2),
        ]);
        assert_eq!(pedersen.evaluate_verifier_at(&id), Ok(verifier(11)));
        assert_eq!(
            pedersen.evaluate_verifier_at(&IdentifierPrimeField::zero()),
            Err(Error::InvalidShare)
        );
    }
}

#[test]
fn test_feldman_with_generator_and_verifiers() {
    type IdK256 = IdentifierPrimeField<k256::Scalar>;
    type VK256 = ValuePrimeField<k256::Scalar>;
    type ShareVerifierK256 = ShareVerifierGroup<k256::ProjectivePoint>;
    type K256Share = (IdK256, VK256);

    let set = <[ShareVerifierK256; 8] as FeldmanVerifierSet<K256Share, ShareVerifierK256>>::feldman_set_with_generator_and_verifiers(
        ValueGroup(k256::ProjectivePoint::GENERATOR),
        &[ValueGroup(k256::ProjectivePoint::IDENTITY); 7]);
    assert_eq!(
        ValueGroup(k256::ProjectivePoint::GENERATOR),
        <[ShareVerifierK256; 8] as FeldmanVerifierSet<K256Share, ShareVerifierK256>>::generator(
            &set
        )
    );
    assert_eq!(
        [ValueGroup(k256::ProjectivePoint::IDENTITY); 7],
        <[ShareVerifierK256; 8] as FeldmanVerifierSet<K256Share, ShareVerifierK256>>::verifiers(
            &set
        )
    );
}
