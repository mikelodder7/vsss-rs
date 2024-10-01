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

/// Represents a readable data store for secret shares
pub trait ReadableShareSet<S>: AsRef<[S]>
where
    S: Share,
{
    /// Convert the given shares into a field element
    fn combine(&self) -> VsssResult<S::Value> {
        let shares = self.as_ref();
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
        interpolate(shares)
    }
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

fn interpolate<S>(shares: &[S]) -> VsssResult<S::Value>
where
    S: Share,
{
    let mut secret = S::Value::default();
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

        let den = den.invert().expect("shouldn't be zero");
        let basis: S::Identifier = (num.as_ref().clone() * den.as_ref()).into();
        let t = x_i.value().clone() * &basis;
        *secret.as_mut() += t.as_ref();
    }

    Ok(secret)
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

    /// Verify a share with this set
    fn verify_share(&self, share: &S) -> VsssResult<()> {
        if (share.value().is_zero() | share.identifier().is_zero()).into() {
            return Err(Error::InvalidShare);
        }
        if self.generator().is_zero().into() {
            return Err(Error::InvalidGenerator("Generator is identity"));
        }

        let s = share.value();

        let mut i = S::Identifier::one();

        // FUTURE: execute this sum of products
        // c_0 * c_1^i * c_2^{i^2} ... c_t^{i^t}
        // as a constant time operation using <https://cr.yp.to/papers/pippenger.pdf>
        // or Guide to Elliptic Curve Cryptography book,
        // "Algorithm 3.48 Simultaneous multiple point multiplication"
        // without precomputing the addition but still reduces doublings

        // c_0
        let commitments = self.verifiers();
        let mut rhs = commitments[0];
        for v in &commitments[1..] {
            *i.as_mut() *= share.identifier().as_ref();

            // c_0 * c_1^i * c_2^{i^2} ... c_t^{i^t}
            rhs += *v * i.clone();
        }

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

    /// Verify a share and blinder with this set
    fn verify_share_and_blinder(&self, share: &S, blinder: &S) -> VsssResult<()> {
        if (share.value().is_zero() | blinder.value().is_zero() | share.identifier().is_zero())
            .into()
        {
            return Err(Error::InvalidShare);
        }
        let blind_generator = self.blinder_generator();
        let generator = self.secret_generator();

        if generator == G::default() || blind_generator == G::default() {
            return Err(Error::InvalidGenerator(
                "Generator or Blind generator is an identity",
            ));
        }

        let secret = share.value();
        let blinder = blinder.value();
        let x = share.identifier();

        let mut i = S::Identifier::one();

        // FUTURE: execute this sum of products
        // c_0 * c_1^i * c_2^{i^2} ... c_t^{i^t}
        // as a constant time operation using <https://cr.yp.to/papers/pippenger.pdf>
        // or Guide to Elliptic Curve Cryptography book,
        // "Algorithm 3.48 Simultaneous multiple point multiplication"
        // without precomputing the addition but still reduces doublings

        let commitments = self.blind_verifiers();
        // c_0
        let mut rhs = commitments[0];
        for v in &commitments[1..] {
            *i.as_mut() *= x.as_ref();

            // c_0 * c_1^i * c_2^{i^2} ... c_t^{i^t}
            rhs += *v * i.clone();
        }

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

/// A wrapper around a generic array of verifiers
/// Allows for convenient type aliasing
/// ```
/// use vsss_rs::{DefaultShare, IdentifierPrimeField, ValueGroup, GenericArrayPedersenVerifierSet};
/// use generic_array::typenum::U4;
/// type K256Share = DefaultShare<IdentifierPrimeField<k256::Scalar>, IdentifierPrimeField<k256::Scalar>>;
/// type K256PedersenVerifierSet = GenericArrayPedersenVerifierSet<K256Share, ValueGroup<k256::ProjectivePoint>, U4>;
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
