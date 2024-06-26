//! Sets are used for storing shares and other data associated with
//! secret sharing operations like splitting, combining, and verifying
//! Sizes greater than 32 should probably use Vec instead of fixed sizes
//! due to stack allocations
use crate::*;
use elliptic_curve::{ff::Field, group::GroupEncoding, Group, PrimeField};
use generic_array::{ArrayLength, GenericArray};

/// Represents a readable data store for secret shares
pub trait ReadableShareSet<I: ShareIdentifier, S: Share<Identifier = I>>: AsRef<[S]> {
    /// Convert the given shares into a field element
    fn combine_to_field_element<F: PrimeField, C>(&self) -> VsssResult<F>
    where
        C: ShareSetCombiner<I, S, F, F>,
    {
        C::combine(self.as_ref(), |s| s.as_field_element::<F>())
    }

    /// Convert the given shares into a group element
    fn combine_to_group_element<G, C>(&self) -> VsssResult<G>
    where
        G: Group + GroupEncoding + Default,
        C: ShareSetCombiner<I, S, G::Scalar, G>,
    {
        C::combine(self.as_ref(), |s| s.as_group_element::<G>())
    }
}

/// Represents a data store for secret shares
pub trait WriteableShareSet<I: ShareIdentifier, S: Share<Identifier = I>>:
    ReadableShareSet<I, S> + AsMut<[S]>
{
    /// Create a new writeable share set
    fn create(size_hint: usize) -> Self;
}

impl<I: ShareIdentifier, S: Share<Identifier = I>, B: AsRef<[S]>> ReadableShareSet<I, S> for B {}

/// A data store for reconstructing secret shares
pub trait ShareSetCombiner<I, S, F, G>: Sized + AsRef<[(F, G)]> + AsMut<[(F, G)]>
where
    I: ShareIdentifier,
    S: Share<Identifier = I>,
    F: PrimeField,
    G: Default + Copy + core::ops::AddAssign + core::ops::Mul<F, Output = G>,
{
    /// Create a new shared set combiner
    fn create(size_hint: usize) -> Self;

    /// Combine the secret shares into a single secret
    /// using Lagrange interpolation
    fn combine<BB, M>(shares: BB, mut m: M) -> VsssResult<G>
    where
        BB: AsRef<[S]>,
        M: FnMut(&S) -> VsssResult<G>,
    {
        let shares = shares.as_ref();
        if shares.len() < 2 {
            return Err(Error::SharingMinThreshold);
        }
        let mut values = Self::create(shares.len());
        {
            let indexer = values.as_mut();
            for (i, s) in shares.iter().enumerate() {
                if s.identifier().is_zero().into() {
                    return Err(Error::SharingInvalidIdentifier);
                }
                let x = s.identifier().as_field_element()?;
                let y = m(s)?;
                indexer[i] = (x, y);
            }
        }
        let inner_values = &values.as_ref()[..shares.len()];
        if dup_checker(inner_values) {
            return Err(Error::SharingDuplicateIdentifier);
        }
        interpolate(inner_values)
    }
}

fn interpolate<F, S>(shares: &[(F, S)]) -> VsssResult<S>
where
    F: PrimeField,
    S: Default + Copy + core::ops::AddAssign + core::ops::Mul<F, Output = S>,
{
    let mut secret = S::default();
    // Calculate lagrange interpolation
    for (i, &(x_i, s)) in shares.iter().enumerate() {
        let mut num = F::ONE;
        let mut den = F::ONE;
        for (j, &(x_j, _)) in shares.iter().enumerate() {
            if i == j {
                continue;
            }

            den *= x_j - x_i;
            num *= x_j;
            // x_j / (x_j - x_i) * ...
        }

        let basis = num * den.invert().expect("shouldn't be zero");
        secret += s * basis;
    }

    Ok(secret)
}

impl<I, S, F, G, const L: usize> ShareSetCombiner<I, S, F, G> for [(F, G); L]
where
    I: ShareIdentifier,
    S: Share<Identifier = I>,
    F: PrimeField,
    G: Default + Copy + core::ops::AddAssign + core::ops::Mul<F, Output = G>,
{
    fn create(_size_hint: usize) -> Self {
        [(F::ZERO, G::default()); L]
    }
}

impl<I, S, F, G, L> ShareSetCombiner<I, S, F, G> for GenericArray<(F, G), L>
where
    I: ShareIdentifier,
    S: Share<Identifier = I>,
    F: PrimeField,
    G: Default + Copy + core::ops::AddAssign + core::ops::Mul<F, Output = G>,
    L: ArrayLength,
{
    fn create(_size_hint: usize) -> Self {
        Self::default()
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<
        I: ShareIdentifier,
        S: Share<Identifier = I>,
        F: PrimeField,
        G: Default + Copy + core::ops::AddAssign + core::ops::Mul<F, Output = G>,
    > ShareSetCombiner<I, S, F, G> for Vec<(F, G)>
{
    fn create(size_hint: usize) -> Self {
        vec![(F::ZERO, G::default()); size_hint]
    }
}

impl<I, S, const L: usize> WriteableShareSet<I, S> for [S; L]
where
    I: ShareIdentifier,
    S: Share<Identifier = I>,
{
    fn create(_size_hint: usize) -> Self {
        core::array::from_fn(|_| S::empty_share_with_capacity(0))
    }
}

impl<I, S, L> WriteableShareSet<I, S> for GenericArray<S, L>
where
    I: ShareIdentifier,
    S: Share<Identifier = I>,
    L: ArrayLength,
{
    fn create(_size_hint: usize) -> Self {
        Self::try_from_iter((0..L::to_usize()).map(|_| S::empty_share_with_capacity(0))).unwrap()
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for Vec<S> {
    fn create(size_hint: usize) -> Self {
        (0..size_hint)
            .map(|_| S::empty_share_with_capacity(0))
            .collect()
    }
}

fn dup_checker<B, F, G>(set: B) -> bool
where
    B: AsRef<[(F, G)]>,
    F: PrimeField,
    G: Default + Copy + core::ops::AddAssign + core::ops::Mul<F, Output = G>,
{
    let indexer = set.as_ref();
    for (i, (x_i, _)) in indexer.iter().enumerate() {
        for (x_j, _) in indexer.iter().skip(i + 1) {
            if x_i == x_j {
                return true;
            }
        }
    }
    false
}

/// Objects that represent the ability to verify shamir shares using
/// Feldman verifiers
pub trait FeldmanVerifierSet<G: Group + GroupEncoding + Default>: Sized {
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
    fn verify_share<I: ShareIdentifier, S: Share<Identifier = I>>(
        &self,
        share: &S,
    ) -> VsssResult<()> {
        if (share.is_zero() | share.identifier().is_zero()).into() {
            return Err(Error::InvalidShare);
        }
        if self.generator().is_identity().into() {
            return Err(Error::InvalidGenerator);
        }

        let s = share.as_field_element::<G::Scalar>()?;

        let x = share.identifier().as_field_element::<G::Scalar>()?;
        let mut i = G::Scalar::ONE;

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
            i *= x;

            // c_0 * c_1^i * c_2^{i^2} ... c_t^{i^t}
            rhs += *v * i;
        }

        let lhs: G = -self.generator() * s;

        let res: G = lhs + rhs;

        if res.is_identity().into() {
            Ok(())
        } else {
            Err(Error::InvalidShare)
        }
    }
}

/// Objects that represent the ability to verify shamir shares using
/// Pedersen verifiers
pub trait PedersenVerifierSet<G: Group + GroupEncoding + Default>: Sized {
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
    fn verify_share_and_blinder<I: ShareIdentifier, S: Share<Identifier = I>>(
        &self,
        share: &S,
        blinder: &S,
    ) -> VsssResult<()> {
        if (share.is_zero() | blinder.is_zero() | share.identifier().is_zero()).into() {
            return Err(Error::InvalidShare);
        }
        let blind_generator = self.blinder_generator();
        let generator = self.secret_generator();

        if (generator.is_identity() | blind_generator.is_identity()).into() {
            return Err(Error::InvalidGenerator);
        }

        let secret = share.as_field_element::<G::Scalar>()?;
        let blinder = blinder.as_field_element::<G::Scalar>()?;

        let x = share.identifier().as_field_element::<G::Scalar>()?;
        let mut i = G::Scalar::ONE;

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
            i *= x;

            // c_0 * c_1^i * c_2^{i^2} ... c_t^{i^t}
            rhs += *v * i;
        }

        let g = (-generator) * secret;
        let h = (-blind_generator) * blinder;

        let res = rhs + g + h;

        if res.is_identity().into() {
            Ok(())
        } else {
            Err(Error::InvalidShare)
        }
    }
}

impl<G: Group + GroupEncoding + Default, const L: usize> FeldmanVerifierSet<G> for [G; L] {
    fn empty_feldman_set_with_capacity(_size_hint: usize, generator: G) -> Self {
        let mut t = [G::identity(); L];
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

impl<G: Group + GroupEncoding + Default, L: ArrayLength> FeldmanVerifierSet<G>
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

#[cfg(any(feature = "alloc", feature = "std"))]
impl<G: Group + GroupEncoding + Default> FeldmanVerifierSet<G> for Vec<G> {
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

impl<G: Group + GroupEncoding + Default, const L: usize> PedersenVerifierSet<G> for [G; L] {
    fn empty_pedersen_set_with_capacity(
        _size_hint: usize,
        secret_generator: G,
        blinder_generator: G,
    ) -> Self {
        let mut t = [G::identity(); L];
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

impl<G: Group + GroupEncoding + Default, L: ArrayLength> PedersenVerifierSet<G>
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

#[cfg(any(feature = "alloc", feature = "std"))]
impl<G: Group + GroupEncoding + Default> PedersenVerifierSet<G> for Vec<G> {
    fn empty_pedersen_set_with_capacity(
        size_hint: usize,
        secret_generator: G,
        blinder_generator: G,
    ) -> Self {
        let mut t = vec![blinder_generator; size_hint + 2];
        t[0] = secret_generator;
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

#[test]
fn test_feldman_with_generator_and_verifiers() {
    let set = <[k256::ProjectivePoint; 8] as FeldmanVerifierSet<k256::ProjectivePoint>>::feldman_set_with_generator_and_verifiers(
        k256::ProjectivePoint::GENERATOR,
        &[k256::ProjectivePoint::IDENTITY; 7]);
    assert_eq!(k256::ProjectivePoint::GENERATOR, set.generator());
    assert_eq!([k256::ProjectivePoint::IDENTITY; 7], set.verifiers());
}
