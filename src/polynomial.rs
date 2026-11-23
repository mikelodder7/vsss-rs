//! A polynomial type for storing coefficients and evaluating the polynomial.
//! Sizes greater than 32 should probably use `Vec` instead of fixed-size storage
//! because of stack allocations.

use crate::*;
use generic_array::{ArrayLength, GenericArray};
use hybrid_array::{Array, ArraySize};
use rand_core::CryptoRng;

/// The polynomial used for generating the shares
pub trait Polynomial<S: Share> {
    /// Create a new polynomial with a size hint
    fn create(size_hint: usize) -> Self;

    /// Generate the polynomial coefficients
    fn fill(
        &mut self,
        intercept: &S::Value,
        mut rng: impl CryptoRng,
        length: usize,
    ) -> VsssResult<()> {
        let repr = self.coefficients_mut();
        if repr.len() < length {
            return Err(Error::InvalidSizeRequest);
        }
        // Ensure intercept is set
        *repr[0].value_mut() = intercept.clone();

        // Assign random coefficients. Slot 0 is the intercept (secret).
        //
        // Coefficients must be drawn uniformly over the entire field
        // including zero (audit finding #2) — rejecting zeros biases
        // the distribution and is exploitable in re-sharing scenarios.
        // Small-field identifiers (GF(256), GF(16)) override
        // `random_coefficient` because their `random` is the non-zero
        // x-sampler; prime fields use the default impl which is already
        // uniform.
        for i in repr.iter_mut().take(length).skip(1) {
            *i.identifier_mut() = S::Identifier::random_coefficient(&mut rng);
        }
        Ok(())
    }

    /// Evaluate the polynomial with the specified `x`, writing the result into `out`.
    fn evaluate_in_place(&self, x: &S::Identifier, threshold: usize, out: &mut S::Value) {
        let coefficients = self.coefficients();
        // Compute the polynomial value using Horner's method.
        let degree = threshold - 1;
        // b_n = a_n
        let mut accumulator = coefficients[degree].identifier().clone();

        for i in (0..degree).rev() {
            // b_{n-1} = a_{n-1} + b_n*x
            *accumulator *= x.as_ref();
            *accumulator += coefficients[i].identifier().as_ref();
        }

        *out = S::Value::from(&accumulator);
        *out.as_mut() += coefficients[0].value().as_ref();
    }

    /// Evaluate the polynomial with the specified `x`.
    fn evaluate(&self, x: &S::Identifier, threshold: usize) -> S::Value {
        let mut out = S::Value::default();
        self.evaluate_in_place(x, threshold, &mut out);
        out
    }

    /// Return the coefficients of the polynomial.
    fn coefficients(&self) -> &[S];

    /// Return the mutable coefficients of the polynomial.
    fn coefficients_mut(&mut self) -> &mut [S];
}

impl<S: Share, const L: usize> Polynomial<S> for [S; L] {
    fn create(_size_hint: usize) -> Self {
        core::array::from_fn(|_| Default::default())
    }

    fn coefficients(&self) -> &[S] {
        self
    }

    fn coefficients_mut(&mut self) -> &mut [S] {
        self
    }
}

impl<S: Share, L: ArrayLength> Polynomial<S> for GenericArray<S, L> {
    fn create(_size_hint: usize) -> Self {
        GenericArray::default()
    }

    fn coefficients(&self) -> &[S] {
        self.as_ref()
    }

    fn coefficients_mut(&mut self) -> &mut [S] {
        self.as_mut()
    }
}

impl<S: Share, L: ArraySize> Polynomial<S> for Array<S, L> {
    fn create(_size_hint: usize) -> Self {
        Array::default()
    }

    fn coefficients(&self) -> &[S] {
        self.as_ref()
    }

    fn coefficients_mut(&mut self) -> &mut [S] {
        self.as_mut()
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S: Share> Polynomial<S> for Vec<S> {
    fn create(size_hint: usize) -> Self {
        vec![Default::default(); size_hint]
    }

    fn coefficients(&self) -> &[S] {
        self.as_ref()
    }

    fn coefficients_mut(&mut self) -> &mut [S] {
        self.as_mut()
    }
}

/// Wraps a polynomial and wipes its coefficients when dropped.
///
/// Coefficient 0 holds the secret and the rest are enough to rebuild it, so
/// every split path keeps its polynomial in this guard. Without the `zeroize`
/// feature it is a plain wrapper.
pub(crate) struct ZeroizingPolynomial<S: Share, P: Polynomial<S>> {
    inner: P,
    _share: core::marker::PhantomData<S>,
}

impl<S: Share, P: Polynomial<S>> Polynomial<S> for ZeroizingPolynomial<S, P> {
    fn create(size_hint: usize) -> Self {
        Self {
            inner: P::create(size_hint),
            _share: core::marker::PhantomData,
        }
    }

    fn coefficients(&self) -> &[S] {
        self.inner.coefficients()
    }

    fn coefficients_mut(&mut self) -> &mut [S] {
        self.inner.coefficients_mut()
    }
}

impl<S: Share, P: Polynomial<S>> ZeroizingPolynomial<S, P> {
    /// A guarded polynomial of `threshold` coefficients whose constant term
    /// is `constant` and whose other coefficients are uniformly random.
    pub(crate) fn random(
        constant: &S::Value,
        rng: impl CryptoRng,
        threshold: usize,
    ) -> VsssResult<Self> {
        let mut polynomial = Self::create(threshold);
        polynomial.fill(constant, rng, threshold)?;
        Ok(polynomial)
    }
}

/// The `k`-th coefficient of a polynomial stored the crate's way: the
/// constant term in the value, every other coefficient in the identifier.
#[cfg(feature = "pi-la")]
pub(crate) fn coefficient<S, F>(share: &S, k: usize) -> &IdentifierPrimeField<F>
where
    F: elliptic_curve::PrimeField,
    S: Share<Identifier = IdentifierPrimeField<F>, Value = IdentifierPrimeField<F>>,
{
    if k == 0 {
        share.value()
    } else {
        share.identifier()
    }
}

/// Evaluate the polynomial with coefficients `z`, constant term first, at
/// `x` with Horner's method.
#[cfg(feature = "pi-la")]
pub(crate) fn evaluate<F: elliptic_curve::PrimeField>(
    z: &[IdentifierPrimeField<F>],
    x: &IdentifierPrimeField<F>,
) -> F {
    z.iter().rev().fold(F::ZERO, |acc, c| acc * x.0 + c.0)
}

/// The coefficients of `mask + s·f`, for polynomials stored as in
/// [`coefficient`].
#[cfg(feature = "pi-la")]
pub(crate) fn mask_plus_scaled<S, F>(mask: &[S], s: F, f: &[S]) -> Vec<IdentifierPrimeField<F>>
where
    F: elliptic_curve::PrimeField,
    S: Share<Identifier = IdentifierPrimeField<F>, Value = IdentifierPrimeField<F>>,
{
    mask.iter()
        .zip(f)
        .enumerate()
        .map(|(k, (m_k, f_k))| {
            IdentifierPrimeField(coefficient(m_k, k).0 + s * coefficient(f_k, k).0)
        })
        .collect()
}

#[cfg(feature = "zeroize")]
impl<S: Share, P: Polynomial<S>> zeroize::Zeroize for ZeroizingPolynomial<S, P> {
    fn zeroize(&mut self) {
        self.inner
            .coefficients_mut()
            .iter_mut()
            .for_each(zeroize::Zeroize::zeroize);
    }
}

#[cfg(feature = "zeroize")]
impl<S: Share, P: Polynomial<S>> Drop for ZeroizingPolynomial<S, P> {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

#[cfg(test)]
mod tests {
    use super::Polynomial;
    use crate::{Error, IdentifierPrimeField, PrimeFieldShare, Share, ShareElement};
    use generic_array::{GenericArray, typenum::U3 as GenericU3};
    use hybrid_array::{Array, typenum::U3 as HybridU3};
    use k256::Scalar;
    use rand_core::SeedableRng;
    use std::vec::Vec;

    type TestShare = PrimeFieldShare<Scalar>;

    fn share(identifier: u64, value: u64) -> TestShare {
        TestShare::with_identifier_and_value(
            IdentifierPrimeField(Scalar::from(identifier)),
            IdentifierPrimeField(Scalar::from(value)),
        )
    }

    #[test]
    fn polynomial_create_works_for_all_storage_backends() {
        let array = <[TestShare; 3] as Polynomial<TestShare>>::create(99);
        assert_eq!(array.coefficients().len(), 3);

        let generic = <GenericArray<TestShare, GenericU3> as Polynomial<TestShare>>::create(99);
        assert_eq!(generic.coefficients().len(), 3);

        let hybrid = <Array<TestShare, HybridU3> as Polynomial<TestShare>>::create(99);
        assert_eq!(hybrid.coefficients().len(), 3);

        let vec = <Vec<TestShare> as Polynomial<TestShare>>::create(4);
        assert_eq!(vec.coefficients().len(), 4);
    }

    #[test]
    fn polynomial_fill_sets_intercept_and_rejects_oversized_request() {
        let mut polynomial = <[TestShare; 2] as Polynomial<TestShare>>::create(0);
        let secret = IdentifierPrimeField(Scalar::from(42u64));
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([7u8; 32]);

        assert_eq!(polynomial.fill(&secret, &mut rng, 2), Ok(()));
        assert_eq!(polynomial.coefficients()[0].value(), &secret);
        assert_ne!(
            polynomial.coefficients()[1].identifier(),
            &IdentifierPrimeField::zero()
        );

        assert_eq!(
            polynomial.fill(&secret, &mut rng, 3),
            Err(Error::InvalidSizeRequest)
        );
    }

    #[test]
    fn polynomial_evaluate_uses_horner_method_with_intercept() {
        let polynomial = [share(0, 5), share(2, 0), share(3, 0)];
        let x = IdentifierPrimeField(Scalar::from(4u64));

        assert_eq!(
            polynomial.evaluate(&x, 3),
            IdentifierPrimeField(Scalar::from(61u64))
        );
        assert_eq!(
            polynomial.evaluate(&x, 2),
            IdentifierPrimeField(Scalar::from(13u64))
        );

        let mut out = IdentifierPrimeField(Scalar::from(99u64));
        polynomial.evaluate_in_place(&x, 3, &mut out);
        assert_eq!(out, IdentifierPrimeField(Scalar::from(61u64)));
    }

    #[test]
    fn polynomial_coefficients_mut_updates_backing_storage() {
        let mut polynomial = <Vec<TestShare> as Polynomial<TestShare>>::create(2);
        polynomial.coefficients_mut()[0] = share(9, 10);
        polynomial.coefficients_mut()[1] = share(11, 12);

        assert_eq!(polynomial.coefficients(), &[share(9, 10), share(11, 12)]);
    }

    #[test]
    fn zeroizing_polynomial_random_matches_create_then_fill() {
        use super::ZeroizingPolynomial;
        let secret = IdentifierPrimeField(Scalar::from(42u64));
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([5u8; 32]);
        let random = ZeroizingPolynomial::<TestShare, Vec<TestShare>>::random(&secret, &mut rng, 3)
            .expect("fits");
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([5u8; 32]);
        let mut filled = <Vec<TestShare> as Polynomial<TestShare>>::create(3);
        filled.fill(&secret, &mut rng, 3).expect("fits");
        assert_eq!(random.coefficients(), filled.coefficients());
        assert_eq!(
            ZeroizingPolynomial::<TestShare, [TestShare; 2]>::random(&secret, &mut rng, 3).err(),
            Some(Error::InvalidSizeRequest)
        );
    }

    #[cfg(feature = "pi-la")]
    #[test]
    fn coefficient_evaluate_and_mask_plus_scaled_match_their_definitions() {
        use super::{coefficient, evaluate, mask_plus_scaled};
        // Constant term lives in the value, the rest in the identifier.
        let poly = [share(9, 2), share(3, 9), share(5, 9)];
        assert_eq!(coefficient(&poly[0], 0).0, Scalar::from(2u64));
        assert_eq!(coefficient(&poly[1], 1).0, Scalar::from(3u64));
        assert_eq!(coefficient(&poly[2], 2).0, Scalar::from(5u64));

        // z(x) = 2 + 3x + 5x^2 at x = 4 is 2 + 12 + 80 = 94.
        let z = [2u64, 3, 5].map(|c| IdentifierPrimeField(Scalar::from(c)));
        let x = IdentifierPrimeField(Scalar::from(4u64));
        assert_eq!(evaluate(&z, &x), Scalar::from(94u64));
        assert_eq!(evaluate::<Scalar>(&[], &x), Scalar::ZERO);

        // (2 + 3x + 5x²) + 2·(1 + 4x + 6x²) = 4 + 11x + 17x².
        let f = [share(0, 1), share(4, 0), share(6, 0)];
        let combined = mask_plus_scaled(&poly, Scalar::from(2u64), &f);
        let expected = [4u64, 11, 17].map(|c| IdentifierPrimeField(Scalar::from(c)));
        assert_eq!(combined, expected);
    }

    #[cfg(feature = "zeroize")]
    #[test]
    fn zeroizing_polynomial_wipes_every_coefficient() {
        use super::ZeroizingPolynomial;
        use zeroize::Zeroize;

        let mut rng = rand_chacha::ChaCha8Rng::from_seed([9u8; 32]);
        let secret = IdentifierPrimeField(Scalar::from(42u64));
        let mut polynomial =
            <ZeroizingPolynomial<TestShare, Vec<TestShare>> as Polynomial<TestShare>>::create(3);
        assert_eq!(polynomial.fill(&secret, &mut rng, 3), Ok(()));
        assert_eq!(polynomial.coefficients()[0].value(), &secret);

        polynomial.zeroize();

        assert_eq!(polynomial.coefficients().len(), 3);
        assert!(
            polynomial
                .coefficients()
                .iter()
                .all(|s| s.identifier().is_zero().into() && s.value().is_zero().into())
        );
    }
}
