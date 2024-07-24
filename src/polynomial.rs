//! A polynomial structure for holding coefficients and evaluating
//! Sizes greater than 32 should probably use Vec instead of fixed sizes
//! due to stack allocations

use crate::*;
use elliptic_curve::PrimeField;
use generic_array::{ArrayLength, GenericArray};
use rand_core::{CryptoRng, RngCore};

/// The polynomial used for generating the shares
pub trait Polynomial<F: PrimeField> {
    /// Create a new polynomial with a size hint
    fn create(size_hint: usize) -> Self;

    /// Generate the polynomial coefficients
    fn fill(
        &mut self,
        intercept: F,
        mut rng: impl RngCore + CryptoRng,
        length: usize,
    ) -> VsssResult<()> {
        let repr = self.coefficients_mut();
        if repr.len() < length {
            return Err(Error::InvalidSizeRequest);
        }
        // Ensure intercept is set
        repr[0] = intercept;

        // Assign random coefficients to polynomial
        // Start at 1 since 0 is the intercept and not chosen at random
        for i in repr.iter_mut().take(length).skip(1) {
            *i = F::random(&mut rng);
            while *i == F::ZERO {
                *i = F::random(&mut rng);
            }
        }
        Ok(())
    }

    /// Evaluate the polynomial with the specified `x`
    fn evaluate(&self, x: F, threshold: usize) -> F {
        let coefficients = self.coefficients();
        // Compute the polynomial value using Horner's Method
        let degree = threshold - 1;
        // b_n = a_n
        let mut out = coefficients[degree];

        for i in (0..degree).rev() {
            // b_{n-1} = a_{n-1} + b_n*x
            out *= x;
            out += coefficients[i];
        }
        out
    }

    /// Return the coefficients of the polynomial
    fn coefficients(&self) -> &[F];

    /// Return the mutable coefficients of the polynomial
    fn coefficients_mut(&mut self) -> &mut [F];
}

impl<F: PrimeField, const L: usize> Polynomial<F> for [F; L] {
    fn create(_size_hint: usize) -> Self {
        [F::ZERO; L]
    }

    fn coefficients(&self) -> &[F] {
        self
    }

    fn coefficients_mut(&mut self) -> &mut [F] {
        self
    }
}

impl<F: PrimeField, L: ArrayLength> Polynomial<F> for GenericArray<F, L> {
    fn create(_size_hint: usize) -> Self {
        Self::default()
    }

    fn coefficients(&self) -> &[F] {
        self.as_ref()
    }

    fn coefficients_mut(&mut self) -> &mut [F] {
        self.as_mut()
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<F: PrimeField> Polynomial<F> for Vec<F> {
    fn create(size_hint: usize) -> Self {
        vec![F::ZERO; size_hint]
    }

    fn coefficients(&self) -> &[F] {
        self.as_ref()
    }

    fn coefficients_mut(&mut self) -> &mut [F] {
        self.as_mut()
    }
}
