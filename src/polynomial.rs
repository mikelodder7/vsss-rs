//! A polynomial structure for holding coefficients and evaluating
//! Sizes greater than 32 should probably use Vec instead of fixed sizes
//! due to stack allocations

use crate::*;
use generic_array::{ArrayLength, GenericArray};
use rand_core::{CryptoRng, RngCore};

/// The polynomial used for generating the shares
pub trait Polynomial<S: Share> {
    /// Create a new polynomial with a size hint
    fn create(size_hint: usize) -> Self;

    /// Generate the polynomial coefficients
    fn fill(
        &mut self,
        intercept: S::Value,
        mut rng: impl RngCore + CryptoRng,
        length: usize,
    ) -> VsssResult<()> {
        let repr = self.coefficients_mut();
        if repr.len() < length {
            return Err(Error::InvalidSizeRequest);
        }
        // Ensure intercept is set
        *repr[0].value_mut() = intercept;

        // Assign random coefficients to polynomial
        // Start at 1 since 0 is the intercept and not chosen at random
        for i in repr.iter_mut().skip(1) {
            *i.identifier_mut() = S::Identifier::random(&mut rng);
            while i.identifier().is_zero().into() {
                *i.identifier_mut() = S::Identifier::random(&mut rng);
            }
        }
        Ok(())
    }

    /// Evaluate the polynomial with the specified `x`
    fn evaluate(&self, x: &S::Identifier, threshold: usize) -> S::Value {
        let coefficients = self.coefficients();
        // Compute the polynomial value using Horner's Method
        let degree = threshold - 1;
        // b_n = a_n
        let mut out = coefficients[degree].identifier().clone();

        for i in (0..degree).rev() {
            // b_{n-1} = a_{n-1} + b_n*x
            *out *= x.as_ref();
            *out += coefficients[i].identifier().as_ref();
        }
        let mut out = S::Value::from(&out);
        *out += coefficients[0].value().as_ref();
        out
    }

    /// Return the coefficients of the polynomial
    fn coefficients(&self) -> &[S];

    /// Return the mutable coefficients of the polynomial
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
