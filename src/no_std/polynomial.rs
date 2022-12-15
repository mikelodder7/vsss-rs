/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use elliptic_curve::ff::PrimeField;
use rand_core::{CryptoRng, RngCore};

/// The polynomial used for generating the shares
pub struct Polynomial<F: PrimeField + Copy + Default, const N: usize> {
    pub(crate) coefficients: [F; N],
}

impl<F: PrimeField + Copy + Default, const N: usize> Polynomial<F, N> {
    /// Construct a random polynomial with `N` degree using the specified intercept
    pub fn new(intercept: F, mut rng: impl RngCore + CryptoRng) -> Self {
        let mut coefficients = [F::default(); N];

        // Ensure intercept is set
        coefficients[0] = intercept;

        // Assign random coefficients to polynomial
        // Start at 1 since 0 is the intercept and not chosen at random
        for c in coefficients.iter_mut().skip(1) {
            *c = F::random(&mut rng);
        }
        Self { coefficients }
    }

    /// Compute the value of the polynomial for the given `x`
    pub fn evaluate(&self, x: F) -> F {
        // Compute the polynomial value using Horner's Method
        let degree = N - 1;
        // b_n = a_n
        let mut out = self.coefficients[degree];

        for i in (0..degree).rev() {
            // b_{n-1} = a_{n-1} + b_n*x
            out *= x;
            out += self.coefficients[i];
        }
        out
    }
}
