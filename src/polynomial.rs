/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use crate::*;
use elliptic_curve::ff::PrimeField;
use rand_core::{CryptoRng, RngCore};

/// The polynomial used for generating the shares
pub struct Polynomial<F: PrimeField> {
    pub(crate) coefficients: Vec<F, MAX_POLYNOMIAL_SIZE>,
}

impl<F: PrimeField> Polynomial<F> {
    /// Construct a random polynomial with `N` degree using the specified intercept
    pub fn new(intercept: F, mut rng: impl RngCore + CryptoRng, length: usize) -> Self {
        let mut coefficients = Vec::new();

        // Ensure intercept is set
        coefficients.push(intercept).expect(EXPECT_MSG);

        // Assign random coefficients to polynomial
        // Start at 1 since 0 is the intercept and not chosen at random
        for _ in 1..length {
            coefficients.push(F::random(&mut rng)).expect(EXPECT_MSG);
        }
        Self { coefficients }
    }

    /// Compute the value of the polynomial for the given `x`
    pub fn evaluate(&self, x: F, threshold: usize) -> F {
        // Compute the polynomial value using Horner's Method
        let degree = threshold - 1;
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
