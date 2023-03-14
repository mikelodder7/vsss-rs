/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use crate::util::EXPECT_MSG;
use crate::Vec;
use elliptic_curve::PrimeField;
use rand_core::{CryptoRng, RngCore};

/// The polynomial used for generating the shares
pub struct Polynomial<F: PrimeField, const N: usize> {
    pub(crate) coefficients: Vec<F, N>,
}

impl<F: PrimeField, const N: usize> Polynomial<F, N> {
    /// Construct a random polynomial with `N` degree using the specified intercept
    pub fn new(intercept: F, mut rng: impl RngCore + CryptoRng) -> Self {
        let mut coefficients = Vec::<F, N>::new();

        // Ensure intercept is set
        coefficients.push(intercept).expect(EXPECT_MSG);

        // Assign random coefficients to polynomial
        // Start at 1 since 0 is the intercept and not chosen at random
        for _ in 1..N {
            coefficients.push(F::random(&mut rng)).expect(EXPECT_MSG);
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
