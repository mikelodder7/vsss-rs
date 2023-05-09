//! A polynomial structure for holding coefficients and evaluating
//! Sizes greater than 32 should probably use Vec instead of fixed sizes
//! due to stack allocations

use crate::*;
use elliptic_curve::{
    ff::PrimeField,
    generic_array::{typenum, GenericArray},
};
use rand_core::{CryptoRng, RngCore};

/// The polynomial used for generating the shares
pub trait Polynomial<F: PrimeField>: Sized {
    /// Create a new empty polynomial with the specified size
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
        for i in 1..length {
            repr[i] = F::random(&mut rng);
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

macro_rules! polynomial_arr_impl {
    ($($size:ident => $num:expr),+$(,)*) => {
        $(
        impl<F: PrimeField> Polynomial<F> for [F; $num] {
            fn create(_size_hint: usize) -> Self {
                [F::default(); $num]
            }

            fn coefficients(&self) -> &[F] {
                self
            }

            fn coefficients_mut(&mut self) -> &mut [F] {
                self
            }
        }

        impl<F: PrimeField> Polynomial<F> for GenericArray<F, typenum::$size> {
            fn create(_size_hint: usize) -> Self {
                Self::from([F::default(); $num])
            }

            fn coefficients(&self) -> &[F] {
                self.as_ref()
            }

            fn coefficients_mut(&mut self) -> &mut [F] {
                self.as_mut()
            }
        }
        )+
    };
}

polynomial_arr_impl!(
    U2 => 2, U3 => 3, U4 => 4, U5 => 5, U6 => 6, U7 => 7, U8 => 8, U9 => 9,
    U10 => 10, U11 => 11, U12 => 12, U13 => 13, U14 => 14, U15 => 15, U16 => 16,
    U17 => 17, U18 => 18, U19 => 19, U20 => 20, U21 => 21, U22 => 22, U23 => 23,
    U24 => 24, U25 => 25, U26 => 26, U27 => 27, U28 => 28, U29 => 29, U30 => 30,
    U31 => 31, U32 => 32, U33 => 33, U34 => 34, U35 => 35, U36 => 36, U37 => 37,
    U38 => 38, U39 => 39, U40 => 40, U41 => 41, U42 => 42, U43 => 43, U44 => 44,
    U45 => 45, U46 => 46, U47 => 47, U48 => 48, U49 => 49, U50 => 50, U51 => 51,
    U52 => 52, U53 => 53, U54 => 54, U55 => 55, U56 => 56, U57 => 57, U58 => 58,
    U59 => 59, U60 => 60, U61 => 61, U62 => 62, U63 => 63, U64 => 64,
);

#[cfg(any(feature = "alloc", feature = "std"))]
impl<F: PrimeField> Polynomial<F> for Vec<F> {
    fn create(size_hint: usize) -> Self {
        vec![F::default(); size_hint]
    }

    fn coefficients(&self) -> &[F] {
        self.as_ref()
    }

    fn coefficients_mut(&mut self) -> &mut [F] {
        self.as_mut()
    }
}
