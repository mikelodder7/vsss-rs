/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::*;
use core::ops::{AddAssign, Mul};
use elliptic_curve::{
    ff::PrimeField,
    group::{Group, GroupEncoding, ScalarMul},
};
use rand_core::{CryptoRng, RngCore};
use std::collections::BTreeSet;

/// Shamir's simple secret sharing scheme
/// T is the threshold
/// N is the total number of shares
#[derive(Copy, Clone, Debug, Default)]
pub struct Shamir {
    /// The threshold necessary for combine
    pub t: usize,
    /// The number of shares to allocate
    pub n: usize,
}

impl Shamir {
    /// Create shares from a secret.
    /// F is the prime field
    /// S is the number of bytes used to represent F
    pub fn split_secret<F, R>(&self, secret: F, rng: &mut R) -> VsssResult<Vec<Share>>
    where
        F: PrimeField,
        R: RngCore + CryptoRng,
    {
        self.check_params()?;

        let (shares, _) = self.get_shares_and_polynomial(secret, rng);
        Ok(shares)
    }

    /// Reconstruct a secret from shares created from `split_secret`.
    /// The X-coordinates operate in `F`
    /// The Y-coordinates operate in `F`
    pub fn combine_shares<F>(&self, shares: &[Share]) -> VsssResult<F>
    where
        F: PrimeField,
    {
        self.combine::<F, F>(shares, bytes_to_field)
    }

    /// Reconstruct a secret from shares created from `split_secret`.
    /// The X-coordinates operate in `F`
    /// The Y-coordinates operate in `G`
    ///
    /// Exists to support operations like threshold BLS where the shares
    /// operate in `F` but the partial signatures operate in `G`.
    pub fn combine_shares_group<F, G>(&self, shares: &[Share]) -> VsssResult<G>
    where
        F: PrimeField,
        G: Group + GroupEncoding + ScalarMul<F> + Default,
    {
        self.combine::<F, G>(shares, bytes_to_group)
    }

    fn combine<F, S>(&self, shares: &[Share], f: fn(&[u8]) -> Option<S>) -> VsssResult<S>
    where
        F: PrimeField,
        S: Default + Copy + AddAssign + Mul<F, Output = S>,
    {
        if shares.len() < 2 {
            return Err(Error::SharingMinThreshold);
        }

        let mut dups = BTreeSet::new();
        let mut x_coordinates = Vec::with_capacity(self.t);
        let mut y_coordinates = Vec::with_capacity(self.t);

        for s in shares.iter().take(self.t) {
            let identifier = s.identifier();
            if identifier == 0 {
                return Err(Error::SharingInvalidIdentifier);
            }
            if dups.contains(&(identifier as usize - 1)) {
                return Err(Error::SharingDuplicateIdentifier);
            }
            if s.is_zero() {
                return Err(Error::InvalidShare);
            }
            dups.insert(identifier as usize - 1);

            let y = f(s.value()).ok_or_else(|| Error::InvalidShare)?;
            x_coordinates.push(F::from(identifier as u64));
            y_coordinates.push(y);
        }
        let secret = Self::interpolate(&x_coordinates, &y_coordinates);
        Ok(secret)
    }

    pub(crate) fn get_shares_and_polynomial<F, R>(
        &self,
        secret: F,
        rng: &mut R,
    ) -> (Vec<Share>, Polynomial<F>)
    where
        F: PrimeField,
        R: RngCore + CryptoRng,
    {
        let polynomial = Polynomial::<F>::new(secret, rng, self.t);
        // Generate the shares of (x, y) coordinates
        // x coordinates are incremental from [1, N+1). 0 is reserved for the secret
        let mut shares = Vec::with_capacity(self.n);
        let mut x = F::one();
        for i in 0..self.n {
            let y = polynomial.evaluate(x, self.t);
            let mut t = Vec::with_capacity(1 + y.to_repr().as_ref().len());
            t.push((i + 1) as u8);
            t.extend_from_slice(y.to_repr().as_ref());

            shares.push(Share(t));

            x += F::one();
        }
        (shares, polynomial)
    }

    /// Calculate lagrange interpolation
    fn interpolate<F, S>(x_coordinates: &[F], y_coordinates: &[S]) -> S
    where
        F: PrimeField,
        S: Default + Copy + AddAssign + Mul<F, Output = S>,
    {
        let limit = x_coordinates.len();
        // Initialize to zero
        let mut result = S::default();

        for i in 0..limit {
            let mut basis = F::one();
            for j in 0..limit {
                if i == j {
                    continue;
                }

                let mut denom: F = x_coordinates[j] - x_coordinates[i];
                denom = denom.invert().unwrap();
                // x_m / (x_m - x_j) * ...
                basis *= x_coordinates[j] * denom;
            }

            result += y_coordinates[i] * basis;
        }
        result
    }

    pub(crate) fn check_params(&self) -> VsssResult<()> {
        if self.n < self.t {
            return Err(Error::SharingLimitLessThanThreshold);
        }
        if self.t < 2 {
            return Err(Error::SharingMinThreshold);
        }
        if self.n > 255 {
            return Err(Error::SharingMaxRequest);
        }
        Ok(())
    }
}
