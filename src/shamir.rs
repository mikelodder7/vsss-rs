/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::util::bytes_to_group;
use crate::{bytes_to_field, Error, Polynomial, Share};
use core::{
    mem::MaybeUninit,
    ops::{AddAssign, Mul},
};
use ff::PrimeField;
use group::{Group, GroupEncoding, ScalarMul};
use rand_core::{CryptoRng, RngCore};

/// Shamir's simple secret sharing scheme
/// T is the threshold
/// N is the total number of shares
#[derive(Copy, Clone, Debug)]
pub struct Shamir<const T: usize, const N: usize>;

impl<const T: usize, const N: usize> Shamir<T, N> {
    /// Create shares from a secret.
    /// F is the prime field
    /// S is the number of bytes used to represent F
    pub fn split_secret<F, R, const S: usize>(
        secret: F,
        rng: &mut R,
    ) -> Result<[Share<S>; N], Error>
    where
        F: PrimeField,
        R: RngCore + CryptoRng,
    {
        Self::check_params(Some(secret))?;

        let (shares, _) = Self::get_shares_and_polynomial(secret, rng);
        Ok(shares)
    }

    /// Reconstruct a secret from shares created from `split_secret`.
    /// The X-coordinates operate in `F`
    /// The Y-coordinates operate in `F`
    pub fn combine_shares<F, const S: usize>(shares: &[Share<S>]) -> Result<F, Error>
    where
        F: PrimeField,
    {
        Self::combine::<F, F, S>(shares, bytes_to_field)
    }

    /// Reconstruct a secret from shares created from `split_secret`.
    /// The X-coordinates operate in `F`
    /// The Y-coordinates operate in `G`
    ///
    /// Exists to support operations like threshold BLS where the shares
    /// operate in `F` but the partial signatures operate in `G`.
    pub fn combine_shares_group<F, G, const S: usize>(shares: &[Share<S>]) -> Result<G, Error>
    where
        F: PrimeField,
        G: Group + GroupEncoding + ScalarMul<F> + Default,
    {
        Self::combine::<F, G, S>(shares, bytes_to_group)
    }

    fn combine<F, S, const SS: usize>(
        shares: &[Share<SS>],
        f: fn(&[u8]) -> Option<S>,
    ) -> Result<S, Error>
    where
        F: PrimeField,
        S: Default + Copy + AddAssign + Mul<F, Output = S>,
    {
        Self::check_params::<F>(None)?;

        if shares.len() < T {
            return Err(Error::SharingMinThreshold);
        }
        let mut dups = [false; N];
        let mut x_coordinates = [F::default(); T];
        let mut y_coordinates = [S::default(); T];

        for i in 0..T {
            let identifier = shares[i].identifier();
            if identifier == 0 {
                return Err(Error::SharingInvalidIdentifier);
            }
            if dups[identifier as usize - 1] {
                return Err(Error::SharingDuplicateIdentifier);
            }
            if shares[i].is_zero() {
                return Err(Error::InvalidShare);
            }
            dups[identifier as usize - 1] = true;

            let y = f(shares[i].value());
            if y.is_none() {
                return Err(Error::InvalidShare);
            }
            x_coordinates[i] = F::from(identifier as u64);
            y_coordinates[i] = y.unwrap();
        }
        let secret = Self::interpolate(&x_coordinates, &y_coordinates);
        Ok(secret)
    }

    pub(crate) fn get_shares_and_polynomial<F, R, const S: usize>(
        secret: F,
        rng: &mut R,
    ) -> ([Share<S>; N], Polynomial<F, T>)
    where
        F: PrimeField,
        R: RngCore + CryptoRng,
    {
        let polynomial = Polynomial::<F, T>::new(secret, rng);
        // Generate the shares of (x, y) coordinates
        // x coordinates are incremental from [1, N+1). 0 is reserved for the secret
        let mut shares: MaybeUninit<[Share<S>; N]> = MaybeUninit::uninit();
        let mut x = F::one();
        for i in 0..N {
            let y = polynomial.evaluate(x);
            let mut t = [0u8; S];
            t[0] = (i + 1) as u8;
            t[1..].copy_from_slice(y.to_repr().as_ref());

            let p = (shares.as_mut_ptr() as *mut Share<S>).wrapping_add(i);
            unsafe { core::ptr::write(p, Share(t)) };

            x += F::one();
        }
        let shares = unsafe { shares.assume_init() };
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

    pub(crate) fn check_params<F>(secret: Option<F>) -> Result<(), Error>
    where
        F: PrimeField,
    {
        if N < T {
            return Err(Error::SharingLimitLessThanThreshold);
        }
        if T < 2 {
            return Err(Error::SharingMinThreshold);
        }
        if secret.is_some() && secret.unwrap().is_zero() {
            return Err(Error::InvalidShare);
        }
        Ok(())
    }
}
