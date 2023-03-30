/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Secret splitting for Shamir Secret Sharing Scheme
//! and combine methods for field and group elements
use super::*;
use core::ops::{AddAssign, Mul};
use elliptic_curve::{
    ff::PrimeField,
    group::{Group, GroupEncoding, ScalarMul},
};
use rand_core::{CryptoRng, RngCore};

/// Create shares from a secret.
/// F is the prime field
pub fn split_secret<F, R>(
    threshold: usize,
    limit: usize,
    secret: F,
    rng: &mut R,
) -> VsssResult<Vec<Share, MAX_SHARES>>
where
    F: PrimeField,
    R: RngCore + CryptoRng,
{
    check_params(threshold, limit)?;

    let (shares, _) = get_shares_and_polynomial(threshold, limit, secret, rng)?;
    Ok(shares)
}

#[cfg(feature = "const-generics")]
/// Create shares from a secret.
/// F is the prime field
/// S is the number of bytes used to represent F
/// This method allows the flexibility of known share sizes with dynamic threshold and limits
pub fn split_secret_const_generics<F, R, const S: usize>(
    threshold: usize,
    limit: usize,
    secret: F,
    rng: &mut R,
) -> VsssResult<Vec<const_generics::Share<S>, MAX_SHARES>>
where
    F: PrimeField,
    R: RngCore + CryptoRng,
{
    check_params(threshold, limit)?;

    let (shares, _) =
        get_shares_and_polynomial_const_generic_share::<F, R, S>(threshold, limit, secret, rng)?;
    Ok(shares)
}

/// Reconstruct a secret from shares created from `split_secret`.
/// The X-coordinates operate in `F`
/// The Y-coordinates operate in `F`
pub fn combine_shares<F>(shares: &[Share]) -> VsssResult<F>
where
    F: PrimeField,
{
    combine::<F, F>(shares, bytes_to_field)
}

#[cfg(feature = "const-generics")]
/// Reconstruct a secret from shares created from `split_secret`.
/// The X-coordinates operate in `F`
/// The Y-coordinates operate in `F`
/// `S` is the number of bytes to represent `F`.
pub fn combine_shares_const_generics<F, const S: usize>(
    shares: &[const_generics::Share<S>],
) -> VsssResult<F>
where
    F: PrimeField,
{
    combine_const_generics::<F, F, S>(shares, bytes_to_field)
}

/// Reconstruct a secret from shares created from `split_secret`.
/// The X-coordinates operate in `F`
/// The Y-coordinates operate in `G`
///
/// Exists to support operations like threshold BLS where the shares
/// operate in `F` but the partial signatures operate in `G`.
///
pub fn combine_shares_group<F, G>(shares: &[Share]) -> VsssResult<G>
where
    F: PrimeField,
    G: Group + GroupEncoding + ScalarMul<F> + Default,
{
    combine::<F, G>(shares, bytes_to_group)
}

#[cfg(feature = "const-generics")]
/// Reconstruct a secret from shares created from `split_secret`.
/// The X-coordinates operate in `F`
/// The Y-coordinates operate in `G`
///
/// Exists to support operations like threshold BLS where the shares
/// operate in `F` but the partial signatures operate in `G`.
/// `S` is the number of bytes to represent `F`.
pub fn combine_shares_group_const_generics<F, G, const S: usize>(
    shares: &[const_generics::Share<S>],
) -> VsssResult<G>
where
    F: PrimeField,
    G: Group + GroupEncoding + ScalarMul<F> + Default,
{
    combine_const_generics::<F, G, S>(shares, bytes_to_group)
}

fn combine<F, S>(shares: &[Share], f: fn(&[u8]) -> Option<S>) -> VsssResult<S>
where
    F: PrimeField,
    S: Default + Copy + AddAssign + Mul<F, Output = S>,
{
    if shares.len() < 2 {
        return Err(Error::SharingMinThreshold);
    }

    let mut dups = [false; MAX_SHARES];
    let mut x_coordinates = Vec::<F, MAX_SHARES>::new();
    let mut y_coordinates = Vec::<S, MAX_SHARES>::new();

    for s in shares {
        let identifier = s.identifier();
        if identifier == 0 {
            return Err(Error::SharingInvalidIdentifier);
        }
        if dups[identifier as usize - 1] {
            return Err(Error::SharingDuplicateIdentifier);
        }
        if s.is_zero().into() {
            return Err(Error::InvalidShare);
        }
        dups[identifier as usize - 1] = true;

        let y = f(s.value()).ok_or(Error::InvalidShare)?;
        x_coordinates
            .push(F::from(identifier as u64))
            .expect(EXPECT_MSG);
        y_coordinates
            .push(y)
            .map_err(|_| Error::SharingMaxRequest)?;
    }
    let secret = interpolate(&x_coordinates, &y_coordinates);
    Ok(secret)
}

#[cfg(feature = "const-generics")]
fn combine_const_generics<F, S, const N: usize>(
    shares: &[const_generics::Share<N>],
    f: fn(&[u8]) -> Option<S>,
) -> VsssResult<S>
where
    F: PrimeField,
    S: Default + Copy + AddAssign + Mul<F, Output = S>,
{
    if shares.len() < 2 {
        return Err(Error::SharingMinThreshold);
    }

    let mut dups = [false; MAX_SHARES];
    let mut x_coordinates = Vec::<F, MAX_SHARES>::new();
    let mut y_coordinates = Vec::<S, MAX_SHARES>::new();

    for s in shares {
        let identifier = s.identifier();
        if identifier == 0 {
            return Err(Error::SharingInvalidIdentifier);
        }
        if dups[identifier as usize - 1] {
            return Err(Error::SharingDuplicateIdentifier);
        }
        if s.is_zero().into() {
            return Err(Error::InvalidShare);
        }
        dups[identifier as usize - 1] = true;

        let y = f(s.value()).ok_or(Error::InvalidShare)?;
        x_coordinates
            .push(F::from(identifier as u64))
            .expect(EXPECT_MSG);
        y_coordinates
            .push(y)
            .map_err(|_| Error::SharingMaxRequest)?;
    }
    let secret = interpolate(&x_coordinates, &y_coordinates);
    Ok(secret)
}

pub(crate) fn get_shares_and_polynomial<F, R>(
    threshold: usize,
    limit: usize,
    secret: F,
    rng: &mut R,
) -> VsssResult<(Vec<Share, MAX_SHARES>, Polynomial<F>)>
where
    F: PrimeField,
    R: RngCore + CryptoRng,
{
    let polynomial = Polynomial::<F>::new(secret, rng, threshold);
    // Generate the shares of (x, y) coordinates
    // x coordinates are incremental from [1, N+1). 0 is reserved for the secret
    let mut shares = Vec::new();
    let mut x = F::ONE;
    for i in 0..limit {
        let y = polynomial.evaluate(x, threshold);
        shares
            .push(Share::from_field_element((i + 1) as u8, y)?)
            .expect(EXPECT_MSG);
        x += F::ONE;
    }
    Ok((shares, polynomial))
}

#[cfg(feature = "const-generics")]
pub(crate) fn get_shares_and_polynomial_const_generic_share<F, R, const S: usize>(
    threshold: usize,
    limit: usize,
    secret: F,
    rng: &mut R,
) -> VsssResult<(Vec<const_generics::Share<S>, MAX_SHARES>, Polynomial<F>)>
where
    F: PrimeField,
    R: RngCore + CryptoRng,
{
    let polynomial = Polynomial::<F>::new(secret, rng, threshold);
    // Generate the shares of (x, y) coordinates
    // x coordinates are incremental from [1, N+1). 0 is reserved for the secret
    let mut shares = Vec::new();
    let mut x = F::ONE;
    for i in 0..limit {
        let y = polynomial.evaluate(x, threshold);
        shares
            .push(const_generics::Share::<S>::from_field_element(
                (i + 1) as u8,
                y,
            )?)
            .expect(EXPECT_MSG);
        x += F::ONE;
    }
    Ok((shares, polynomial))
}

/// Calculate lagrange interpolation
pub(crate) fn interpolate<F, S>(x_coordinates: &[F], y_coordinates: &[S]) -> S
where
    F: PrimeField,
    S: Default + Copy + AddAssign + Mul<F, Output = S>,
{
    let limit = x_coordinates.len();
    // Initialize to zero
    let mut result = S::default();

    for i in 0..limit {
        let mut basis = F::ONE;
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

pub(crate) fn check_params(threshold: usize, limit: usize) -> VsssResult<()> {
    if limit < threshold {
        return Err(Error::SharingLimitLessThanThreshold);
    }
    if threshold < 2 {
        return Err(Error::SharingMinThreshold);
    }
    if limit > MAX_SHARES {
        return Err(Error::SharingMaxRequest);
    }
    Ok(())
}
