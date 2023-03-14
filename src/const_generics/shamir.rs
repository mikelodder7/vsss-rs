/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Secret splitting for Shamir Secret Sharing Scheme
//! and combine methods for field and group elements

use super::{polynomial::Polynomial, share::Share};
use crate::{
    bytes_to_field, bytes_to_group, check_params, interpolate, Error, Vec, VsssResult, EXPECT_MSG,
};
use core::ops::{AddAssign, Mul};
use elliptic_curve::{
    ff::PrimeField,
    group::{Group, GroupEncoding, ScalarMul},
};
use rand_core::{CryptoRng, RngCore};

/// Create shares from a secret.
/// F is the prime field
/// T is the threshold
/// N is the number of shares
/// S is the number of bytes in the share
pub fn split_secret<F, R, const T: usize, const N: usize, const S: usize>(
    secret: F,
    rng: &mut R,
) -> VsssResult<Vec<Share<S>, N>>
where
    F: PrimeField,
    R: RngCore + CryptoRng,
{
    check_params(T, N)?;

    let (shares, _) = get_shares_and_polynomial::<F, R, T, N, S>(secret, rng)?;
    Ok(shares)
}

/// Reconstruct a secret from shares created from `split_secret`.
/// The X-coordinates operate in `F`
/// The Y-coordinates operate in `F`
pub fn combine_shares<F, const S: usize>(shares: &[Share<S>]) -> VsssResult<F>
where
    F: PrimeField,
{
    combine::<F, F, S>(shares, bytes_to_field)
}

/// Reconstruct a secret from shares created from `split_secret`.
/// The X-coordinates operate in `F`
/// The Y-coordinates operate in `G`
///
/// Exists to support operations like threshold BLS where the shares
/// operate in `F` but the partial signatures operate in `G`.
pub fn combine_shares_group<F, G, const S: usize>(shares: &[Share<S>]) -> VsssResult<G>
where
    F: PrimeField,
    G: Group + GroupEncoding + ScalarMul<F> + Default,
{
    combine::<F, G, S>(shares, bytes_to_group)
}

fn combine<F, S, const SS: usize>(shares: &[Share<SS>], f: fn(&[u8]) -> Option<S>) -> VsssResult<S>
where
    F: PrimeField,
    S: Default + Copy + AddAssign + Mul<F, Output = S>,
{
    if shares.len() < 2 {
        return Err(Error::SharingMinThreshold);
    }

    let mut dups = [false; SS];
    let mut x_coordinates = Vec::<F, SS>::new();
    let mut y_coordinates = Vec::<S, SS>::new();

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

pub(crate) fn get_shares_and_polynomial<F, R, const T: usize, const N: usize, const S: usize>(
    secret: F,
    rng: &mut R,
) -> VsssResult<(Vec<Share<S>, N>, Polynomial<F, T>)>
where
    F: PrimeField,
    R: RngCore + CryptoRng,
{
    let polynomial = Polynomial::<F, T>::new(secret, rng);
    // Generate the shares of (x, y) coordinates
    // x coordinates are incremental from [1, N+1). 0 is reserved for the secret
    let mut shares = Vec::<Share<S>, N>::new();
    let mut x = F::one();
    for i in 0..N {
        let y = polynomial.evaluate(x);
        shares
            .push(Share::<S>::from_field_element((i + 1) as u8, y)?)
            .expect(EXPECT_MSG);
        x += F::one();
    }
    Ok((shares, polynomial))
}
