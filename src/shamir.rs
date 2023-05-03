/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Secret splitting for Shamir Secret Sharing Scheme
//! and combine methods for field and group elements
use super::*;
use elliptic_curve::{
    ff::PrimeField,
    generic_array::{GenericArray, typenum},
};
use rand_core::{CryptoRng, RngCore};

/// A Polynomial that can create secret shares
pub trait Shamir<F, I, S>: Polynomial<F>
where
    F: PrimeField,
    I: ShareIdentifier,
    S: Share<Identifier = I>,
{
    /// The set of secret shares
    type ShareSet: WriteableShareSet<I, S>;

    /// Create shares from a secret.
    /// `F` is the prime field
    fn split_secret(
        threshold: usize,
        limit: usize,
        secret: F,
        rng: impl RngCore + CryptoRng,
    ) -> VsssResult<Self::ShareSet> {
        check_params(threshold, limit)?;
        let polynomial = Self::fill(secret, rng, threshold)?;
        create_shares(&polynomial, threshold, limit)
    }
}

/// Create the shares for the specified polynomial
pub(crate) fn create_shares<F, P, I, S, SS>(
    polynomial: &P,
    threshold: usize,
    limit: usize,
) -> VsssResult<SS>
    where F: PrimeField,
          P: Polynomial<F>,
          I: ShareIdentifier,
          S: Share<Identifier = I>,
          SS: WriteableShareSet<I, S>,
{
    // Generate the shares of (x, y) coordinates
    // x coordinates are incremental from [1, N+1). 0 is reserved for the secret
    let mut shares = SS::create(limit);
    let indexer = shares.as_mut();

    let mut x = F::ONE;
    for i in 0..limit {
        let y = polynomial.evaluate(x, threshold);
        let id = I::from_field_element(x)?;
        let share = S::from_field_element(id, y)?;
        indexer[i] = share;
        x += F::ONE;
    }
    Ok(shares)
}

pub(crate) fn check_params(threshold: usize, limit: usize) -> VsssResult<()> {
    if limit < threshold {
        return Err(Error::SharingLimitLessThanThreshold);
    }
    if threshold < 2 {
        return Err(Error::SharingMinThreshold);
    }
    Ok(())
}

macro_rules! shamir_impl {
    ($($size:ident => $num:expr),+$(,)*) => {
        $(
            impl<F: PrimeField,
                 I: ShareIdentifier,
                 S: Share<Identifier = I>,
            > Shamir<F, I, S> for [F; $num] {
                type ShareSet = [S; $num];
            }

            impl<F: PrimeField,
                 I: ShareIdentifier,
                 S: Share<Identifier = I>,
            > Shamir<F, I, S> for GenericArray<F, typenum::$size> {
                type ShareSet = GenericArray<S, typenum::$size>;
            }
        )+
    }
}

shamir_impl!(
    U2 => 2,
    U3 => 3,
    U4 => 4,
    U5 => 5,
    U6 => 6,
    U7 => 7,
    U8 => 8,
    U9 => 9,
    U10 => 10,
    U11 => 11,
    U12 => 12,
    U13 => 13,
    U14 => 14,
    U15 => 15,
    U16 => 16,
    U17 => 17,
    U18 => 18,
    U19 => 19,
    U20 => 20,
    U21 => 21,
    U22 => 22,
    U23 => 23,
    U24 => 24,
    U25 => 25,
    U26 => 26,
    U27 => 27,
    U28 => 28,
    U29 => 29,
    U30 => 30,
    U31 => 31,
    U32 => 32,
);

#[cfg(any(feature = "alloc", feature = "std"))]
impl<F: PrimeField,
    I: ShareIdentifier,
    S: Share<Identifier = I>,
> Shamir<F, I, S> for Vec<F> {
    type ShareSet = Vec<S>;
}