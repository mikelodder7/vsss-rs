/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Secret splitting for Shamir Secret Sharing Scheme
//! and combine methods for field and group elements
use super::*;
use elliptic_curve::{
    ff::PrimeField,
    generic_array::{typenum, GenericArray},
};
use rand_core::{CryptoRng, RngCore};

/// A Polynomial that can create secret shares
pub trait Shamir<F, B, I, S>
where
    F: PrimeField,
    B: AsRef<[u8]> + AsMut<[u8]>,
    I: ShareIdentifier<ByteRepr = B>,
    S: Share<Identifier = I>,
{
    /// The polynomial for the coefficients
    type InnerPolynomial: Polynomial<F>;
    /// The set of secret shares
    type ShareSet: WriteableShareSet<B, I, S>;

    /// Create shares from a secret.
    /// `F` is the prime field
    fn split_secret(
        threshold: usize,
        limit: usize,
        secret: F,
        rng: impl RngCore + CryptoRng,
    ) -> VsssResult<Self::ShareSet> {
        check_params(threshold, limit)?;
        let mut polynomial = Self::InnerPolynomial::create(threshold);
        polynomial.fill(secret, rng, threshold)?;
        let ss = create_shares(&polynomial, threshold, limit)?;
        polynomial
            .coefficients_mut()
            .iter_mut()
            .for_each(|c| *c = F::ZERO);
        Ok(ss)
    }

    /// Create a share generator from a secret.
    fn split_secret_generator(
        threshold: usize,
        secret: F,
        rng: impl RngCore + CryptoRng,
    ) -> VsssResult<SecretShareGenerator<F, Self::InnerPolynomial, I, S>> {
        if threshold < 2 {
            return Err(Error::SharingMinThreshold);
        }
        let mut polynomial = Self::InnerPolynomial::create(threshold);
        polynomial.fill(secret, rng, threshold)?;
        Ok(SecretShareGenerator::new(threshold, polynomial))
    }
}

/// Create the shares for the specified polynomial
pub(crate) fn create_shares<F, P, B, I, S, SS>(
    polynomial: &P,
    threshold: usize,
    limit: usize,
) -> VsssResult<SS>
where
    F: PrimeField,
    P: Polynomial<F>,
    B: AsRef<[u8]> + AsMut<[u8]>,
    I: ShareIdentifier<ByteRepr = B>,
    S: Share<Identifier = I>,
    SS: WriteableShareSet<B, I, S>,
{
    // Generate the shares of (x, y) coordinates
    // x coordinates are incremental from [1, N+1). 0 is reserved for the secret
    let mut shares = SS::create(limit);
    let indexer = shares.as_mut();

    let mut x = F::ONE;
    for i in indexer.iter_mut().take(limit) {
        let y = polynomial.evaluate(x, threshold);
        let id = I::from_field_element(x)?;
        let share = S::from_field_element(id, y)?;
        *i = share;
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
                 B: AsRef<[u8]> + AsMut<[u8]>,
                 I: ShareIdentifier<ByteRepr = B>,
                 S: Share<Identifier = I>,
            > Shamir<F, B, I, S> for [S; $num] {
                type InnerPolynomial = [F; $num];
                type ShareSet = [S; $num];
            }

            impl<F: PrimeField,
                 B: AsRef<[u8]> + AsMut<[u8]>,
                 I: ShareIdentifier<ByteRepr = B>,
                 S: Share<Identifier = I>,
            > Shamir<F, B, I, S> for GenericArray<F, typenum::$size> {
                type InnerPolynomial = GenericArray<F, typenum::$size>;
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
    U33 => 33, U34 => 34, U35 => 35, U36 => 36, U37 => 37,
    U38 => 38, U39 => 39, U40 => 40, U41 => 41, U42 => 42, U43 => 43, U44 => 44,
    U45 => 45, U46 => 46, U47 => 47, U48 => 48, U49 => 49, U50 => 50, U51 => 51,
    U52 => 52, U53 => 53, U54 => 54, U55 => 55, U56 => 56, U57 => 57, U58 => 58,
    U59 => 59, U60 => 60, U61 => 61, U62 => 62, U63 => 63, U64 => 64,
);

#[cfg(any(feature = "alloc", feature = "std"))]
impl<
        F: PrimeField,
        B: AsRef<[u8]> + AsMut<[u8]>,
        I: ShareIdentifier<ByteRepr = B>,
        S: Share<Identifier = I>,
    > Shamir<F, B, I, S> for Vec<F>
{
    type InnerPolynomial = Vec<F>;
    type ShareSet = Vec<S>;
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret.
pub fn split_secret<
    F: PrimeField,
    B: AsRef<[u8]> + AsMut<[u8]>,
    I: ShareIdentifier<ByteRepr = B>,
    S: Share<Identifier = I>,
>(
    threshold: usize,
    limit: usize,
    secret: F,
    rng: impl RngCore + CryptoRng,
) -> VsssResult<Vec<S>> {
    StdVsssShamir::split_secret(threshold, limit, secret, rng)
}

#[cfg(any(feature = "alloc", feature = "std"))]
struct StdVsssShamir<
    F: PrimeField,
    B: AsRef<[u8]> + AsMut<[u8]>,
    I: ShareIdentifier<ByteRepr = B>,
    S: Share<Identifier = I>,
> {
    _marker: (core::marker::PhantomData<F>, core::marker::PhantomData<S>),
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<
        F: PrimeField,
        B: AsRef<[u8]> + AsMut<[u8]>,
        I: ShareIdentifier<ByteRepr = B>,
        S: Share<Identifier = I>,
    > Shamir<F, B, I, S> for StdVsssShamir<F, B, I, S>
{
    type InnerPolynomial = Vec<F>;
    type ShareSet = Vec<S>;
}
