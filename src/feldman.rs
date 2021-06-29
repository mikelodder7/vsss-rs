/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{Error, FeldmanVerifier, Shamir, Share};
use core::marker::PhantomData;
use ff::PrimeField;
use group::{Group, GroupEncoding, ScalarMul};
use rand_core::{CryptoRng, RngCore};

/// Feldman's Verifiable secret sharing scheme.
/// (see <https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf>.
///
/// Feldman provides a single method to split a secret and return the verifiers and shares.
/// To combine, use Shamir::combine_shares or Shamir::combine_shares_group.
#[derive(Copy, Clone, Debug)]
pub struct Feldman<const T: usize, const N: usize>;

impl<const T: usize, const N: usize> Feldman<T, N> {
    /// Create shares from a secret.
    /// F is the prime field
    /// S is the number of bytes used to represent F.
    /// `generator` is the generator point to use for computing feldman verifiers.
    /// If [`None`], the default generator is used.
    pub fn split_secret<F, G, const S: usize>(
        secret: F,
        generator: Option<G>,
        rng: impl RngCore + CryptoRng,
    ) -> Result<([Share<S>; N], FeldmanVerifier<F, G, T>), Error>
    where
        F: PrimeField,
        G: Group + GroupEncoding + Default + ScalarMul<F>,
    {
        Shamir::<T, N>::check_params()?;

        let (shares, polynomial) = Shamir::<T, N>::get_shares_and_polynomial(secret, rng);

        let g = generator.unwrap_or_else(|| G::default());

        // Generate the verifiable commitments to the polynomial for the shares
        // Each share is multiple of the polynomial and the specified generator point.
        // {g^p0, g^p1, g^p2, ..., g^pn}
        let mut vs = [G::default(); T];
        for (i, c) in polynomial.coefficients.iter().enumerate() {
            vs[i] = g * *c;
        }

        Ok((
            shares,
            FeldmanVerifier {
                generator: g,
                commitments: vs,
                marker: PhantomData,
            },
        ))
    }
}
