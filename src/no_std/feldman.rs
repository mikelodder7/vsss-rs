/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{Error, FeldmanVerifier, Shamir, Share};
use core::marker::PhantomData;
use elliptic_curve::{
    ff::PrimeField,
    group::{Group, GroupEncoding, ScalarMul},
};
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
    pub fn split_secret<F, G, R, const S: usize>(
        secret: F,
        generator: Option<G>,
        rng: &mut R,
    ) -> Result<([Share<S>; N], FeldmanVerifier<F, G, T>), Error>
    where
        F: PrimeField,
        G: Group + GroupEncoding + Default + ScalarMul<F>,
        R: RngCore + CryptoRng,
    {
        Shamir::<T, N>::check_params(Some(secret))?;

        let (shares, polynomial) = Shamir::<T, N>::get_shares_and_polynomial(secret, rng);

        let g = generator.unwrap_or_else(G::generator);

        // Generate the verifiable commitments to the polynomial for the shares
        // Each share is multiple of the polynomial and the specified generator point.
        // {g^p0, g^p1, g^p2, ..., g^pn}
        let mut vs = [G::default(); T];
        for (i, p) in vs.iter_mut().enumerate() {
            *p = g * polynomial.coefficients[i];
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

    /// Reconstruct a secret from shares created from `split_secret`.
    /// The X-coordinates operate in `F`
    /// The Y-coordinates operate in `F`
    pub fn combine_shares<F, const S: usize>(shares: &[Share<S>]) -> Result<F, Error>
    where
        F: PrimeField,
    {
        Shamir::<T, N>::combine_shares::<F, S>(shares)
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
        Shamir::<T, N>::combine_shares_group::<F, G, S>(shares)
    }
}
