// Copyright Michael Lodder. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use core::marker::PhantomData;

use ff::PrimeField;
use group::{Group, GroupEncoding, ScalarMul};
use rand_core::{CryptoRng, RngCore};

use super::{FeldmanVerifier, Shamir, Share};
use crate::{lib::Vec, Error};

/// Feldman's Verifiable secret sharing scheme.
/// (see <https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf>.
///
/// Feldman provides a single method to split a secret and return the verifiers and shares.
/// To combine, use Shamir::combine_shares or Shamir::combine_shares_group.
#[derive(Copy, Clone, Debug)]
pub struct Feldman {
    /// The threshold necessary for combine
    pub t: usize,
    /// The number of shares to allocate
    pub n: usize,
}

impl Feldman {
    /// Create shares from a secret.
    /// F is the prime field
    /// S is the number of bytes used to represent F.
    /// `generator` is the generator point to use for computing feldman verifiers.
    /// If [`None`], the default generator is used.
    pub fn split_secret<F, G, R>(
        &self,
        secret: F,
        generator: Option<G>,
        rng: &mut R,
    ) -> Result<(Vec<Share>, FeldmanVerifier<F, G>), Error>
    where
        F: PrimeField,
        G: Group + GroupEncoding + Default + ScalarMul<F>,
        R: RngCore + CryptoRng,
    {
        let shamir = Shamir { t: self.t, n: self.n };
        shamir.check_params(Some(secret))?;

        let (shares, polynomial) = shamir.get_shares_and_polynomial(secret, rng);

        let g = generator.unwrap_or_else(G::generator);

        // Generate the verifiable commitments to the polynomial for the shares
        // Each share is multiple of the polynomial and the specified generator point.
        // {g^p0, g^p1, g^p2, ..., g^pn}
        let mut vs = Vec::with_capacity(self.t);
        for i in 0..self.t {
            vs.push(g * polynomial.coefficients[i]);
        }

        Ok((shares, FeldmanVerifier {
            generator: g,
            commitments: vs,
            marker: PhantomData,
        }))
    }

    /// Reconstruct a secret from shares created from `split_secret`.
    /// The X-coordinates operate in `F`
    /// The Y-coordinates operate in `F`
    pub fn combine_shares<F>(&self, shares: &[Share]) -> Result<F, Error>
    where F: PrimeField {
        Shamir { t: self.t, n: self.n }.combine_shares::<F>(shares)
    }

    /// Reconstruct a secret from shares created from `split_secret`.
    /// The X-coordinates operate in `F`
    /// The Y-coordinates operate in `G`
    ///
    /// Exists to support operations like threshold BLS where the shares
    /// operate in `F` but the partial signatures operate in `G`.
    pub fn combine_shares_group<F, G, const S: usize>(&self, shares: &[Share]) -> Result<G, Error>
    where
        F: PrimeField,
        G: Group + GroupEncoding + ScalarMul<F> + Default,
    {
        Shamir { t: self.t, n: self.n }.combine_shares_group::<F, G>(shares)
    }
}
