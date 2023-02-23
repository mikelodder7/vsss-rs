/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use super::{
    deserialize_scalar, serialize_scalar, FeldmanVerifier, PedersenVerifier, Shamir, Share,
};
use crate::lib::*;
use crate::Error;
use core::marker::PhantomData;
use elliptic_curve::{
    ff::PrimeField,
    group::{Group, GroupEncoding, ScalarMul},
};
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};

/// Result from calling Pedersen::split_secret
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PedersenResult<F: PrimeField, G: Group + GroupEncoding + ScalarMul<F>> {
    /// The random blinding factor randomly generated or supplied
    #[serde(
        serialize_with = "serialize_scalar",
        deserialize_with = "deserialize_scalar"
    )]
    pub blinding: F,
    /// The blinding shares
    pub blind_shares: Vec<Share>,
    /// The secret shares
    pub secret_shares: Vec<Share>,
    /// The verifier for validating shares
    #[serde(bound(serialize = "PedersenVerifier<F, G>: Serialize"))]
    #[serde(bound(deserialize = "PedersenVerifier<F, G>: Deserialize<'de>"))]
    pub verifier: PedersenVerifier<F, G>,
}

/// Pedersen's Verifiable secret sharing scheme.
/// (see <https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF>)
///
/// Pedersen provides a single method to split a secret and return the verifiers and shares.
/// To combine, use Shamir::combine_shares or Shamir::combine_shares_group.
///
/// Pedersen returns both Pedersen verifiers and Feldman verifiers for the purpose
/// that both may be needed for other protocols like Gennaro's DKG. Otherwise,
/// the Feldman verifiers may be discarded.
#[derive(Copy, Clone, Debug)]
pub struct Pedersen {
    /// The threshold necessary for combine
    pub t: usize,
    /// The number of shares to allocate
    pub n: usize,
}

impl Pedersen {
    /// Create shares from a secret.
    /// F is the prime field
    /// S is the number of bytes used to represent F.
    /// `blinding` is the blinding factor.
    /// If [`None`], a random value is generated in F.
    /// `share_generator` is the generator point to use for shares.
    /// If [`None`], the default generator is used.
    /// `blind_factor_generator` is the generator point to use for blinding factor shares.
    /// If [`None`], a random generator is used
    pub fn split_secret<F, G, R>(
        &self,
        secret: F,
        blinding: Option<F>,
        share_generator: Option<G>,
        blind_factor_generator: Option<G>,
        rng: &mut R,
    ) -> Result<PedersenResult<F, G>, Error>
    where
        F: PrimeField,
        G: Group + GroupEncoding + Default + ScalarMul<F>,
        R: RngCore + CryptoRng,
    {
        let shamir = Shamir {
            t: self.t,
            n: self.n,
        };
        shamir.check_params(Some(secret))?;

        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let mut crng = ChaChaRng::from_seed(seed);

        let g = share_generator.unwrap_or_else(G::generator);
        let t = F::random(&mut crng);
        let h = blind_factor_generator.unwrap_or_else(|| G::generator() * t);

        let blinding = blinding.unwrap_or_else(|| F::random(&mut crng));
        let (secret_shares, secret_polynomial) =
            shamir.get_shares_and_polynomial(secret, &mut crng);
        let (blind_shares, blinding_polynomial) =
            shamir.get_shares_and_polynomial(blinding, &mut crng);

        let mut feldman_commitments = Vec::with_capacity(self.t);
        let mut pedersen_commitments = Vec::with_capacity(self.t);
        // {(g^p0 h^r0), (g^p1, h^r1), ..., (g^pn, h^rn)}
        for i in 0..self.t {
            let g_i = g * secret_polynomial.coefficients[i];
            let h_i = h * blinding_polynomial.coefficients[i];
            feldman_commitments.push(g_i);
            pedersen_commitments.push(g_i + h_i);
        }
        Ok(PedersenResult {
            blinding,
            blind_shares,
            secret_shares,
            verifier: PedersenVerifier {
                generator: h,
                commitments: pedersen_commitments,
                feldman_verifier: FeldmanVerifier {
                    generator: g,
                    commitments: feldman_commitments,
                    marker: PhantomData,
                },
            },
        })
    }

    /// Reconstruct a secret from shares created from `split_secret`.
    /// The X-coordinates operate in `F`
    /// The Y-coordinates operate in `F`
    pub fn combine_shares<F>(&self, shares: &[Share]) -> Result<F, Error>
    where
        F: PrimeField,
    {
        Shamir {
            t: self.t,
            n: self.n,
        }
        .combine_shares::<F>(shares)
    }

    /// Reconstruct a secret from shares created from `split_secret`.
    /// The X-coordinates operate in `F`
    /// The Y-coordinates operate in `G`
    ///
    /// Exists to support operations like threshold BLS where the shares
    /// operate in `F` but the partial signatures operate in `G`.
    pub fn combine_shares_group<F, G>(&self, shares: &[Share]) -> Result<G, Error>
    where
        F: PrimeField,
        G: Group + GroupEncoding + ScalarMul<F> + Default,
    {
        Shamir {
            t: self.t,
            n: self.n,
        }
        .combine_shares_group::<F, G>(shares)
    }
}
