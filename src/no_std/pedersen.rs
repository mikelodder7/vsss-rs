// Copyright Michael Lodder. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use core::marker::PhantomData;

use ff::PrimeField;
use group::{Group, GroupEncoding, ScalarMul};
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use zeroize::Zeroize;

use super::share::Share;
use crate::{Error, FeldmanVerifier, PedersenVerifier, Shamir};

/// Result from calling Pedersen::split_secret
#[derive(Clone, Debug)]
pub struct PedersenResult<
    F: PrimeField,
    G: Group + GroupEncoding + ScalarMul<F>,
    const S: usize,
    const T: usize,
    const N: usize,
> {
    /// The random blinding factor randomly generated or supplied
    pub blinding: F,
    /// The blinding shares
    pub blind_shares: [Share<S>; N],
    /// The secret shares
    pub secret_shares: [Share<S>; N],
    /// The verifier for validating shares
    pub verifier: PedersenVerifier<F, G, T>,
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
pub struct Pedersen<const T: usize, const N: usize>;

impl<const T: usize, const N: usize> Pedersen<T, N> {
    /// Create shares from a secret.
    /// F is the prime field
    /// S is the number of bytes used to represent F.
    /// `blinding` is the blinding factor.
    /// If [`None`], a random value is generated in F.
    /// `share_generator` is the generator point to use for shares.
    /// If [`None`], the default generator is used.
    /// `blind_factor_generator` is the generator point to use for blinding factor shares.
    /// If [`None`], a random generator is used
    pub fn split_secret<F, G, R, const S: usize>(
        secret: F,
        blinding: Option<F>,
        share_generator: Option<G>,
        blind_factor_generator: Option<G>,
        rng: &mut R,
    ) -> Result<PedersenResult<F, G, S, T, N>, Error>
    where
        F: PrimeField + Zeroize,
        G: Group + GroupEncoding + Default + ScalarMul<F>,
        R: RngCore + CryptoRng,
    {
        Shamir::<T, N>::check_params(Some(secret))?;

        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let mut crng = ChaChaRng::from_seed(seed);

        let g = share_generator.unwrap_or_else(G::generator);
        let mut t = F::random(&mut crng);
        let h = blind_factor_generator.unwrap_or_else(|| G::generator() * t);
        t.zeroize();

        let blinding = blinding.unwrap_or_else(|| F::random(&mut crng));
        let (secret_shares, secret_polynomial) = Shamir::<T, N>::get_shares_and_polynomial(secret, &mut crng);
        let (blind_shares, blinding_polynomial) = Shamir::<T, N>::get_shares_and_polynomial(blinding, &mut crng);

        let mut feldman_commitments = [G::default(); T];
        let mut pedersen_commitments = [G::default(); T];
        // {(g^p0 h^r0), (g^p1, h^r1), ..., (g^pn, h^rn)}
        for i in 0..T {
            let g_i = g * secret_polynomial.coefficients[i];
            let h_i = h * blinding_polynomial.coefficients[i];
            feldman_commitments[i] = g_i;
            pedersen_commitments[i] = g_i + h_i;
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
    pub fn combine_shares<F, const S: usize>(shares: &[Share<S>]) -> Result<F, Error>
    where F: PrimeField {
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
