/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use crate::{bytes_to_field, Error, FeldmanVerifier, PedersenVerifier, Shamir, Share};
use core::marker::PhantomData;
use ff::PrimeField;
use group::{Group, GroupEncoding, ScalarMul};
use rand_core::{CryptoRng, RngCore};

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
        F: PrimeField,
        G: Group + GroupEncoding + Default + ScalarMul<F>,
        R: RngCore + CryptoRng,
    {
        Shamir::<T, N>::check_params(Some(secret))?;

        let g = share_generator.unwrap_or_else(|| G::generator());
        let h = blind_factor_generator.unwrap_or_else(|| {
            let mut b = [0u8; S];
            rng.fill_bytes(&mut b);
            let b: F = bytes_to_field(&b[1..]).unwrap();
            G::generator() * b
        });

        let blinding = blinding.unwrap_or_else(|| {
            let mut b = [0u8; S];
            rng.fill_bytes(&mut b);
            bytes_to_field(&b[1..]).unwrap()
        });
        let (secret_shares, secret_polynomial) =
            Shamir::<T, N>::get_shares_and_polynomial(secret, rng);
        let (blind_shares, blinding_polynomial) =
            Shamir::<T, N>::get_shares_and_polynomial(blinding, rng);

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
}
