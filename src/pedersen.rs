/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Pedersen's Verifiable secret sharing scheme.
//! (see <https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF>)
//!
//! Pedersen returns both Pedersen verifiers and Feldman verifiers for the purpose
//! that both may be needed for other protocols like Gennaro's DKG. Otherwise,
//! the Feldman verifiers may be discarded.
use crate::*;
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
    pub blind_shares: Vec<Share, MAX_SHARES>,
    /// The secret shares
    pub secret_shares: Vec<Share, MAX_SHARES>,
    /// The verifier for validating shares
    #[serde(bound(serialize = "PedersenVerifier<F, G>: Serialize"))]
    #[serde(bound(deserialize = "PedersenVerifier<F, G>: Deserialize<'de>"))]
    pub verifier: PedersenVerifier<F, G>,
}

/// Create shares from a secret.
/// F is the prime field
/// `blinding` is the blinding factor.
/// If [`None`], a random value is generated in F.
/// `share_generator` is the generator point to use for shares.
/// If [`None`], the default generator is used.
/// `blind_factor_generator` is the generator point to use for blinding factor shares.
/// If [`None`], a random generator is used
pub fn split_secret<F, G, R>(
    threshold: usize,
    limit: usize,
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
    check_params(threshold, limit)?;

    let mut crng = ChaChaRng::from_rng(rng).map_err(|_| Error::NotImplemented)?;

    let g = share_generator.unwrap_or_else(G::generator);
    let t = F::random(&mut crng);
    let h = blind_factor_generator.unwrap_or_else(|| G::generator() * t);

    let blinding = blinding.unwrap_or_else(|| F::random(&mut crng));
    let (secret_shares, secret_polynomial) =
        get_shares_and_polynomial(threshold, limit, secret, &mut crng)?;
    let (blind_shares, blinding_polynomial) =
        get_shares_and_polynomial(threshold, limit, blinding, &mut crng)?;

    let mut feldman_commitments = Vec::new();
    let mut pedersen_commitments = Vec::new();
    // {(g^p0 h^r0), (g^p1, h^r1), ..., (g^pn, h^rn)}
    for i in 0..threshold {
        let g_i = g * secret_polynomial.coefficients[i];
        let h_i = h * blinding_polynomial.coefficients[i];
        feldman_commitments.push(g_i).expect(EXPECT_MSG);
        pedersen_commitments.push(g_i + h_i).expect(EXPECT_MSG);
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
