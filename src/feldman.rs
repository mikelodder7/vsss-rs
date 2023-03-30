/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Feldman's Verifiable secret sharing scheme.
//! (see <https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf>.
use crate::*;
use core::marker::PhantomData;
use elliptic_curve::{
    ff::PrimeField,
    group::{Group, GroupEncoding, ScalarMul},
};
use rand_core::{CryptoRng, RngCore};

/// Create shares from a secret.
/// `F` is the prime field
/// `generator` is the generator point to use for computing feldman verifiers.
/// If [`None`], the default generator is used.
pub fn split_secret<F, G, R>(
    threshold: usize,
    limit: usize,
    secret: F,
    generator: Option<G>,
    rng: &mut R,
) -> VsssResult<(Vec<Share, MAX_SHARES>, FeldmanVerifier<F, G>)>
where
    F: PrimeField,
    G: Group + GroupEncoding + Default + ScalarMul<F>,
    R: RngCore + CryptoRng,
{
    check_params(threshold, limit)?;

    let (shares, polynomial) = get_shares_and_polynomial(threshold, limit, secret, rng)?;

    let g = generator.unwrap_or_else(G::generator);

    // Generate the verifiable commitments to the polynomial for the shares
    // Each share is multiple of the polynomial and the specified generator point.
    // {g^p0, g^p1, g^p2, ..., g^pn}
    let mut vs = Vec::<G, MAX_SHARES>::new();
    for i in 0..threshold {
        vs.push(g * polynomial.coefficients[i]).expect(EXPECT_MSG);
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

#[cfg(feature = "const-generics")]
/// Create shares from a secret.
/// `F` is the prime field
/// `generator` is the generator point to use for computing feldman verifiers.
/// `S` is the number of bytes used to represent `F`
/// This method allows the flexibility of known share sizes with dynamic threshold and limits
pub fn split_secret_const_generics<F, G, R, const S: usize>(
    threshold: usize,
    limit: usize,
    secret: F,
    generator: Option<G>,
    rng: &mut R,
) -> VsssResult<(
    Vec<const_generics::Share<S>, MAX_SHARES>,
    FeldmanVerifier<F, G>,
)>
where
    F: PrimeField,
    G: Group + GroupEncoding + Default + ScalarMul<F>,
    R: RngCore + CryptoRng,
{
    check_params(threshold, limit)?;

    let (shares, polynomial) =
        get_shares_and_polynomial_const_generic_share::<F, R, S>(threshold, limit, secret, rng)?;

    let g = generator.unwrap_or_else(G::generator);

    // Generate the verifiable commitments to the polynomial for the shares
    // Each share is multiple of the polynomial and the specified generator point.
    // {g^p0, g^p1, g^p2, ..., g^pn}
    let mut vs = Vec::<G, MAX_SHARES>::new();
    for i in 0..threshold {
        vs.push(g * polynomial.coefficients[i]).expect(EXPECT_MSG);
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
