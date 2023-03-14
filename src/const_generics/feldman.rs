/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Feldman's Verifiable secret sharing scheme.
//! (see <https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf>.
use super::{shamir::get_shares_and_polynomial, share::Share, FeldmanVerifier};
use crate::{check_params, Vec, VsssResult, EXPECT_MSG};
use core::marker::PhantomData;
use elliptic_curve::{
    ff::PrimeField,
    group::{Group, GroupEncoding, ScalarMul},
};
use rand_core::{CryptoRng, RngCore};

/// Create shares from a secret.
/// F is the prime field
/// S is the number of bytes used to represent F.
/// `generator` is the generator point to use for computing feldman verifiers.
/// If [`None`], the default generator is used.
pub fn split_secret<F, G, R, const T: usize, const N: usize, const S: usize>(
    secret: F,
    generator: Option<G>,
    rng: &mut R,
) -> VsssResult<(Vec<Share<S>, N>, FeldmanVerifier<F, G, T>)>
where
    F: PrimeField,
    G: Group + GroupEncoding + Default + ScalarMul<F>,
    R: RngCore + CryptoRng,
{
    check_params(T, N)?;

    let (shares, polynomial) = get_shares_and_polynomial::<F, R, T, N, S>(secret, rng)?;

    let g = generator.unwrap_or_else(G::generator);

    // Generate the verifiable commitments to the polynomial for the shares
    // Each share is multiple of the polynomial and the specified generator point.
    // {g^p0, g^p1, g^p2, ..., g^pn}
    let mut vs = Vec::<G, T>::new();
    for i in 0..T {
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
