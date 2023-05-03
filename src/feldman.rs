/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Feldman's Verifiable secret sharing scheme.
//! (see <https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf>.
use crate::*;
use elliptic_curve::group::Group;
use rand_core::{CryptoRng, RngCore};

/// A secret sharing scheme that uses feldman commitments as verifiers
pub trait Feldman<G, I, S>: Shamir<G::Scalar, I, S>
where
    G: Group,
    I: ShareIdentifier,
    S: Share<Identifier = I>,
{
    /// The verifier set
    type VerifierSet: FeldmanVerifierSet<G>;

    /// Create shares from a secret.
    /// `F` is the prime field
    /// `generator` is the generator point to use for computing feldman verifiers.
    /// If [`None`], the default generator is used.
    fn split_secret_with_verifier(
        threshold: usize,
        limit: usize,
        secret: G::Scalar,
        generator: Option<G>,
        rng: impl RngCore + CryptoRng,
    ) -> VsssResult<(Self::ShareSet, Self::VerifierSet)> {
        check_params(threshold, limit)?;
        let polynomial = Self::fill(secret, rng, threshold)?;
        let g = generator.unwrap_or_else(G::generator);
        if g.is_identity().into() {
            return Err(Error::InvalidGenerator);
        }
        let mut verifier_set = Self::VerifierSet::create(threshold, g);

        // Generate the verifiable commitments to the polynomial for the shares
        // Each share is multiple of the polynomial and the specified generator point.
        // {g^p0, g^p1, g^p2, ..., g^pn}
        let coefficients = polynomial.as_ref();
        for (i, vs) in verifier_set.verifiers_mut().iter_mut().enumerate() {
            *vs = g * coefficients[i];
        }
        let shares = create_shares(&polynomial, threshold, limit)?;
        Ok((shares, verifier_set))
    }
}
