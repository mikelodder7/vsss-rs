/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use super::super::*;
use super::FeldmanVerifier;
use crate::{util::bytes_to_field, Share};
use elliptic_curve::{
    ff::PrimeField,
    group::{Group, GroupEncoding, ScalarMul},
};
use serde::{Deserialize, Serialize};

/// A Pedersen verifier is used to provide integrity checking of shamir shares
/// `T` commitments are made to be used for verification.
#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct PedersenVerifier<F: PrimeField, G: Group + GroupEncoding + ScalarMul<F>, const T: usize>
{
    /// The generator for the blinding factor
    #[serde(
        serialize_with = "serialize_group",
        deserialize_with = "deserialize_group"
    )]
    pub generator: G,
    /// The feldman verifier containing the share generator and commitments
    #[serde(bound(serialize = "FeldmanVerifier<F, G, T>: Serialize"))]
    #[serde(bound(deserialize = "FeldmanVerifier<F, G, T>: Deserialize<'de>"))]
    pub feldman_verifier: FeldmanVerifier<F, G, T>,
    /// The blinded commitments to the polynomial
    #[serde(
        serialize_with = "serialize_group_vec",
        deserialize_with = "deserialize_group_vec"
    )]
    pub commitments: [G; T],
}

impl<F: PrimeField, G: Group + GroupEncoding + ScalarMul<F>, const T: usize>
    PedersenVerifier<F, G, T>
{
    /// Check whether the share is valid according this verifier set
    pub fn verify<const S: usize>(&self, share: &Share<S>, blind_share: &Share<S>) -> bool {
        let secret = bytes_to_field::<F>(share.value());
        let blinding = bytes_to_field::<F>(blind_share.value());
        if secret.is_none() || blinding.is_none() {
            return false;
        }

        let secret = secret.unwrap();
        let blinding = blinding.unwrap();

        let x = F::from(share.identifier() as u64);
        let mut i = F::one();

        // FUTURE: execute this sum of products
        // c_0 * c_1^i * c_2^{i^2} ... c_t^{i^t}
        // as a constant time operation using <https://cr.yp.to/papers/pippenger.pdf>
        // or Guide to Elliptic Curve Cryptography book,
        // "Algorithm 3.48 Simultaneous multiple point multiplication"
        // without precomputing the addition but still reduces doublings

        // c_0
        let mut rhs = self.commitments[0];
        for v in &self.commitments[1..] {
            i *= x;

            // c_0 * c_1^i * c_2^{i^2} ... c_t^{i^t}
            rhs += *v * i;
        }

        let g: G = (-self.feldman_verifier.generator) * secret;
        let h: G = (-self.generator) * blinding;

        let res: G = rhs + g + h;

        res.is_identity().unwrap_u8() == 1
    }
}
