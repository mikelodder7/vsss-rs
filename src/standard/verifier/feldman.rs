/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use super::super::*;
use crate::{lib::*, util::bytes_to_field};
use core::marker::PhantomData;
use elliptic_curve::{
    ff::PrimeField,
    group::{Group, GroupEncoding, ScalarMul},
};
use serde::{Deserialize, Serialize};

/// A Feldman verifier is used to provide integrity checking of shamir shares
/// `T` commitments are made to be used for verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeldmanVerifier<F: PrimeField, G: Group + GroupEncoding + ScalarMul<F>> {
    /// The generator for the share polynomial coefficients
    #[serde(
        serialize_with = "serialize_group",
        deserialize_with = "deserialize_group"
    )]
    pub generator: G,
    /// The commitments to the polynomial
    #[serde(
        serialize_with = "serialize_group_vec",
        deserialize_with = "deserialize_group_vec"
    )]
    pub commitments: Vec<G>,
    /// Marker
    #[serde(skip)]
    pub marker: PhantomData<F>,
}

impl<F: PrimeField, G: Group + GroupEncoding + ScalarMul<F>> FeldmanVerifier<F, G> {
    /// Check whether the share is valid according this verifier set
    pub fn verify(&self, share: &Share) -> bool {
        let s = bytes_to_field::<F>(share.value());
        if s.is_none() {
            return false;
        }

        let s = s.unwrap();
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

        let lhs: G = -self.generator * s;

        let res: G = lhs + rhs;

        res.is_identity().unwrap_u8() == 1
    }
}
