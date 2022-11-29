// Copyright Michael Lodder. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use core::marker::PhantomData;

use ff::PrimeField;
use group::{Group, GroupEncoding, ScalarMul};
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

use super::super::Share;
use crate::{lib::*, util::bytes_to_field};

/// A Feldman verifier is used to provide integrity checking of shamir shares
/// `T` commitments are made to be used for verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeldmanVerifier<F: PrimeField, G: Group + GroupEncoding + ScalarMul<F>> {
    /// The generator for the share polynomial coefficients
    pub generator: G,
    /// The commitments to the polynomial
    pub commitments: Vec<G>,
    /// Marker
    pub marker: PhantomData<F>,
}

#[derive(Serialize, Deserialize)]
struct FeldmanVerifierSerdes {
    pub generator: Vec<u8>,
    pub commitments: Vec<Vec<u8>>,
}

impl<F, G> Serialize for FeldmanVerifier<F, G>
where
    F: PrimeField,
    G: Group + GroupEncoding + ScalarMul<F>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let serdes = FeldmanVerifierSerdes {
            generator: self.generator.to_bytes().as_ref().to_vec(),
            commitments: self
                .commitments
                .iter()
                .map(|c| c.to_bytes().as_ref().to_vec())
                .collect(),
        };
        serdes.serialize(serializer)
    }
}

impl<'de, F, G> Deserialize<'de> for FeldmanVerifier<F, G>
where
    F: PrimeField,
    G: Group + GroupEncoding + ScalarMul<F>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        let group_elem = |v: &[u8], msg: &'static str| -> Result<G, D::Error> {
            let mut repr = G::Repr::default();
            repr.as_mut().copy_from_slice(v);
            let opt = G::from_bytes(&repr);
            if opt.is_none().unwrap_u8() == 1 {
                return Err(D::Error::missing_field(msg));
            }
            Ok(opt.unwrap())
        };
        let serdes = FeldmanVerifierSerdes::deserialize(deserializer)?;
        let mut commitments = Vec::with_capacity(serdes.commitments.len());
        for c in &serdes.commitments {
            commitments.push(group_elem(c, "commitment")?);
        }
        Ok(Self {
            generator: group_elem(&serdes.generator, "generator")?,
            commitments,
            marker: PhantomData,
        })
    }
}

impl<F: PrimeField, G: Group + GroupEncoding + ScalarMul<F>> FeldmanVerifier<F, G> {
    /// Check whether the share is valid according this verifier set
    pub fn verify(&self, share: &Share) -> bool {
        let s = bytes_to_field::<F>(share.value());
        if s.is_none() {
            return false;
        }

        let s = s.unwrap();
        let x = F::from(u64::from(share.identifier()));
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
