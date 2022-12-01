// Copyright Michael Lodder. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use ff::PrimeField;
use group::{Group, GroupEncoding, ScalarMul};
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

use super::{super::Share, FeldmanVerifier};
use crate::{lib::*, util::bytes_to_field};

/// A Pedersen verifier is used to provide integrity checking of shamir shares
/// `T` commitments are made to be used for verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenVerifier<F: PrimeField, G: Group + GroupEncoding + ScalarMul<F>> {
    /// The generator for the blinding factor
    pub generator: G,
    /// The feldman verifier containing the share generator and commitments
    pub feldman_verifier: FeldmanVerifier<F, G>,
    /// The blinded commitments to the polynomial
    pub commitments: Vec<G>,
}

#[derive(Deserialize, Serialize)]
struct PedersenVerifierSerdes {
    pub generator: Vec<u8>,
    pub feldman_verifier: Vec<u8>,
    pub commitments: Vec<Vec<u8>>,
}

impl<F: PrimeField, G: Group + GroupEncoding + ScalarMul<F>> Serialize for PedersenVerifier<F, G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let serdes = PedersenVerifierSerdes {
            generator: self.generator.to_bytes().as_ref().to_vec(),
            feldman_verifier: serde_cbor::to_vec(&self.feldman_verifier).unwrap(),
            commitments: self
                .commitments
                .iter()
                .map(|c| c.to_bytes().as_ref().to_vec())
                .collect(),
        };
        serdes.serialize(serializer)
    }
}

impl<'de, F, G> Deserialize<'de> for PedersenVerifier<F, G>
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
        let serdes = PedersenVerifierSerdes::deserialize(deserializer)?;
        let mut commitments = Vec::with_capacity(serdes.commitments.len());
        for c in &serdes.commitments {
            commitments.push(group_elem(c, "commitment")?);
        }
        let feldman_verifier = serde_cbor::from_slice(&serdes.feldman_verifier)
            .map_err(|_| D::Error::missing_field("feldman_verifier"))?;
        Ok(Self {
            generator: group_elem(&serdes.generator, "generator")?,
            feldman_verifier,
            commitments,
        })
    }
}

impl<F: PrimeField, G: Group + GroupEncoding + ScalarMul<F>> PedersenVerifier<F, G> {
    /// Check whether the share is valid according this verifier set
    pub fn verify(&self, share: &Share, blind_share: &Share) -> bool {
        let secret = bytes_to_field::<F>(share.value());
        let blinding = bytes_to_field::<F>(blind_share.value());
        if secret.is_none() || blinding.is_none() {
            return false;
        }

        let secret = secret.unwrap();
        let blinding = blinding.unwrap();

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

        let g: G = (-self.feldman_verifier.generator) * secret;
        let h: G = (-self.generator) * blinding;

        let res: G = rhs + g + h;

        res.is_identity().unwrap_u8() == 1
    }
}
