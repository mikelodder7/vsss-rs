// Copyright Michael Lodder. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use core::{fmt, marker::PhantomData};

use ff::PrimeField;
use group::{Group, GroupEncoding, ScalarMul};
use serde::{
    de::{Error, SeqAccess, Unexpected, Visitor},
    ser::SerializeTuple,
    Deserialize,
    Deserializer,
    Serialize,
    Serializer,
};

use super::FeldmanVerifier;
use crate::{
    util::{bytes_to_field, get_group_size},
    Share,
};

/// A Pedersen verifier is used to provide integrity checking of shamir shares
/// `T` commitments are made to be used for verification.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PedersenVerifier<F: PrimeField, G: Group + GroupEncoding + ScalarMul<F>, const T: usize> {
    /// The generator for the blinding factor
    pub generator: G,
    /// The feldman verifier containing the share generator and commitments
    pub feldman_verifier: FeldmanVerifier<F, G, T>,
    /// The blinded commitments to the polynomial
    pub commitments: [G; T],
}

impl<F, G, const T: usize> Serialize for PedersenVerifier<F, G, T>
where
    F: PrimeField,
    G: Group + GroupEncoding + ScalarMul<F>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let mut bytes = self.generator.to_bytes();
        let mut tv = serializer.serialize_tuple(2 * (T + 1) * bytes.as_ref().len())?;
        for b in bytes.as_ref() {
            tv.serialize_element(b)?;
        }
        for c in &self.commitments {
            bytes = c.to_bytes();
            for b in bytes.as_ref() {
                tv.serialize_element(b)?;
            }
        }
        bytes = self.feldman_verifier.generator.to_bytes();
        for b in bytes.as_ref() {
            tv.serialize_element(b)?;
        }
        for c in &self.feldman_verifier.commitments {
            bytes = c.to_bytes();
            for b in bytes.as_ref() {
                tv.serialize_element(b)?;
            }
        }

        tv.end()
    }
}

impl<'de, F, G, const T: usize> Deserialize<'de> for PedersenVerifier<F, G, T>
where
    F: PrimeField,
    G: Group + GroupEncoding + ScalarMul<F>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        struct GroupVisitor<F, G, const T: usize>
        where
            F: PrimeField,
            G: Group + GroupEncoding + ScalarMul<F>,
        {
            marker1: PhantomData<F>,
            marker2: PhantomData<G>,
        }

        impl<'de, F, G, const T: usize> Visitor<'de> for GroupVisitor<F, G, T>
        where
            F: PrimeField,
            G: Group + GroupEncoding + ScalarMul<F>,
        {
            type Value = PedersenVerifier<F, G, T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "an array of length {}", 2 * (T + 1) * get_group_size::<G>())
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where A: SeqAccess<'de> {
                let mut group_elem = |offset: usize| -> Result<G, A::Error> {
                    let mut repr = G::Repr::default();
                    for (i, ptr) in repr.as_mut().iter_mut().enumerate() {
                        *ptr = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::invalid_length(offset + i, &self))?;
                    }
                    let opt = G::from_bytes(&repr);
                    if opt.is_none().unwrap_u8() == 1 {
                        return Err(A::Error::invalid_type(Unexpected::Bytes(repr.as_ref()), &self));
                    }
                    Ok(opt.unwrap())
                };
                let bytes = G::Repr::default();
                let length = bytes.as_ref().len();
                let generator = group_elem(0)?;
                let mut offset = length;

                let mut commitments = [G::identity(); T];
                for i in commitments.iter_mut() {
                    *i = group_elem(offset)?;
                    offset += length;
                }

                let f_generator = group_elem(offset)?;
                offset += length;
                let mut f_commitments = [G::identity(); T];
                for i in f_commitments.iter_mut() {
                    *i = group_elem(offset)?;
                    offset += length;
                }

                Ok(PedersenVerifier {
                    generator,
                    commitments,
                    feldman_verifier: FeldmanVerifier {
                        generator: f_generator,
                        commitments: f_commitments,
                        marker: PhantomData,
                    },
                })
            }
        }

        let visitor = GroupVisitor {
            marker1: PhantomData,
            marker2: PhantomData,
        };
        deserializer.deserialize_tuple(2 * (T + 1) * get_group_size::<G>(), visitor)
    }
}

impl<F: PrimeField, G: Group + GroupEncoding + ScalarMul<F>, const T: usize> PedersenVerifier<F, G, T> {
    /// Check whether the share is valid according this verifier set
    pub fn verify<const S: usize>(&self, share: &Share<S>, blind_share: &Share<S>) -> bool {
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
