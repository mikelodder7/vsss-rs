/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use crate::{
    util::{bytes_to_field, get_group_size},
    Share,
};
use core::fmt;
use core::marker::PhantomData;
use ff::PrimeField;
use group::{Group, GroupEncoding, ScalarMul};
use serde::{
    de::{Error, SeqAccess, Unexpected, Visitor},
    ser::SerializeTuple,
    Deserialize, Deserializer, Serialize, Serializer,
};

/// A Feldman verifier is used to provide integrity checking of shamir shares
/// `T` commitments are made to be used for verification.
#[derive(Copy, Clone, Debug)]
pub struct FeldmanVerifier<F: PrimeField, G: Group + GroupEncoding + ScalarMul<F>, const T: usize> {
    /// The generator for the share polynomial coefficients
    pub generator: G,
    /// The commitments to the polynomial
    pub commitments: [G; T],
    /// Marker
    pub marker: PhantomData<F>,
}

impl<F, G, const T: usize> Serialize for FeldmanVerifier<F, G, T>
where
    F: PrimeField,
    G: Group + GroupEncoding + ScalarMul<F>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = self.generator.to_bytes();
        let mut tv = serializer.serialize_tuple((T + 1) * bytes.as_ref().len())?;
        for b in bytes.as_ref() {
            tv.serialize_element(b)?;
        }
        for c in &self.commitments {
            bytes = c.to_bytes();
            for b in bytes.as_ref() {
                tv.serialize_element(b)?;
            }
        }
        tv.end()
    }
}

impl<'de, F, G, const T: usize> Deserialize<'de> for FeldmanVerifier<F, G, T>
where
    F: PrimeField,
    G: Group + GroupEncoding + ScalarMul<F>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
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
            type Value = FeldmanVerifier<F, G, T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    formatter,
                    "an array of length {}",
                    (T + 1) * get_group_size::<G>()
                )
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut group_elem = |offset: usize| -> Result<G, A::Error> {
                    let mut repr = G::Repr::default();
                    for (i, ptr) in repr.as_mut().iter_mut().enumerate() {
                        *ptr = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::invalid_length(offset + i, &self))?;
                    }
                    let opt = G::from_bytes(&repr);
                    if opt.is_none().unwrap_u8() == 1 {
                        return Err(A::Error::invalid_type(
                            Unexpected::Bytes(repr.as_ref()),
                            &self,
                        ));
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

                Ok(FeldmanVerifier {
                    generator,
                    commitments,
                    marker: PhantomData,
                })
            }
        }

        let visitor = GroupVisitor {
            marker1: PhantomData,
            marker2: PhantomData,
        };
        deserializer.deserialize_tuple((T + 1) * get_group_size::<G>(), visitor)
    }
}

impl<F: PrimeField, G: Group + GroupEncoding + ScalarMul<F>, const T: usize>
    FeldmanVerifier<F, G, T>
{
    /// Check whether the share is valid according this verifier set
    pub fn verify<const S: usize>(&self, share: &Share<S>) -> bool {
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
