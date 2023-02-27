/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use crate::error::Error;
use core::{
    array::TryFromSliceError,
    convert::TryFrom,
    fmt::{self, Formatter},
};
use elliptic_curve::{ff::PrimeField, group::GroupEncoding};
use serde::de::Unexpected;
use serde::{
    de::{self, SeqAccess, Visitor},
    ser::{self, SerializeSeq},
    Deserialize, Deserializer, Serialize, Serializer,
};
use zeroize::Zeroize;
/// A Shamir simple secret share
/// provides no integrity checking
/// The first byte is the X-coordinate or identifier
/// The remaining bytes are the Y-coordinate
#[derive(Copy, Clone, Debug, PartialEq, Eq, Zeroize)]
pub struct Share<const N: usize>(pub [u8; N]);

impl<const N: usize> Default for Share<N> {
    fn default() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> AsRef<[u8]> for Share<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> TryFrom<&[u8]> for Share<N> {
    type Error = TryFromSliceError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(<[u8; N]>::try_from(bytes)?))
    }
}

impl<const N: usize> From<Share<N>> for [u8; N] {
    fn from(share: Share<N>) -> Self {
        share.0
    }
}

impl<const N: usize> Serialize for Share<N> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if s.is_human_readable() {
            let mut output = [0u8; 66];
            let len = self.0.len();
            hex::encode_to_slice(self.0, &mut output[..len * 2])
                .map_err(|_| ser::Error::custom("invalid length"))?;
            let h = unsafe { core::str::from_utf8_unchecked(&output[..len * 2]) };
            s.serialize_str(h)
        } else {
            let mut seq = s.serialize_seq(Some(N))?;
            for b in &self.0 {
                seq.serialize_element(b)?;
            }
            seq.end()
        }
    }
}

impl<'de, const N: usize> Deserialize<'de> for Share<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ShareVisitor<const N: usize>;

        impl<'de, const N: usize> Visitor<'de> for ShareVisitor<N> {
            type Value = Share<N>;

            fn expecting(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "a byte sequence")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let mut arr = [0u8; N];
                hex::decode_to_slice(v, &mut arr)
                    .map_err(|_| de::Error::invalid_value(Unexpected::Str(v), &self))?;
                Ok(Share(arr))
            }

            fn visit_seq<A>(self, mut s: A) -> Result<Share<N>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut arr = [0u8; N];
                for (i, p) in arr.iter_mut().enumerate() {
                    *p = s
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                Ok(Share(arr))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(ShareVisitor)
        } else {
            deserializer.deserialize_seq(ShareVisitor)
        }
    }
}

impl<const N: usize> Share<N> {
    /// True if all value bytes are zero in constant time
    pub fn is_zero(&self) -> bool {
        let mut v = 0u8;
        for b in &self.0[1..] {
            v |= b;
        }
        v == 0
    }

    /// Convert this share into a group element
    pub fn as_group_element<G: GroupEncoding>(&self) -> Result<G, Error> {
        let mut repr = G::Repr::default();
        repr.as_mut().copy_from_slice(self.value());
        let res = G::from_bytes(&repr);
        if res.is_some().unwrap_u8() == 1u8 {
            Ok(res.unwrap())
        } else {
            Err(Error::InvalidShareConversion)
        }
    }

    /// Convert this share into a prime field element
    pub fn as_field_element<F: PrimeField>(&self) -> Result<F, Error> {
        let mut repr = F::Repr::default();
        repr.as_mut().copy_from_slice(self.value());
        let res = F::from_repr(repr);
        if res.is_some().unwrap_u8() == 1u8 {
            Ok(res.unwrap())
        } else {
            Err(Error::InvalidShareConversion)
        }
    }

    /// The identifier for this share
    pub fn identifier(&self) -> u8 {
        self.0[0]
    }

    /// The raw byte value of the share
    pub fn value(&self) -> &[u8] {
        &self.0[1..]
    }
}
