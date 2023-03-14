/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use crate::*;
use core::{
    array::TryFromSliceError,
    convert::TryFrom,
    fmt::{self, Formatter},
};
use elliptic_curve::{ff::PrimeField, group::GroupEncoding};
use serde::{
    de::{self, SeqAccess, Unexpected, Visitor},
    ser::{self, SerializeSeq},
    Deserialize, Deserializer, Serialize, Serializer,
};
use zeroize::ZeroizeOnDrop;

/// A Shamir simple secret share
/// provides no integrity checking
/// The first byte is the X-coordinate or identifier
/// The remaining bytes are the Y-coordinate
#[derive(Clone, Debug, PartialEq, Eq, ZeroizeOnDrop)]
pub struct Share<const N: usize>(pub Vec<u8, N>);

impl<const N: usize> Default for Share<N> {
    fn default() -> Self {
        Self(Vec::<u8, N>::new())
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
        Ok(Self(Vec::from_slice(bytes).expect(EXPECT_MSG)))
    }
}

impl<const N: usize> From<Share<N>> for Vec<u8, N> {
    fn from(share: Share<N>) -> Self {
        share.0.clone()
    }
}

impl<const N: usize> From<Share<N>> for crate::Share {
    fn from(value: Share<N>) -> Self {
        Self(Vec::from_slice(&value.0[..]).expect(EXPECT_MSG))
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> From<Share<N>> for alloc::vec::Vec<u8> {
    fn from(value: Share<N>) -> Self {
        (&value.0[..]).to_vec()
    }
}

#[cfg(feature = "std")]
impl<const N: usize> From<Share<N>> for std::vec::Vec<u8> {
    fn from(value: Share<N>) -> Self {
        (&value.0[..]).to_vec()
    }
}

impl<const N: usize> TryFrom<crate::Share> for Share<N> {
    type Error = Error;

    fn try_from(value: crate::Share) -> VsssResult<Self> {
        if value.0.len() > N {
            return Err(Error::InvalidShareConversion);
        }

        Ok(Self(Vec::from_slice(&value.0[..]).expect(EXPECT_MSG)))
    }
}

impl<const N: usize> Serialize for Share<N> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if s.is_human_readable() {
            let mut output = [0u8; MAX_GROUP_HEXITS];
            let len = self.0.len();
            hex::encode_to_slice(&self.0[..], &mut output[..len * 2])
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
                Ok(Share(
                    Vec::from_slice(&arr[..])
                        .expect("should've failed during hex::decode_to_slice"),
                ))
            }

            fn visit_seq<A>(self, mut s: A) -> Result<Share<N>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut arr = Vec::<u8, N>::new();
                for i in 0..N {
                    let p = s
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                    arr.push(p).expect(EXPECT_MSG);
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
    pub fn is_zero(&self) -> Choice {
        let mut v = 0i8;
        for b in self.value() {
            v |= *b as i8;
        }
        let v = ((v | -v) >> 7) + 1;
        Choice::from(v as u8)
    }

    /// Convert this share into a group element
    pub fn as_group_element<G: GroupEncoding>(&self) -> Result<G, Error> {
        let mut repr = G::Repr::default();
        repr.as_mut().copy_from_slice(self.value());
        Option::<G>::from(G::from_bytes(&repr)).ok_or(Error::InvalidShareConversion)
    }

    /// Convert group element into a share
    pub fn from_group_element<G: GroupEncoding>(identifier: u8, group: G) -> VsssResult<Self> {
        if identifier == 0 {
            Err(Error::InvalidShareConversion)
        } else {
            let repr = group.to_bytes();
            let r_repr = repr.as_ref();
            let mut bytes = Vec::new();
            bytes.push(identifier).expect(EXPECT_MSG);
            bytes.extend_from_slice(r_repr).expect(EXPECT_MSG);
            Ok(Self(bytes))
        }
    }

    /// Convert this share into a prime field element
    pub fn as_field_element<F: PrimeField>(&self) -> Result<F, Error> {
        let mut repr = F::Repr::default();
        repr.as_mut().copy_from_slice(self.value());
        Option::<F>::from(F::from_repr(repr)).ok_or(Error::InvalidShareConversion)
    }

    /// Convert field element into a share
    pub fn from_field_element<F: PrimeField>(identifier: u8, field: F) -> VsssResult<Self> {
        if identifier == 0 {
            Err(Error::InvalidShareConversion)
        } else {
            let repr = field.to_repr();
            let r_repr = repr.as_ref();
            let mut bytes = Vec::new();
            bytes.push(identifier).expect(EXPECT_MSG);
            bytes.extend_from_slice(r_repr).expect(EXPECT_MSG);
            Ok(Self(bytes))
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
