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
    ser::SerializeSeq,
    Deserialize, Deserializer, Serialize, Serializer,
};
use zeroize::Zeroize;

/// A Shamir simple secret share
/// provides no integrity checking
/// The first byte is the X-coordinate or identifier
/// The remaining bytes are the Y-coordinate
#[derive(Clone, Debug, Default, PartialEq, Eq, Zeroize)]
pub struct Share(pub Vec<u8>);

impl Serialize for Share {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if s.is_human_readable() {
            hex::encode(&self.0).serialize(s)
        } else {
            let mut tupler = s.serialize_seq(Some(self.0.len()))?;
            for b in &self.0 {
                tupler.serialize_element(b)?;
            }
            tupler.end()
        }
    }
}

impl<'de> Deserialize<'de> for Share {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ShareVisitor;

        impl<'de> Visitor<'de> for ShareVisitor {
            type Value = Share;

            fn expecting(&self, f: &mut Formatter) -> fmt::Result {
                write!(f, "a hex string or byte sequence")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let bytes = hex::decode(v)
                    .map_err(|_e| de::Error::invalid_value(Unexpected::Str(v), &self))?;
                Ok(Share(bytes))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytes = Vec::new();
                while let Some(b) = seq.next_element()? {
                    bytes.push(b);
                }
                Ok(Share(bytes))
            }
        }

        if d.is_human_readable() {
            d.deserialize_str(ShareVisitor)
        } else {
            d.deserialize_seq(ShareVisitor)
        }
    }
}

impl AsRef<[u8]> for Share {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Share {
    type Error = TryFromSliceError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(bytes.to_vec()))
    }
}

impl From<Share> for Vec<u8> {
    fn from(share: Share) -> Self {
        share.0
    }
}

impl Share {
    /// True if all value bytes are zero in constant time
    pub fn is_zero(&self) -> bool {
        let mut v = 0u8;
        for b in self.value() {
            v |= b;
        }
        v == 0
    }

    /// The identifier for this share
    pub fn identifier(&self) -> u8 {
        self.0[0]
    }

    /// The raw byte value of the share
    pub fn value(&self) -> &[u8] {
        &self.0[1..]
    }

    /// Convert this share into a group element
    pub fn as_group_element<G: GroupEncoding>(&self) -> VsssResult<G> {
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
            let mut bytes = vec![identifier; repr.as_ref().len()];
            bytes[1..].copy_from_slice(repr.as_ref());
            Ok(Self(bytes))
        }
    }

    /// Convert this share into a prime field element
    pub fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
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
            let mut bytes = vec![identifier; repr.as_ref().len()];
            bytes[1..].copy_from_slice(repr.as_ref());
            Ok(Self(bytes))
        }
    }
}
