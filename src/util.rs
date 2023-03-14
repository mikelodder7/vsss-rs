/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use core::{
    fmt::{self, Formatter},
    marker::PhantomData,
};
use elliptic_curve::{
    ff::PrimeField,
    group::{Group, GroupEncoding},
};
use serde::{
    de::{Error, SeqAccess, Unexpected, Visitor},
    ser::SerializeTuple,
    Deserializer, Serialize, Serializer,
};

pub(crate) const MAX_GROUP_SIZE: usize = 192;
pub(crate) const MAX_GROUP_HEXITS: usize = MAX_GROUP_SIZE * 2;
pub(crate) const MAX_SHARE_BYTES: usize = MAX_GROUP_SIZE + 1;
pub(crate) const MAX_SHARE_HEXITS: usize = MAX_SHARE_BYTES * 2;
pub(crate) const MAX_POLYNOMIAL_SIZE: usize = 255;
pub(crate) const MAX_SHARES: usize = 255;
pub(crate) const EXPECT_MSG: &str = "a bigger array";

pub fn bytes_to_field<F: PrimeField>(bytes: &[u8]) -> Option<F> {
    let mut s_repr = F::Repr::default();
    s_repr.as_mut()[..bytes.len()].copy_from_slice(bytes);

    Option::<F>::from(F::from_repr(s_repr))
}

pub fn bytes_to_group<G: Group + GroupEncoding>(bytes: &[u8]) -> Option<G> {
    let mut y_repr = <G as GroupEncoding>::Repr::default();
    y_repr.as_mut().copy_from_slice(bytes);

    Option::<G>::from(G::from_bytes(&y_repr))
}

pub(crate) fn deserialize_group<'de, G: Group + GroupEncoding, D: Deserializer<'de>>(
    d: D,
) -> Result<G, D::Error> {
    struct GroupVisitor<G: Group + GroupEncoding> {
        marker: PhantomData<G>,
    }

    impl<'de, G: Group + GroupEncoding> Visitor<'de> for GroupVisitor<G> {
        type Value = G;

        fn expecting(&self, f: &mut Formatter) -> fmt::Result {
            write!(f, "a byte sequence or string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            let mut repr = G::Repr::default();
            hex::decode_to_slice(v, repr.as_mut())
                .map_err(|_| Error::invalid_value(Unexpected::Str(v), &self))?;
            bytes_to_group(repr.as_ref())
                .ok_or_else(|| Error::invalid_value(Unexpected::Bytes(repr.as_ref()), &self))
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut repr = G::Repr::default();

            let mut i = 0;
            while let Some(b) = seq.next_element()? {
                repr.as_mut()[i] = b;
                i += 1;
            }

            bytes_to_group(repr.as_ref())
                .ok_or_else(|| Error::custom("unable to convert to a group element"))
        }
    }

    let v = GroupVisitor {
        marker: PhantomData::<G>,
    };
    if d.is_human_readable() {
        d.deserialize_str(v)
    } else {
        let repr = G::Repr::default();
        d.deserialize_tuple(repr.as_ref().len(), v)
    }
}

pub(crate) fn serialize_scalar<F: PrimeField, S: Serializer>(
    scalar: &F,
    s: S,
) -> Result<S::Ok, S::Error> {
    let repr = scalar.to_repr();
    serialize_ref(repr, s)
}

pub(crate) fn deserialize_scalar<'de, F: PrimeField, D: Deserializer<'de>>(
    d: D,
) -> Result<F, D::Error> {
    struct ScalarVisitor<F: PrimeField> {
        marker: PhantomData<F>,
    }

    impl<'de, F: PrimeField> Visitor<'de> for ScalarVisitor<F> {
        type Value = F;

        fn expecting(&self, f: &mut Formatter) -> fmt::Result {
            write!(f, "a byte sequence or string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            let mut repr = F::Repr::default();
            hex::decode_to_slice(v, repr.as_mut())
                .map_err(|_| Error::invalid_value(Unexpected::Str(v), &self))?;
            bytes_to_field(repr.as_ref())
                .ok_or_else(|| Error::invalid_value(Unexpected::Bytes(repr.as_ref()), &self))
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut repr = F::Repr::default();

            let mut i = 0;
            while let Some(b) = seq.next_element()? {
                repr.as_mut()[i] = b;
                i += 1;
            }

            bytes_to_field(repr.as_ref())
                .ok_or_else(|| Error::custom("unable to convert to a scalar"))
        }
    }

    let v = ScalarVisitor {
        marker: PhantomData::<F>,
    };
    if d.is_human_readable() {
        d.deserialize_str(v)
    } else {
        let repr = F::Repr::default();
        d.deserialize_tuple(repr.as_ref().len(), v)
    }
}

pub(crate) fn serialize_group<G: Group + GroupEncoding, S: Serializer>(
    g: &G,
    s: S,
) -> Result<S::Ok, S::Error> {
    let repr = g.to_bytes();
    serialize_ref(repr, s)
}

fn serialize_ref<B: AsRef<[u8]>, S: Serializer>(bytes: B, s: S) -> Result<S::Ok, S::Error> {
    let bytes = bytes.as_ref();
    if s.is_human_readable() {
        let hexit_len = bytes.len() * 2;
        let mut hexits = [0u8; MAX_GROUP_HEXITS];
        hex::encode_to_slice(bytes, &mut hexits[..hexit_len]).expect(EXPECT_MSG);
        let h = unsafe { core::str::from_utf8_unchecked(&hexits[..hexit_len]) };
        h.serialize(s)
    } else {
        let mut tupler = s.serialize_tuple(bytes.len())?;
        for b in bytes {
            tupler.serialize_element(b)?;
        }
        tupler.end()
    }
}
