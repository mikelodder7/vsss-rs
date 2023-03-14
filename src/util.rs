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
use heapless::Vec;
use serde::{
    de::{Error, SeqAccess, Unexpected, Visitor},
    ser::{SerializeSeq, SerializeTuple},
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

pub(crate) fn serialize_group_vec<G: Group + GroupEncoding, S: Serializer, const N: usize>(
    g: &Vec<G, N>,
    s: S,
) -> Result<S::Ok, S::Error> {
    let is_human_readable = s.is_human_readable();
    let g_len = G::Repr::default().as_ref().len();
    let g_hexits = g_len * 2;
    let mut sequencer;
    if is_human_readable {
        sequencer = s.serialize_seq(Some(g.len()))?;
        let mut hexits = [0u8; MAX_GROUP_HEXITS];
        for gg in g {
            hex::encode_to_slice(gg.to_bytes().as_ref(), &mut hexits[..g_hexits])
                .expect(EXPECT_MSG);
            let h = unsafe { core::str::from_utf8_unchecked(&hexits[..g_hexits]) };
            sequencer.serialize_element(h)?;
        }
    } else {
        let mut len_bytes = [0u8; uint_zigzag::Uint::MAX_BYTES];
        let len = uint_zigzag::Uint::from(g.len());

        let i = len.to_bytes_with_length(&mut len_bytes);
        sequencer = s.serialize_seq(Some(g.len() * g_len + i))?;
        for b in &len_bytes[..i] {
            sequencer.serialize_element(&b)?;
        }

        for gg in g {
            let repr = gg.to_bytes();
            for b in repr.as_ref() {
                sequencer.serialize_element(b)?;
            }
        }
    }
    sequencer.end()
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

pub(crate) fn deserialize_group_vec<
    'de,
    G: Group + GroupEncoding,
    D: Deserializer<'de>,
    const N: usize,
>(
    d: D,
) -> Result<Vec<G, N>, D::Error> {
    struct GroupVecVisitor<G: Group + GroupEncoding, const NN: usize> {
        is_human_readable: bool,
        marker: PhantomData<G>,
    }

    impl<'de, G: Group + GroupEncoding, const NN: usize> Visitor<'de> for GroupVecVisitor<G, NN> {
        type Value = Vec<G, NN>;

        fn expecting(&self, f: &mut Formatter) -> fmt::Result {
            write!(f, "a byte sequence or strings")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut values = Vec::new();
            if self.is_human_readable {
                let mut repr = G::Repr::default();
                while let Some(s) = seq.next_element::<&str>()? {
                    hex::decode_to_slice(s, repr.as_mut())
                        .map_err(|_| Error::invalid_value(Unexpected::Str(s), &self))?;
                    let bytes = repr.as_ref();
                    let f = bytes_to_group(bytes)
                        .ok_or_else(|| Error::invalid_value(Unexpected::Bytes(bytes), &self))?;
                    values.push(f).expect(EXPECT_MSG);
                }
            } else {
                let mut buffer = [0u8; uint_zigzag::Uint::MAX_BYTES];
                let mut i = 0;
                while let Some(b) = seq.next_element()? {
                    buffer[i] = b;
                    i += 1;
                    if i == uint_zigzag::Uint::MAX_BYTES {
                        break;
                    }
                }
                let bytes_cnt_size = uint_zigzag::Uint::peek(&buffer)
                    .ok_or_else(|| Error::invalid_value(Unexpected::Bytes(&buffer), &self))?;
                let groups = uint_zigzag::Uint::try_from(&buffer[..bytes_cnt_size])
                    .map_err(|_| Error::invalid_value(Unexpected::Bytes(&buffer), &self))?;
                let groups = groups.0 as usize;

                i = uint_zigzag::Uint::MAX_BYTES - bytes_cnt_size;
                let mut repr = G::Repr::default();
                {
                    let r = repr.as_mut();
                    r[..i].copy_from_slice(&buffer[bytes_cnt_size..]);
                }
                let repr_len = repr.as_ref().len();
                while let Some(b) = seq.next_element()? {
                    repr.as_mut()[i] = b;
                    i += 1;
                    if i == repr_len {
                        i = 0;
                        let pt = Option::<G>::from(G::from_bytes(&repr)).ok_or_else(|| {
                            Error::invalid_value(Unexpected::Bytes(&buffer), &self)
                        })?;
                        values.push(pt).expect(EXPECT_MSG);
                        if values.len() == groups {
                            break;
                        }
                    }
                }
                if values.len() != groups {
                    return Err(Error::invalid_length(values.len(), &self));
                }
            }
            Ok(values)
        }
    }

    let v = GroupVecVisitor::<G, N> {
        is_human_readable: d.is_human_readable(),
        marker: PhantomData::<G>,
    };
    d.deserialize_seq(v)
}
