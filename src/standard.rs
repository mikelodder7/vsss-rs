mod feldman;
mod pedersen;
mod polynomial;
mod shamir;
mod share;
mod verifier;

pub use feldman::*;
pub use pedersen::*;
pub use polynomial::*;
pub use shamir::*;
pub use share::*;
pub use verifier::*;

use crate::lib::{String, Vec};
use crate::util::*;
use core::{
    fmt::{self, Formatter},
    marker::PhantomData,
};
use elliptic_curve::group::{Group, GroupEncoding};
use serde::{
    de::{Error, SeqAccess, Unexpected, Visitor},
    ser::{SerializeSeq, SerializeTuple},
    Deserializer, Serializer,
};

pub(crate) fn serialize_group<G: Group + GroupEncoding, S: Serializer>(
    g: &G,
    s: S,
) -> Result<S::Ok, S::Error> {
    let repr = g.to_bytes();
    serialize_ref(repr, s)
}

pub(crate) fn serialize_group_vec<G: Group + GroupEncoding, S: Serializer>(
    g: &Vec<G>,
    s: S,
) -> Result<S::Ok, S::Error> {
    let is_human_readable = s.is_human_readable();
    let mut sequencer;
    if is_human_readable {
        sequencer = s.serialize_seq(Some(g.len()))?;
        for gg in g {
            sequencer.serialize_element(&hex::encode(gg.to_bytes().as_ref()))?;
        }
    } else {
        let len = uint_zigzag::Uint::from(g.len());

        let g_len = G::Repr::default().as_ref().len();
        let len_bytes = len.to_vec();
        sequencer = s.serialize_seq(Some(g.len() * g_len + len_bytes.len()))?;
        for b in len_bytes {
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
    if s.is_human_readable() {
        let h = hex::encode(bytes.as_ref());
        s.serialize_str(&h)
    } else {
        let bytes = bytes.as_ref();
        let mut tupler = s.serialize_tuple(bytes.len())?;
        for b in bytes {
            tupler.serialize_element(b)?;
        }
        tupler.end()
    }
}

pub(crate) fn deserialize_group_vec<'de, G: Group + GroupEncoding, D: Deserializer<'de>>(
    d: D,
) -> Result<Vec<G>, D::Error> {
    struct GroupVecVisitor<G: Group + GroupEncoding> {
        is_human_readable: bool,
        marker: PhantomData<G>,
    }

    impl<'de, G: Group + GroupEncoding> Visitor<'de> for GroupVecVisitor<G> {
        type Value = Vec<G>;

        fn expecting(&self, f: &mut Formatter) -> fmt::Result {
            write!(f, "a byte sequence or strings")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut values = Vec::new();
            if self.is_human_readable {
                while let Some(s) = seq.next_element()? {
                    let bytes = hex::decode::<&String>(&s)
                        .map_err(|_| Error::invalid_length(values.len(), &self))?;
                    let f = bytes_to_group(&bytes)
                        .ok_or_else(|| Error::invalid_value(Unexpected::Bytes(&bytes), &self))?;
                    values.push(f);
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

                i = uint_zigzag::Uint::MAX_BYTES - bytes_cnt_size;
                let mut repr = G::Repr::default();
                {
                    let r = repr.as_mut();
                    r[..i].copy_from_slice(&buffer[bytes_cnt_size..]);
                }
                let repr_len = repr.as_ref().len();
                values.reserve(groups.0 as usize);
                while let Some(b) = seq.next_element()? {
                    repr.as_mut()[i] = b;
                    i += 1;
                    if i == repr_len {
                        i = 0;
                        let pt = G::from_bytes(&repr);
                        if pt.is_none().unwrap_u8() == 1u8 {
                            return Err(Error::invalid_value(Unexpected::Bytes(&buffer), &self));
                        }
                        values.push(pt.unwrap());
                        if values.len() == groups.0 as usize {
                            break;
                        }
                    }
                }
                if values.len() != groups.0 as usize {
                    return Err(Error::invalid_length(values.len(), &self));
                }
            }
            Ok(values)
        }
    }

    let v = GroupVecVisitor {
        is_human_readable: d.is_human_readable(),
        marker: PhantomData::<G>,
    };
    d.deserialize_seq(v)
}
