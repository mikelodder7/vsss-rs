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

use crate::util::*;
use core::{
    fmt::{self, Formatter},
    marker::PhantomData,
    mem::MaybeUninit,
};
use elliptic_curve::group::{Group, GroupEncoding};
use serde::{
    de::{Error, SeqAccess, Unexpected, Visitor},
    ser::{self, SerializeSeq, SerializeTuple},
    Deserializer, Serializer,
};

/// Set to BLS12-381. If we need bigger, then adjust
const MAX_GROUP_BYTES: usize = 192;
const MAX_GROUP_HEX: usize = MAX_GROUP_BYTES * 2;

pub(crate) fn serialize_group<G: Group + GroupEncoding, S: Serializer>(
    g: &G,
    s: S,
) -> Result<S::Ok, S::Error> {
    let repr = g.to_bytes();
    let bytes = repr.as_ref();

    if s.is_human_readable() {
        let mut output = [0u8; MAX_GROUP_HEX];
        let len = bytes.len();
        hex::encode_to_slice(bytes, &mut output[..len * 2])
            .map_err(|_| ser::Error::custom("invalid length"))?;
        let h = unsafe { core::str::from_utf8_unchecked(&output[..len * 2]) };
        s.serialize_str(h)
    } else {
        let mut tupler = s.serialize_tuple(bytes.len())?;
        for b in bytes {
            tupler.serialize_element(b)?;
        }
        tupler.end()
    }
}

pub(crate) fn serialize_group_vec<G: Group + GroupEncoding, S: Serializer, const N: usize>(
    g: &[G; N],
    s: S,
) -> Result<S::Ok, S::Error> {
    let is_human_readable = s.is_human_readable();
    let mut sequencer;
    if is_human_readable {
        sequencer = s.serialize_seq(Some(N))?;
        let mut out = [0u8; MAX_GROUP_HEX];
        for gg in g {
            let repr = gg.to_bytes();
            let bytes = repr.as_ref();
            let len = bytes.len();
            hex::encode_to_slice(bytes, &mut out[..len * 2])
                .map_err(|_| ser::Error::custom("invalid length"))?;
            let h = unsafe { core::str::from_utf8_unchecked(&out[..len * 2]) };
            sequencer.serialize_element(h)?;
        }
    } else {
        let len = uint_zigzag::Uint::from(g.len());

        let mut len_bytes = [0u8; uint_zigzag::Uint::MAX_BYTES];
        let len_len = len.to_bytes_with_length(&mut len_bytes);

        let g_len = G::Repr::default().as_ref().len();
        sequencer = s.serialize_seq(Some(N * g_len + len_len))?;
        for i in &len_bytes[..len_len] {
            sequencer.serialize_element(i)?;
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

pub(crate) fn deserialize_group_vec<
    'de,
    G: Group + GroupEncoding,
    D: Deserializer<'de>,
    const N: usize,
>(
    d: D,
) -> Result<[G; N], D::Error> {
    struct GroupVecVisitor<G: Group + GroupEncoding, const N: usize> {
        is_human_readable: bool,
        marker: PhantomData<G>,
    }

    impl<'de, G: Group + GroupEncoding, const N: usize> Visitor<'de> for GroupVecVisitor<G, N> {
        type Value = [G; N];

        fn expecting(&self, f: &mut Formatter) -> fmt::Result {
            write!(f, "a byte sequence or strings")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut values = MaybeUninit::<[G; N]>::uninit();
            if self.is_human_readable {
                let mut repr = G::Repr::default();
                let mut i = 0;
                while let Some(s) = seq.next_element::<&str>()? {
                    hex::decode_to_slice(s, repr.as_mut())
                        .map_err(|_| Error::invalid_length(i, &self))?;
                    let g = bytes_to_group(repr.as_ref()).ok_or_else(|| {
                        Error::invalid_value(Unexpected::Bytes(repr.as_ref()), &self)
                    })?;
                    let p = (values.as_mut_ptr() as *mut G).wrapping_add(i);
                    unsafe { core::ptr::write(p, g) };
                    i += 1;
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

                if groups.0 as usize != N {
                    return Err(Error::invalid_length(groups.0 as usize, &self));
                }

                i = uint_zigzag::Uint::MAX_BYTES - bytes_cnt_size;
                let mut repr = G::Repr::default();
                {
                    let r = repr.as_mut();
                    r[..i].copy_from_slice(&buffer[bytes_cnt_size..]);
                }
                let repr_len = repr.as_ref().len();
                let mut j = 0;
                while let Some(b) = seq.next_element()? {
                    repr.as_mut()[i] = b;
                    i += 1;
                    if i == repr_len {
                        i = 0;
                        let pt = G::from_bytes(&repr);
                        if pt.is_none().unwrap_u8() == 1u8 {
                            return Err(Error::invalid_value(Unexpected::Bytes(&buffer), &self));
                        }
                        let p = (values.as_mut_ptr() as *mut G).wrapping_add(j);
                        unsafe { core::ptr::write(p, pt.unwrap()) };
                        j += 1;
                        if j == groups.0 as usize {
                            break;
                        }
                    }
                }
            }
            let values = unsafe { values.assume_init() };
            Ok(values)
        }
    }

    let v = GroupVecVisitor {
        is_human_readable: d.is_human_readable(),
        marker: PhantomData::<G>,
    };
    d.deserialize_seq(v)
}
