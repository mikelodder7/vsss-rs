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
    Deserializer,
};

pub fn bytes_to_field<F: PrimeField>(bytes: &[u8]) -> Option<F> {
    let mut s_repr = F::Repr::default();
    s_repr.as_mut()[..bytes.len()].copy_from_slice(bytes);

    let res = F::from_repr(s_repr);
    if res.is_some().unwrap_u8() == 1u8 {
        Some(res.unwrap())
    } else {
        None
    }
}

pub fn bytes_to_group<G: Group + GroupEncoding>(bytes: &[u8]) -> Option<G> {
    let mut y_repr = <G as GroupEncoding>::Repr::default();
    y_repr.as_mut().copy_from_slice(bytes);

    let y = G::from_bytes(&y_repr);
    if y.is_some().unwrap_u8() == 1 {
        Some(y.unwrap())
    } else {
        None
    }
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
