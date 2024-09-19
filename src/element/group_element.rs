use crate::*;
use core::ops::{Deref, DerefMut};

/// A share element represented as a group field element.
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub struct GroupElement<G: GroupType>(pub G);

impl<G: GroupType> Deref for GroupElement<G> {
    type Target = G;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<G: GroupType> DerefMut for GroupElement<G> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<G: GroupType> AsRef<G> for GroupElement<G> {
    fn as_ref(&self) -> &G {
        &self.0
    }
}

impl<G: GroupType> AsMut<G> for GroupElement<G> {
    fn as_mut(&mut self) -> &mut G {
        &mut self.0
    }
}

impl<G: GroupType> From<G> for GroupElement<G> {
    fn from(value: G) -> Self {
        Self(value)
    }
}

impl<G: GroupType> ShareElement for GroupElement<G> {
    type Serialization = G::Repr;

    type Inner = G;

    fn zero() -> Self {
        Self(<G as Group>::identity())
    }

    fn one() -> Self {
        Self(<G as Group>::generator())
    }

    fn is_zero(&self) -> Choice {
        G::is_identity(self)
    }

    fn serialize(&self) -> Self::Serialization {
        self.to_bytes()
    }

    fn deserialize(serialized: &Self::Serialization) -> VsssResult<Self> {
        Option::from(G::from_bytes(serialized))
            .map(Self)
            .ok_or(Error::InvalidShareElement)
    }

    fn from_slice(vec: &[u8]) -> VsssResult<Self> {
        let mut repr = G::Repr::default();
        if vec.len() != repr.as_ref().len() {
            return Err(Error::InvalidShareElement);
        }
        repr.as_mut().copy_from_slice(vec);
        Option::from(G::from_bytes(&repr))
            .map(Self)
            .ok_or(Error::InvalidShareElement)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.to_bytes().as_ref().to_vec()
    }
}

#[cfg(feature = "serde")]
impl<G: GroupType> serde::Serialize for GroupElement<G> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serdect::array::serialize_hex_lower_or_bin(&self.0.to_bytes(), s)
    }
}

#[cfg(feature = "serde")]
impl<'de, G: GroupType> serde::Deserialize<'de> for GroupElement<G> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut repr = G::Repr::default();
        serdect::array::deserialize_hex_or_bin(repr.as_mut(), d)?;
        Option::from(G::from_bytes(&repr)).map(Self).ok_or_else(|| {
            serde::de::Error::custom("failed to deserialize group element from bytes")
        })
    }
}
