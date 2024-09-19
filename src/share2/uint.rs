use elliptic_curve::bigint::{ArrayEncoding, Encoding, Uint, Zero};

use super::*;
use crate::saturating::Saturating;

/// A share with a `Uint` value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShareUint<I: ShareIdentifier, const LIMBS: usize>
where
    Uint<LIMBS>: ArrayEncoding,
{
    /// The share identifier
    pub identifier: I,
    /// The share value
    pub value: Saturating<LIMBS>,
}

impl<I: ShareIdentifier, const LIMBS: usize> From<(I, Saturating<LIMBS>)> for ShareUint<I, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn from((identifier, value): (I, Saturating<LIMBS>)) -> Self {
        Self { identifier, value }
    }
}

impl<I: ShareIdentifier, const LIMBS: usize> From<ShareUint<I, LIMBS>> for (I, Saturating<LIMBS>)
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn from(share: ShareUint<I, LIMBS>) -> Self {
        (share.identifier, share.value)
    }
}

impl<I: ShareIdentifier, const LIMBS: usize> Share for ShareUint<I, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Serialization = <Uint<LIMBS> as Encoding>::Repr;
    type Identifier = I;
    type Value = Saturating<LIMBS>;

    fn with_identifier_and_value(identifier: I, value: Saturating<LIMBS>) -> Self {
        Self { identifier, value }
    }

    fn is_zero(&self) -> Choice {
        self.value.is_zero()
    }

    fn identifier(&self) -> &I {
        &self.identifier
    }

    fn identifier_mut(&mut self) -> &mut I {
        &mut self.identifier
    }

    fn serialize(&self) -> Self::Serialization {
        self.value.0.to_be_bytes()
    }

    fn deserialize(&mut self, serialized: &Self::Serialization) -> VsssResult<()> {
        self.value = Saturating(<Uint<LIMBS> as Encoding>::from_be_bytes(*serialized));
        Ok(())
    }

    fn value(&self) -> &Self::Value {
        &self.value
    }

    fn value_mut(&mut self) -> &mut Self::Value {
        &mut self.value
    }

    fn parse_slice(&mut self, slice: &[u8]) -> VsssResult<()> {
        if slice.len() != Uint::<LIMBS>::BYTES {
            return Err(Error::InvalidShare);
        }
        self.value = Saturating(Uint::<LIMBS>::from_be_slice(slice));
        Ok(())
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.serialize().as_ref().to_vec()
    }
}

#[cfg(feature = "serde")]
impl<I: ShareIdentifier + serde::Serialize, const LIMBS: usize> serde::Serialize
    for ShareUint<I, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (self.identifier(), self.value()).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, I: ShareIdentifier + serde::Deserialize<'de>, const LIMBS: usize> serde::Deserialize<'de>
    for ShareUint<I, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (identifier, value) = <(I, Saturating<LIMBS>)>::deserialize(d)?;
        Ok(Self { identifier, value })
    }
}
