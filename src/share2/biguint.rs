use super::*;

use num::traits::Zero;
use num::BigUint;
use subtle::Choice;

/// A share value represented as a big unsigned number
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ShareBigUint<I: ShareElement> {
    /// The share identifier
    pub identifier: I,
    /// The share value
    pub value: BigUint,
}

impl<I: ShareElement> From<(I, BigUint)> for ShareBigUint<I> {
    fn from((identifier, value): (I, BigUint)) -> Self {
        Self { identifier, value }
    }
}

impl<I: ShareElement> From<ShareBigUint<I>> for (I, BigUint) {
    fn from(share: ShareBigUint<I>) -> Self {
        (share.identifier, share.value)
    }
}

impl<I: ShareElement> Share for ShareBigUint<I> {
    type Serialization = Vec<u8>;
    type Identifier = I;
    type Value = BigUint;

    fn with_identifier_and_value(identifier: Self::Identifier, value: Self::Value) -> Self {
        Self { identifier, value }
    }

    fn is_zero(&self) -> Choice {
        Choice::from(if self.value.is_zero() { 1 } else { 0 })
    }

    fn identifier(&self) -> &Self::Identifier {
        &self.identifier
    }

    fn identifier_mut(&mut self) -> &mut Self::Identifier {
        &mut self.identifier
    }

    fn serialize(&self) -> Self::Serialization {
        self.value.to_bytes_be()
    }

    fn deserialize(&mut self, serialized: &Self::Serialization) -> VsssResult<()> {
        self.value = BigUint::from_bytes_be(serialized);
        Ok(())
    }

    fn value(&self) -> &Self::Value {
        &self.value
    }

    fn value_mut(&mut self) -> &mut Self::Value {
        &mut self.value
    }

    fn parse_slice(&mut self, slice: &[u8]) -> VsssResult<()> {
        self.value = BigUint::from_bytes_be(slice);
        Ok(())
    }

    fn to_vec(&self) -> Vec<u8> {
        self.value.to_bytes_be()
    }
}

#[cfg(feature = "serde")]
impl<I: ShareElement + serde::Serialize> serde::Serialize for ShareBigUint<I> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (self.identifier(), self.value()).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, I: ShareElement + serde::Deserialize<'de>> serde::Deserialize<'de>
    for ShareBigUint<I>
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (identifier, value) = <(I, BigUint)>::deserialize(deserializer)?;
        Ok(Self { identifier, value })
    }
}
