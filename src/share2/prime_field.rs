use elliptic_curve::PrimeField;
use subtle::Choice;

use super::*;

/// A share of a prime field element
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SharePrimeField<I: ShareElement, F: PrimeField> {
    /// The share identifier
    pub identifier: I,
    /// The share value
    pub value: F,
}

impl<I: ShareElement, F: PrimeField> From<(I, F)> for SharePrimeField<I, F> {
    fn from((identifier, value): (I, F)) -> Self {
        Self { identifier, value }
    }
}

impl<I: ShareElement, F: PrimeField> From<SharePrimeField<I, F>> for (I, F) {
    fn from(share: SharePrimeField<I, F>) -> Self {
        (share.identifier, share.value)
    }
}

impl<I: ShareElement, F: PrimeField> Share for SharePrimeField<I, F> {
    type Serialization = F::Repr;
    type Identifier = I;
    type Value = F;

    fn with_identifier_and_value(identifier: I, value: F) -> Self {
        Self { identifier, value }
    }

    fn is_zero(&self) -> Choice {
        self.value.is_zero()
    }

    fn identifier(&self) -> &Self::Identifier {
        &self.identifier
    }

    fn identifier_mut(&mut self) -> &mut Self::Identifier {
        &mut self.identifier
    }

    fn serialize(&self) -> Self::Serialization {
        self.value.to_repr()
    }

    fn deserialize(&mut self, serialized: &Self::Serialization) -> VsssResult<()> {
        self.value = Option::from(F::from_repr(*serialized)).ok_or(Error::InvalidShare)?;
        Ok(())
    }

    fn value(&self) -> &Self::Value {
        &self.value
    }

    fn value_mut(&mut self) -> &mut Self::Value {
        &mut self.value
    }

    fn parse_slice(&mut self, slice: &[u8]) -> VsssResult<()> {
        let mut repr = F::Repr::default();
        if slice.len() != repr.as_ref().len() {
            return Err(Error::InvalidShare);
        }
        repr.as_mut().copy_from_slice(slice);
        self.deserialize(&repr)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.value.to_repr().as_ref().to_vec()
    }
}

#[cfg(feature = "serde")]
impl<I: ShareElement + serde::Serialize, F: PrimeField> serde::Serialize
    for SharePrimeField<I, F>
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let id2 = IdentifierPrimeField(self.value);
        (self.identifier(), id2).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, I: ShareElement + serde::Deserialize<'de>, F: PrimeField> serde::Deserialize<'de>
    for SharePrimeField<I, F>
{
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (identifier, IdentifierPrimeField(value)) =
            <(I, IdentifierPrimeField<F>)>::deserialize(d)?;
        Ok(Self { identifier, value })
    }
}
