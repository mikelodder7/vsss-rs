
use elliptic_curve::PrimeField;
use subtle::Choice;

use super::*;
use crate::*;

impl<F: PrimeField + Sized> Share for (F, F) {
    type Serialization = F::Repr;
    type Identifier = F;
    type Value = F;

    fn zero() -> Self {
        (F::ZERO, F::ZERO)
    }

    fn with_identifier_and_value(identifier: F, value: &Self::Serialization) -> VsssResult<Self> {
        let value = Option::from(F::from_repr(*value)).ok_or(Error::InvalidShare)?;
        Ok((identifier, value))
    }

    fn is_zero(&self) -> Choice {
        self.1.is_zero()
    }

    fn identifier(&self) -> &Self::Identifier {
        &self.0
    }

    fn identifier_mut(&mut self) -> &mut Self::Identifier {
        &mut self.0
    }

    fn serialize(&self) -> Self::Serialization {
        self.1.to_repr()
    }

    fn deserialize(&mut self, serialized: &Self::Serialization) -> VsssResult<()> {
        self.1 = Option::from(F::from_repr(*serialized)).ok_or(Error::InvalidShare)?;
        Ok(())
    }

    fn value(&self) -> &Self::Value {
        &self.1
    }

    fn value_mut(&mut self) -> &mut Self::Value {
        &mut self.1
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.1.to_repr().as_ref().to_vec()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShareTuple<I: ShareIdentifier, F: PrimeField>(pub (I, F));

impl<I: ShareIdentifier, F: PrimeField> Share for ShareTuple<I, F> {
    type Serialization = F::Repr;
    type Identifier = I;
    type Value = F;

    fn zero() -> Self {
        Self((I::default(), F::ZERO))
    }

    fn with_identifier_and_value(identifier: I, value: &Self::Serialization) -> VsssResult<Self> {
        let value = Option::from(F::from_repr(*value)).ok_or(Error::InvalidShare)?;
        Ok(Self((identifier, value)))
    }

    fn is_zero(&self) -> Choice {
        self.0.1.is_zero()
    }

    fn identifier(&self) -> &Self::Identifier {
        &self.0.0
    }

    fn identifier_mut(&mut self) -> &mut Self::Identifier {
        &mut self.0.0
    }

    fn serialize(&self) -> Self::Serialization {
        self.0.1.to_repr()
    }

    fn deserialize(&mut self, serialized: &Self::Serialization) -> VsssResult<()> {
        self.0.1 = Option::from(F::from_repr(*serialized)).ok_or(Error::InvalidShare)?;
        Ok(())
    }

    fn value(&self) -> &Self::Value {
        &self.0.1
    }

    fn value_mut(&mut self) -> &mut Self::Value {
        &mut self.0.1
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.0.1.to_repr().as_ref().to_vec()
    }
}