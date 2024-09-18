use super::*;

/// A share identifier represented as a primitive integer.
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub struct SharePrimitive<I: ShareIdentifier, P: Primitive<BYTES>, const BYTES: usize> {
    /// The share identifier.
    pub identifier: I,
    /// The share value.
    pub value: P,
}

impl<I: ShareIdentifier, P: Primitive<BYTES>, const BYTES: usize> From<(I, P)>
    for SharePrimitive<I, P, BYTES>
{
    fn from((identifier, value): (I, P)) -> Self {
        Self { identifier, value }
    }
}

impl<I: ShareIdentifier, P: Primitive<BYTES>, const BYTES: usize> From<SharePrimitive<I, P, BYTES>>
    for (I, P)
{
    fn from(share: SharePrimitive<I, P, BYTES>) -> Self {
        (share.identifier, share.value)
    }
}

impl<I: ShareIdentifier, P: Primitive<BYTES>, const BYTES: usize> Share
    for SharePrimitive<I, P, BYTES>
{
    type Serialization = [u8; BYTES];
    type Identifier = I;
    type Value = P;

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
        self.value.to_fixed_array()
    }

    fn deserialize(&mut self, serialized: &Self::Serialization) -> VsssResult<()> {
        self.value = P::from_fixed_array(serialized);
        Ok(())
    }

    fn value(&self) -> &Self::Value {
        &self.value
    }

    fn value_mut(&mut self) -> &mut Self::Value {
        &mut self.value
    }

    fn parse_slice(&mut self, slice: &[u8]) -> VsssResult<()> {
        let mut repr = P::ZERO.to_be_bytes();
        if slice.len() != repr.as_ref().len() {
            return Err(Error::InvalidShareIdentifier);
        }
        repr.as_mut().copy_from_slice(slice);
        self.value = P::from_be_bytes(&repr);
        Ok(())
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.serialize().to_vec()
    }
}
