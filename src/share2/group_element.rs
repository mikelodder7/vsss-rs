use elliptic_curve::{group::GroupEncoding, Group};
use subtle::Choice;

use super::*;

/// A share of a group element,
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShareGroupElement<I: ShareIdentifier, G: Group + GroupEncoding + Default> {
    /// The share identifier
    pub identifier: I,
    /// The share value
    pub value: G,
}

impl<I: ShareIdentifier, G: Group + GroupEncoding + Default> From<(I, G)>
    for ShareGroupElement<I, G>
{
    fn from((identifier, value): (I, G)) -> Self {
        Self { identifier, value }
    }
}

impl<I: ShareIdentifier, G: Group + GroupEncoding + Default> From<ShareGroupElement<I, G>>
    for (I, G)
{
    fn from(share: ShareGroupElement<I, G>) -> (I, G) {
        (share.identifier, share.value)
    }
}

impl<I: ShareIdentifier, G: Group + GroupEncoding + Default> Share for ShareGroupElement<I, G> {
    type Serialization = G::Repr;
    type Identifier = I;
    type Value = G;

    fn with_identifier_and_value(identifier: I, value: G) -> Self {
        Self { identifier, value }
    }

    fn is_zero(&self) -> Choice {
        self.value.is_identity()
    }

    fn identifier(&self) -> &Self::Identifier {
        &self.identifier
    }

    fn identifier_mut(&mut self) -> &mut Self::Identifier {
        &mut self.identifier
    }

    fn serialize(&self) -> Self::Serialization {
        self.value.to_bytes()
    }

    fn deserialize(&mut self, serialized: &Self::Serialization) -> VsssResult<()> {
        self.value = Option::from(G::from_bytes(serialized)).ok_or(Error::InvalidShare)?;
        Ok(())
    }

    fn value(&self) -> &Self::Value {
        &self.value
    }

    fn value_mut(&mut self) -> &mut Self::Value {
        &mut self.value
    }

    fn parse_slice(&mut self, slice: &[u8]) -> VsssResult<()> {
        let mut repr = G::Repr::default();
        if repr.as_ref().len() != slice.len() {
            return Err(Error::InvalidShare);
        }
        repr.as_mut().copy_from_slice(slice);
        self.deserialize(&repr)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.value.to_bytes().as_ref().to_vec()
    }
}

#[cfg(feature = "serde")]
struct ShareGroupSerde<G: Group + GroupEncoding + Default>(pub G);

#[cfg(feature = "serde")]
impl<G: Group + GroupEncoding + Default> serde::Serialize for ShareGroupSerde<G> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serdect::array::serialize_hex_lower_or_bin(&self.0.to_bytes(), s)
    }
}

#[cfg(feature = "serde")]
impl<'de, G: Group + GroupEncoding + Default> serde::Deserialize<'de> for ShareGroupSerde<G> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut repr = G::Repr::default();
        serdect::array::deserialize_hex_or_bin(repr.as_mut(), d)?;
        Option::from(G::from_bytes(&repr)).map(Self).ok_or_else(|| {
            serde::de::Error::custom("failed to deserialize group element from bytes")
        })
    }
}

#[cfg(feature = "serde")]
impl<I: ShareIdentifier + serde::Serialize, G: Group + GroupEncoding + Default> serde::Serialize
    for ShareGroupElement<I, G>
{
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let share = ShareGroupSerde(self.value);
        (self.identifier(), share).serialize(s)
    }
}

#[cfg(feature = "serde")]
impl<'de, I: ShareIdentifier + serde::Deserialize<'de>, G: Group + GroupEncoding + Default>
    serde::Deserialize<'de> for ShareGroupElement<I, G>
{
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (identifier, ShareGroupSerde(value)) = <(I, ShareGroupSerde<G>)>::deserialize(d)?;
        Ok(Self { identifier, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "serde")]
    #[test]
    fn serde_share_group_element() {
        let share = ShareGroupElement::<IdentifierU8, k256::ProjectivePoint>::from((
            IdentifierU8::from(1),
            k256::ProjectivePoint::GENERATOR,
        ));
        let serialized = serde_json::to_string(&share).unwrap();
        let res = serde_json::from_str::<ShareGroupElement<IdentifierU8, k256::ProjectivePoint>>(
            &serialized,
        );
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), share);

        let serialized = serde_bare::to_vec(&share).unwrap();
        let res = serde_bare::from_slice::<ShareGroupElement<IdentifierU8, k256::ProjectivePoint>>(
            &serialized,
        );
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), share);
    }
}
