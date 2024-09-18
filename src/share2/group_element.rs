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
pub use group_element_serde::*;

#[cfg(feature = "serde")]
mod group_element_serde {
    use super::*;

    use serde::{
        de::{Error as DError, MapAccess, SeqAccess, Visitor},
        ser::SerializeStruct,
        Deserialize, Deserializer, Serialize, Serializer,
    };

    impl<I: ShareIdentifier, G: Group + GroupEncoding + Default> Serialize for ShareGroupElement<I, G> {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let hr = s.is_human_readable();
            let mut state = s.serialize_struct("ShareGroupElement", 2)?;
            if hr {
                state.serialize_field(
                    "identifier",
                    &hex::encode(self.identifier.serialize().as_ref()),
                )?;
                state.serialize_field(
                    "value",
                    &hex::encode(<ShareGroupElement<I, G> as Share>::serialize(self).as_ref()),
                )?;
            } else {
                state.serialize_field("identifier", &self.identifier.serialize().as_ref())?;
                state.serialize_field(
                    "value",
                    <ShareGroupElement<I, G> as Share>::serialize(self).as_ref(),
                )?;
            }
            state.end()
        }
    }

    impl<'de, I: ShareIdentifier, G: Group + GroupEncoding + Default> Deserialize<'de>
        for ShareGroupElement<I, G>
    {
        fn deserialize<D>(d: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct ShareGroupElementVisitor<I: ShareIdentifier, G: Group + GroupEncoding + Default> {
                _phantom: std::marker::PhantomData<(I, G)>,
            }

            impl<'de, I: ShareIdentifier, G: Group + GroupEncoding + Default> Visitor<'de>
                for ShareGroupElementVisitor<I, G>
            {
                type Value = ShareGroupElement<I, G>;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("struct ShareGroupElement")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let mut repr = G::Repr::default();
                    let identifier = I::from_slice(
                        &seq.next_element::<Vec<u8>>()?
                            .ok_or_else(|| DError::invalid_length(0, &self))?,
                    )
                    .map_err(DError::custom)?;
                    let bytes = seq
                        .next_element::<Vec<u8>>()?
                        .ok_or_else(|| DError::invalid_length(1, &self))?;
                    if repr.as_ref().len() != bytes.len() {
                        return Err(DError::custom("invalid share value length"));
                    }
                    repr.as_mut().copy_from_slice(bytes.as_slice());
                    Ok(ShareGroupElement {
                        identifier,
                        value: Option::from(G::from_bytes(&repr)).ok_or_else(|| {
                            DError::custom("invalid share value while deserializing")
                        })?,
                    })
                }

                fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                where
                    A: MapAccess<'de>,
                {
                    let mut identifier = None;
                    let mut value = None;
                    while let Some(key) = map.next_key()? {
                        match key {
                            "identifier" => {
                                identifier = Some(
                                    I::from_slice(
                                        &hex::decode(&map.next_value::<String>()?)
                                            .map_err(DError::custom)?,
                                    )
                                    .map_err(DError::custom)?,
                                );
                            }
                            "value" => {
                                let mut repr = G::Repr::default();
                                let temp = hex::decode(map.next_value::<String>()?)
                                    .map_err(DError::custom)?;
                                if repr.as_ref().len() != temp.len() {
                                    return Err(DError::custom("invalid share value length"));
                                }
                                repr.as_mut().copy_from_slice(&temp[..]);
                                value = Option::<G>::from(G::from_bytes(&repr));
                            }
                            _ => {
                                return Err(DError::unknown_field(key, &["identifier", "value"]));
                            }
                        }
                    }
                    let identifier =
                        identifier.ok_or_else(|| DError::missing_field("identifier"))?;
                    let value = value.ok_or_else(|| {
                        DError::missing_field("invalid share value while deserializing")
                    })?;
                    Ok(ShareGroupElement { identifier, value })
                }
            }

            d.deserialize_struct(
                "ShareGroupElement",
                &["identifier", "value"],
                ShareGroupElementVisitor {
                    _phantom: core::marker::PhantomData,
                },
            )
        }
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
