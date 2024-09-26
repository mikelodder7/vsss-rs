use super::*;
use core::{
    cmp::Ordering,
    fmt::Debug,
    hash::{Hash, Hasher},
    ops::Mul,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A share.
pub trait Share: Sized + Debug + Eq + PartialEq + Clone + Default {
    /// The identifier type for the share.
    type Identifier: ShareIdentifier;

    /// The value type for the share.
    type Value: ShareElement
        + for<'a> From<&'a Self::Identifier>
        + for<'a> Mul<&'a Self::Identifier, Output = Self::Value>;

    /// A new share with a given value
    fn with_identifier_and_value(identifier: Self::Identifier, value: Self::Value) -> Self;
    /// The identifier for this share
    fn identifier(&self) -> &Self::Identifier;
    /// The mutable identifier for this share
    fn identifier_mut(&mut self) -> &mut Self::Identifier;
    /// Serialize the share value.
    fn value(&self) -> &Self::Value;
    /// The mutable share value
    fn value_mut(&mut self) -> &mut Self::Value;
}

impl<I, V> Share for (I, V)
where
    I: ShareIdentifier,
    V: ShareElement + for<'a> From<&'a I> + for<'a> Mul<&'a I, Output = V>,
{
    type Identifier = I;
    type Value = V;

    fn with_identifier_and_value(identifier: I, value: V) -> Self {
        (identifier, value)
    }

    fn identifier(&self) -> &I {
        &self.0
    }

    fn identifier_mut(&mut self) -> &mut I {
        &mut self.0
    }

    fn value(&self) -> &V {
        &self.1
    }

    fn value_mut(&mut self) -> &mut V {
        &mut self.1
    }
}

/// A default share implementation providing named fields for the identifier and value.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct DefaultShare<I, V>
where
    I: ShareIdentifier,
    V: ShareElement + for<'a> From<&'a I> + for<'a> Mul<&'a I, Output = V>,
{
    /// The share identifier
    pub identifier: I,
    /// The share value
    pub value: V,
}

impl<I, V> Copy for DefaultShare<I, V>
where
    I: ShareIdentifier + Copy,
    V: ShareElement + for<'a> From<&'a I> + for<'a> Mul<&'a I, Output = V> + Copy,
{
}

impl<I, V> Ord for DefaultShare<I, V>
where
    I: ShareIdentifier + Ord + PartialOrd,
    V: ShareElement + for<'a> From<&'a I> + for<'a> Mul<&'a I, Output = V>,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.identifier.cmp(&other.identifier)
    }
}

impl<I, V> PartialOrd for DefaultShare<I, V>
where
    I: ShareIdentifier + Ord + PartialOrd,
    V: ShareElement + for<'a> From<&'a I> + for<'a> Mul<&'a I, Output = V>,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.identifier.partial_cmp(&other.identifier)
    }
}

impl<I, V> Hash for DefaultShare<I, V>
where
    I: ShareIdentifier + Hash,
    V: ShareElement + for<'a> From<&'a I> + for<'a> Mul<&'a I, Output = V>,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.identifier.hash(state);
    }
}

impl<I, V> Zeroize for DefaultShare<I, V>
where
    I: ShareIdentifier + Zeroize,
    V: ShareElement + for<'a> From<&'a I> + for<'a> Mul<&'a I, Output = V> + Zeroize,
{
    fn zeroize(&mut self) {
        self.identifier.zeroize();
        self.value.zeroize();
    }
}

impl<I, V> ZeroizeOnDrop for DefaultShare<I, V>
where
    I: ShareIdentifier + ZeroizeOnDrop,
    V: ShareElement + for<'a> From<&'a I> + for<'a> Mul<&'a I, Output = V> + ZeroizeOnDrop,
{
}

#[cfg(feature = "serde")]
impl<I, V> serde::Serialize for DefaultShare<I, V>
where
    I: ShareIdentifier + serde::Serialize,
    V: ShareElement + for<'a> From<&'a I> + for<'a> Mul<&'a I, Output = V> + serde::Serialize,
{
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;

        let mut state = s.serialize_struct("DefaultShare", 2)?;
        state.serialize_field("identifier", &self.identifier)?;
        state.serialize_field("value", &self.value)?;
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de, I, V> serde::Deserialize<'de> for DefaultShare<I, V>
where
    I: ShareIdentifier + serde::Deserialize<'de>,
    V: ShareElement
        + for<'a> From<&'a I>
        + for<'a> Mul<&'a I, Output = V>
        + serde::Deserialize<'de>,
{
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DefaultShareVisitor<'de, I, V>
        where
            I: ShareIdentifier + serde::Deserialize<'de>,
            V: ShareElement
                + for<'a> From<&'a I>
                + for<'a> Mul<&'a I, Output = V>
                + serde::Deserialize<'de>,
        {
            marker: core::marker::PhantomData<(&'de (), DefaultShare<I, V>)>,
        }

        impl<'de, I, V> serde::de::Visitor<'de> for DefaultShareVisitor<'de, I, V>
        where
            I: ShareIdentifier + serde::Deserialize<'de>,
            V: ShareElement
                + for<'a> From<&'a I>
                + for<'a> Mul<&'a I, Output = V>
                + serde::Deserialize<'de>,
        {
            type Value = DefaultShare<I, V>;

            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "struct DefaultShare")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let identifier = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let value = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                Ok(DefaultShare { identifier, value })
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut identifier = None;
                let mut value = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        "identifier" => {
                            if identifier.is_some() {
                                return Err(serde::de::Error::duplicate_field("identifier"));
                            }
                            identifier = Some(map.next_value()?);
                        }
                        "value" => {
                            if value.is_some() {
                                return Err(serde::de::Error::duplicate_field("value"));
                            }
                            value = Some(map.next_value()?);
                        }
                        _ => {
                            return Err(serde::de::Error::unknown_field(
                                key,
                                &["identifier", "value"],
                            ));
                        }
                    }
                }
                let identifier =
                    identifier.ok_or_else(|| serde::de::Error::missing_field("identifier"))?;
                let value = value.ok_or_else(|| serde::de::Error::missing_field("value"))?;
                Ok(DefaultShare { identifier, value })
            }
        }

        d.deserialize_struct(
            "DefaultShare",
            &["identifier", "value"],
            DefaultShareVisitor {
                marker: core::marker::PhantomData,
            },
        )
    }
}

impl<I, V> Share for DefaultShare<I, V>
where
    I: ShareIdentifier,
    V: ShareElement + for<'a> From<&'a I> + for<'a> Mul<&'a I, Output = V>,
{
    type Identifier = I;
    type Value = V;

    fn with_identifier_and_value(identifier: Self::Identifier, value: Self::Value) -> Self {
        Self { identifier, value }
    }

    fn identifier(&self) -> &Self::Identifier {
        &self.identifier
    }

    fn identifier_mut(&mut self) -> &mut Self::Identifier {
        &mut self.identifier
    }

    fn value(&self) -> &Self::Value {
        &self.value
    }

    fn value_mut(&mut self) -> &mut Self::Value {
        &mut self.value
    }
}
