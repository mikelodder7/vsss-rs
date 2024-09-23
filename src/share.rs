use super::*;
use core::fmt::Debug;

/// A share.
pub trait Share: Sized + Debug + Eq + PartialEq + Clone + Default {
    /// The identifier type for the share.
    type Identifier: ShareIdentifier;

    /// The value type for the share.
    type Value: ShareElement
        + for<'a> From<&'a Self::Identifier>
        + for<'a> core::ops::Mul<&'a Self::Identifier, Output = Self::Value>;

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
    V: ShareElement + for<'a> From<&'a I> + for<'a> core::ops::Mul<&'a I, Output = V>,
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
    V: ShareElement + for<'a> From<&'a I> + for<'a> core::ops::Mul<&'a I, Output = V>,
{
    /// The share identifier
    pub identifier: I,
    /// The share value
    pub value: V,
}

impl<I, V> Share for DefaultShare<I, V>
where
    I: ShareIdentifier,
    V: ShareElement + for<'a> From<&'a I> + for<'a> core::ops::Mul<&'a I, Output = V>,
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
