use super::*;
use core::fmt::Debug;

/// A share.
pub trait Share:
    Sized
    + Debug
    + Eq
    + PartialEq
    + Clone
    + Default
    + From<(Self::Identifier, Self::Value)>
    + Into<(Self::Identifier, Self::Value)>
{
    /// The share identifier type.
    type Identifier: ShareIdentifier;
    /// The share value type.
    type Value: ShareElement + From<Self::Identifier>;

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

impl<I: ShareIdentifier, E: ShareElement + From<I>> Share for (I, E) {
    type Identifier = I;
    type Value = E;

    fn with_identifier_and_value(identifier: Self::Identifier, value: Self::Value) -> Self {
        (identifier, value)
    }

    fn identifier(&self) -> &Self::Identifier {
        &self.0
    }

    fn identifier_mut(&mut self) -> &mut Self::Identifier {
        &mut self.0
    }

    fn value(&self) -> &Self::Value {
        &self.1
    }

    fn value_mut(&mut self) -> &mut Self::Value {
        &mut self.1
    }
}

// #[cfg(any(feature = "alloc", feature = "std"))]
// mod biguint;
// mod prime_field;
// mod primitive;
// mod residue;
// mod uint;
//
// #[cfg(any(feature = "alloc", feature = "std"))]
// pub use biguint::*;
// pub use prime_field::*;
// pub use primitive::*;
// pub use residue::*;
// pub use uint::*;
