use core::fmt::Debug;
use subtle::Choice;

use super::*;

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
    /// The serialized form of the share value.
    type Serialization: AsRef<[u8]> + AsMut<[u8]> + 'static;
    /// The share identifier type.
    type Identifier: ShareIdentifier;
    /// The share value type.
    type Value: Sized + Debug + Eq + PartialEq + Clone + Default + 'static;

    /// A new share with a given value
    fn with_identifier_and_value(identifier: Self::Identifier, value: Self::Value) -> Self;
    /// True if the share value is zero
    fn is_zero(&self) -> Choice;
    /// The identifier for this share
    fn identifier(&self) -> &Self::Identifier;
    /// The mutable identifier for this share
    fn identifier_mut(&mut self) -> &mut Self::Identifier;
    /// Serialize the share value.
    fn serialize(&self) -> Self::Serialization;
    /// Deserialize the value into this share.
    fn deserialize(&mut self, serialized: &Self::Serialization) -> VsssResult<()>;
    /// The share value
    fn value(&self) -> &Self::Value;
    /// The mutable share value
    fn value_mut(&mut self) -> &mut Self::Value;
    /// Read the share value from a slice of bytes
    fn parse_slice(&mut self, slice: &[u8]) -> VsssResult<()>;
    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Serialize the share identifier to a byte vector.
    fn to_vec(&self) -> Vec<u8>;
}

#[cfg(any(feature = "alloc", feature = "std"))]
mod biguint;
mod group_element;
mod prime_field;
mod primitive;
mod residue;
mod uint;

#[cfg(any(feature = "alloc", feature = "std"))]
pub use biguint::*;
pub use group_element::*;
pub use prime_field::*;
pub use primitive::*;
pub use residue::*;
pub use uint::*;
