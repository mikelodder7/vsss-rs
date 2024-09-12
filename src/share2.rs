use core::{
    fmt::Debug,
    ops::{Add, AddAssign, Sub, SubAssign, Mul, MulAssign},
};
use subtle::Choice;

use crate::*;

pub trait Share:
    Sized
    + Debug
    + Eq
    + PartialEq
    + Clone
    + Default
{
    /// The serialized form of the share identifier.
    type Serialization: AsRef<[u8]> + AsMut<[u8]> + 'static;
    /// The share identifier type.
    type Identifier: ShareIdentifier;
    /// The share value type.
    type Value: Debug + Clone + Default;

    /// A new empty share
    fn zero() -> Self;
    /// A new share with a given value
    fn with_identifier_and_value(identifier: Self::Identifier, value: &Self::Serialization) -> VsssResult<Self>;
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
    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Serialize the share identifier to a byte vector.
    fn to_vec(&self) -> Vec<u8>;
}

mod prime_field;
mod group_element;