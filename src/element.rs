//! Share identifiers for secret sharing schemes.

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

use crate::*;

use core::{
    fmt::Debug,
    ops::{Add, AddAssign, Deref, DerefMut, Mul, MulAssign, Neg, Sub, SubAssign},
};
use elliptic_curve::bigint::{Encoding, Random, Zero as CryptoZero};
use rand_core::{CryptoRng, RngCore};
use subtle::Choice;

/// A value used to represent a share element for secret shares.
/// A share element can either be the share identifier or the share value.
pub trait ShareElement:
    Sized
    + Clone
    + Default
    + Debug
    + Eq
    + PartialEq
    + Deref<Target = Self::Inner>
    + DerefMut<Target = Self::Inner>
    + AsRef<Self::Inner>
    + AsMut<Self::Inner>
    + From<Self::Inner>
{
    /// The serialized form of the share element.
    type Serialization: AsRef<[u8]> + AsMut<[u8]> + 'static;
    /// The inner type of the share element.
    type Inner: ShareElementInner;

    /// Generate a random share element.
    fn random(rng: impl RngCore + CryptoRng) -> Self;
    /// Defines an additive identity element for the share identifier.
    fn zero() -> Self;
    /// Defines a multiplicative identity element for the share identifier.
    fn one() -> Self;
    /// Check if the share identifier is zero.
    fn is_zero(&self) -> Choice;
    /// Serialize the share identifier.
    fn serialize(&self) -> Self::Serialization;
    /// Deserialize the share identifier.
    fn deserialize(serialized: &Self::Serialization) -> VsssResult<Self>;
    /// Attempt to convert the byte sequence to a share element.
    fn from_slice(slice: &[u8]) -> VsssResult<Self>;
    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Serialize the share identifier to a byte vector.
    fn to_vec(&self) -> Vec<u8>;
}

/// A share identifier for secret sharing schemes.
pub trait ShareIdentifier: ShareElement<Inner: ShareIdentifierInner> {
    /// Add to the identifier by the increment value.
    fn inc(&mut self, increment: &Self);

    /// Invert the share identifier.
    fn invert(&self) -> VsssResult<Self>;
}

/// Objects that represent the ability to verify shamir shares
pub trait ShareVerifier<S: Share>:
    ShareElement
    + Copy
    + Add<Output = Self>
    + Sub<Output = Self>
    + AddAssign
    + SubAssign
    + Neg<Output = Self>
    + Mul<S::Identifier, Output = Self>
    + Mul<S::Value, Output = Self>
    + MulAssign<S::Identifier>
    + MulAssign<S::Value>
    + for<'a> Mul<&'a S::Identifier, Output = Self>
    + for<'a> Mul<&'a S::Value, Output = Self>
    + for<'a> MulAssign<&'a S::Identifier>
    + for<'a> MulAssign<&'a S::Value>
{
}

impl<
        S: Share,
        SV: ShareElement
            + Copy
            + Add<Output = Self>
            + Sub<Output = Self>
            + AddAssign
            + SubAssign
            + Neg<Output = Self>
            + Mul<S::Identifier, Output = Self>
            + Mul<S::Value, Output = Self>
            + MulAssign<S::Identifier>
            + MulAssign<S::Value>
            + for<'a> Mul<&'a S::Identifier, Output = Self>
            + for<'a> Mul<&'a S::Value, Output = Self>
            + for<'a> MulAssign<&'a S::Identifier>
            + for<'a> MulAssign<&'a S::Value>,
    > ShareVerifier<S> for SV
{
}

/// A share element inner type for secret sharing schemes.
pub trait ShareElementInner:
    Sized
    + Debug
    + Eq
    + PartialEq
    + Clone
    + Default
    + 'static
    + Add<Output = Self>
    + Sub<Output = Self>
    + AddAssign
    + SubAssign
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + for<'a> AddAssign<&'a Self>
    + for<'a> SubAssign<&'a Self>
{
}

impl<
        I: Sized
            + Debug
            + Eq
            + PartialEq
            + Clone
            + Default
            + 'static
            + Add<Output = Self>
            + Sub<Output = Self>
            + AddAssign
            + SubAssign
            + for<'a> Add<&'a Self, Output = Self>
            + for<'a> Sub<&'a Self, Output = Self>
            + for<'a> AddAssign<&'a Self>
            + for<'a> SubAssign<&'a Self>,
    > ShareElementInner for I
{
}

/// A share identifier inner type for secret sharing schemes.
pub trait ShareIdentifierInner:
    ShareElementInner
    + Mul<Output = Self>
    + MulAssign
    + for<'a> Mul<&'a Self, Output = Self>
    + for<'a> MulAssign<&'a Self>
{
}

impl<
        E: ShareElementInner
            + Mul<Output = Self>
            + MulAssign
            + for<'a> Mul<&'a Self, Output = Self>
            + for<'a> MulAssign<&'a Self>,
    > ShareIdentifierInner for E
{
}
