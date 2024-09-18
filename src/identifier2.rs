//! Share identifiers for secret sharing schemes.

#[cfg(any(feature = "alloc", feature = "std"))]
mod biguint;
mod prime_field;
mod primitive;
mod residue;
mod uint;

#[cfg(any(feature = "alloc", feature = "std"))]
pub use biguint::*;
pub use prime_field::*;
pub use primitive::*;
pub use residue::*;
pub use uint::*;

use crate::*;

use core::{
    fmt::Debug,
    ops::{Add, AddAssign, Deref, DerefMut, Mul, MulAssign, Sub, SubAssign},
};
use elliptic_curve::bigint::{Encoding, Random, Zero as CryptoZero};
use rand_core::{CryptoRng, RngCore};
use subtle::Choice;

/// A value used to represent the identifier for secret shares.
pub trait ShareIdentifier:
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
    /// The serialized form of the share identifier.
    type Serialization: AsRef<[u8]> + AsMut<[u8]> + 'static;
    /// The inner type of the share identifier.
    type Inner: Sized
        + Debug
        + Eq
        + PartialEq
        + Clone
        + Default
        + 'static
        + Add<Self::Inner, Output = Self::Inner>
        + Sub<Self::Inner, Output = Self::Inner>
        + Mul<Self::Inner, Output = Self::Inner>
        + AddAssign
        + SubAssign
        + MulAssign
        + for<'a> AddAssign<&'a Self::Inner>
        + for<'a> SubAssign<&'a Self::Inner>
        + for<'a> MulAssign<&'a Self::Inner>;
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
    /// Generate a random share identifier.
    fn random(rng: impl RngCore + CryptoRng) -> Self;
    /// Invert the share identifier.
    fn invert(&self) -> VsssResult<Self>;
    /// Create a share identifier from a byte slice.
    fn from_slice(slice: &[u8]) -> VsssResult<Self>;
    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Serialize the share identifier to a byte vector.
    fn to_vec(&self) -> Vec<u8>;
}
