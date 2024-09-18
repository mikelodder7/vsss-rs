use core::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};
use rand_core::{CryptoRng, RngCore};
use subtle::Choice;

use super::*;
use crate::*;

/// A share identifier represented as u8
pub type IdentifierU8 = IdentifierPrimitive<u8, 1>;
/// A share identifier represented as u16
pub type IdentifierU16 = IdentifierPrimitive<u16, 2>;
/// A share identifier represented as u32
pub type IdentifierU32 = IdentifierPrimitive<u32, 4>;
/// A share identifier represented as u64
pub type IdentifierU64 = IdentifierPrimitive<u64, 8>;
#[cfg(target_pointer_width = "64")]
/// A share identifier represent as u128
pub type IdentifierU128 = IdentifierPrimitive<u128, 16>;
/// A share identifier represented as usize
pub type IdentifierUsize = IdentifierPrimitive<usize, USIZE_BYTES>;
/// A share identifier represented as i8
pub type IdentifierI8 = IdentifierPrimitive<i8, 1>;
/// A share identifier represented as i16
pub type IdentifierI16 = IdentifierPrimitive<i16, 2>;
/// A share identifier represented as i32
pub type IdentifierI32 = IdentifierPrimitive<i32, 4>;
/// A share identifier represented as i64
pub type IdentifierI64 = IdentifierPrimitive<i64, 8>;
#[cfg(target_pointer_width = "64")]
/// A share identifier represented as i128
pub type IdentifierI128 = IdentifierPrimitive<i128, 16>;
/// A share identifier represented as isize
pub type IdentifierIsize = IdentifierPrimitive<isize, ISIZE_BYTES>;

/// A share identifier represented as a primitive integer.
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub struct IdentifierPrimitive<P: Primitive<BYTES>, const BYTES: usize>(pub P);

impl<P: Primitive<BYTES>, const BYTES: usize> Deref for IdentifierPrimitive<P, BYTES> {
    type Target = P;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<P: Primitive<BYTES>, const BYTES: usize> DerefMut for IdentifierPrimitive<P, BYTES> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<P: Primitive<BYTES>, const BYTES: usize> AsRef<P> for IdentifierPrimitive<P, BYTES> {
    fn as_ref(&self) -> &P {
        &self.0
    }
}

impl<P: Primitive<BYTES>, const BYTES: usize> AsMut<P> for IdentifierPrimitive<P, BYTES> {
    fn as_mut(&mut self) -> &mut P {
        &mut self.0
    }
}

impl<P: Primitive<BYTES>, const BYTES: usize> From<P> for IdentifierPrimitive<P, BYTES> {
    fn from(value: P) -> Self {
        Self(value)
    }
}

impl<P: Primitive<BYTES>, const BYTES: usize> ShareIdentifier for IdentifierPrimitive<P, BYTES> {
    type Serialization = [u8; BYTES];
    type Inner = P;

    fn zero() -> Self {
        Self(P::ZERO)
    }

    fn one() -> Self {
        Self(P::ONE)
    }

    fn is_zero(&self) -> Choice {
        Choice::from(if self.0.is_zero() { 1 } else { 0 })
    }

    fn serialize(&self) -> Self::Serialization {
        self.0.to_fixed_array()
    }

    fn deserialize(serialized: &Self::Serialization) -> VsssResult<Self> {
        Self::from_slice(&serialized[..])
    }

    fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        let mut repr = [0u8; BYTES];
        rng.fill_bytes(repr.as_mut());
        Self(P::from_fixed_array(&repr))
    }

    fn invert(&self) -> VsssResult<Self> {
        Ok(Self(P::ONE / self.0))
    }

    fn from_slice(slice: &[u8]) -> VsssResult<Self> {
        if slice.len() != BYTES {
            return Err(Error::InvalidShareIdentifier);
        }
        let repr: [u8; BYTES] = slice.try_into().unwrap();
        Ok(Self(P::from_fixed_array(&repr)))
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.serialize().to_vec()
    }
}
