use core::{
    fmt::{self, Display, Formatter},
    ops::{Deref, DerefMut},
};
use rand_core::{CryptoRng, RngCore};
use subtle::Choice;
use zeroize::*;

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
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct IdentifierPrimitive<P: Primitive<BYTES>, const BYTES: usize>(pub P);

impl<P: Primitive<BYTES>, const BYTES: usize> Display for IdentifierPrimitive<P, BYTES> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        for b in &self.0.to_fixed_array() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

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

impl<P: Primitive<BYTES>, const BYTES: usize> DefaultIsZeroes for IdentifierPrimitive<P, BYTES> {}

impl<P: Primitive<BYTES>, const BYTES: usize> ShareElement for IdentifierPrimitive<P, BYTES> {
    type Serialization = [u8; BYTES];
    type Inner = P;

    fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        let mut repr = [0u8; BYTES];
        rng.fill_bytes(repr.as_mut());
        Self(P::from_fixed_array(&repr))
    }

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

    fn from_slice(slice: &[u8]) -> VsssResult<Self> {
        if slice.len() != BYTES {
            return Err(Error::InvalidShareElement);
        }
        let repr: [u8; BYTES] = slice.try_into().unwrap();
        Ok(Self(P::from_fixed_array(&repr)))
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.serialize().to_vec()
    }
}

impl<P: Primitive<BYTES>, const BYTES: usize> ShareIdentifier for IdentifierPrimitive<P, BYTES> {
    fn inc(&mut self, increment: &Self) {
        self.0 = self.0.saturating_add(increment.0);
    }

    fn invert(&self) -> VsssResult<Self> {
        P::ONE
            .checked_div(&self.0)
            .map(Self)
            .ok_or(Error::InvalidShareElement)
    }
}

impl<P: Primitive<BYTES>, const BYTES: usize> IdentifierPrimitive<P, BYTES> {
    /// Returns the additive identity element.
    pub const ZERO: Self = Self(P::ZERO);
    /// Returns the multiplicative identity element.
    pub const ONE: Self = Self(P::ONE);
}

#[cfg(feature = "serde")]
macro_rules! impl_serde {
    ($($identifier:ident => $primitive:ty),+$(,)*) => {
        $(
            impl serde::Serialize for $identifier {
                fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                    self.0.serialize(s)
                }
            }

            impl<'de> serde::Deserialize<'de> for $identifier {
                fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                    <$primitive>::deserialize(d).map(IdentifierPrimitive)
                }
            }
        )+
    };
}

#[cfg(feature = "serde")]
impl_serde!(
    IdentifierU8 => u8,
    IdentifierU16 => u16,
    IdentifierU32 => u32,
    IdentifierU64 => u64,
    IdentifierI8 => i8,
    IdentifierI16 => i16,
    IdentifierI32 => i32,
    IdentifierI64 => i64,
);

#[cfg(all(feature = "serde", target_pointer_width = "64"))]
impl_serde!(
    IdentifierU128 => u128,
    IdentifierI128 => i128,
);
#[cfg(all(feature = "serde", target_pointer_width = "32"))]
pub use serde_32::*;

#[cfg(all(feature = "serde", target_pointer_width = "64"))]
mod serde_64 {
    use super::*;
    use serde::*;

    impl Serialize for IdentifierUsize {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            (self.0 as u64).serialize(s)
        }
    }

    impl<'de> Deserialize<'de> for IdentifierUsize {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            <u64>::deserialize(d).map(|x| IdentifierPrimitive(x as usize))
        }
    }

    impl Serialize for IdentifierIsize {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            (self.0 as i64).serialize(s)
        }
    }

    impl<'de> Deserialize<'de> for IdentifierIsize {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            <i64>::deserialize(d).map(|x| IdentifierPrimitive(x as isize))
        }
    }
}

#[cfg(all(feature = "serde", target_pointer_width = "32"))]
mod serde_32 {
    use super::*;
    use serde::*;

    impl Serialize for IdentifierUsize {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            (self.0 as u32).serialize(s)
        }
    }

    impl<'de> Deserialize<'de> for IdentifierUsize {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            <u32>::deserialize(d).map(|x| IdentifierPrimitive(x as usize))
        }
    }

    impl Serialize for IdentifierIsize {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            (self.0 as i32).serialize(s)
        }
    }

    impl<'de> Deserialize<'de> for IdentifierIsize {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            <i32>::deserialize(d).map(|x| IdentifierPrimitive(x as isize))
        }
    }
}
