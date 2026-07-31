use core::{
    fmt::{self, Display, Formatter},
    ops::{Deref, DerefMut},
};
use rand_core::CryptoRng;
use subtle::Choice;
#[cfg(feature = "zeroize")]
use zeroize::*;

use super::*;
use crate::*;

/// A share identifier represented as `u8`.
pub type IdentifierU8 = IdentifierPrimitive<u8, 1>;
/// A share value represented as `u8`.
pub type ValueU8 = IdentifierU8;
/// A share identifier represented as `u16`.
pub type IdentifierU16 = IdentifierPrimitive<u16, 2>;
/// A share value represented as `u16`.
pub type ValueU16 = IdentifierU16;
/// A share identifier represented as `u32`.
pub type IdentifierU32 = IdentifierPrimitive<u32, 4>;
/// A share value represented as `u32`.
pub type ValueU32 = IdentifierU32;
/// A share identifier represented as `u64`.
pub type IdentifierU64 = IdentifierPrimitive<u64, 8>;
/// A share value represented as `u64`.
pub type ValueU64 = IdentifierU64;
#[cfg(target_pointer_width = "64")]
/// A share identifier represented as `u128`.
pub type IdentifierU128 = IdentifierPrimitive<u128, 16>;
#[cfg(target_pointer_width = "64")]
/// A share value represented as `u128`.
pub type ValueU128 = IdentifierU128;
/// A share identifier represented as `usize`.
pub type IdentifierUsize = IdentifierPrimitive<usize, USIZE_BYTES>;
/// A share value represented as `usize`.
pub type ValueUsize = IdentifierUsize;
/// A share identifier represented as `i8`.
pub type IdentifierI8 = IdentifierPrimitive<i8, 1>;
/// A share value represented as `i8`.
pub type ValueI8 = IdentifierI8;
/// A share identifier represented as `i16`.
pub type IdentifierI16 = IdentifierPrimitive<i16, 2>;
/// A share value represented as `i16`.
pub type ValueI16 = IdentifierI16;
/// A share identifier represented as `i32`.
pub type IdentifierI32 = IdentifierPrimitive<i32, 4>;
/// A share value represented as `i32`.
pub type ValueI32 = IdentifierI32;
/// A share identifier represented as `i64`.
pub type IdentifierI64 = IdentifierPrimitive<i64, 8>;
/// A share value represented as `i64`.
pub type ValueI64 = IdentifierI64;
#[cfg(target_pointer_width = "64")]
/// A share identifier represented as `i128`.
pub type IdentifierI128 = IdentifierPrimitive<i128, 16>;
#[cfg(target_pointer_width = "64")]
/// A share value represented as `i128`.
pub type ValueI128 = IdentifierI128;
/// A share identifier represented as `isize`.
pub type IdentifierIsize = IdentifierPrimitive<isize, ISIZE_BYTES>;
/// A share value represented as `isize`.
pub type ValueIsize = IdentifierIsize;

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

#[cfg(feature = "zeroize")]
impl<P: Primitive<BYTES>, const BYTES: usize> DefaultIsZeroes for IdentifierPrimitive<P, BYTES> {}

impl<P: Primitive<BYTES>, const BYTES: usize> ShareElement for IdentifierPrimitive<P, BYTES> {
    type Serialization = [u8; BYTES];
    type Inner = P;

    fn random(mut rng: impl CryptoRng) -> Self {
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

#[cfg(test)]
mod tests {
    use super::{
        IdentifierI8, IdentifierI16, IdentifierI32, IdentifierI64, IdentifierIsize, IdentifierU8,
        IdentifierU16, IdentifierU32, IdentifierU64, IdentifierUsize,
    };
    #[cfg(target_pointer_width = "64")]
    use super::{IdentifierI128, IdentifierU128};
    use crate::{Error, ShareElement, ShareIdentifier};
    use std::{string::ToString, vec};

    #[test]
    fn primitive_identifier_share_element_methods_round_trip() {
        let identifier = IdentifierU16::from(0x1234);
        let serialized = identifier.serialize();

        assert_eq!(identifier.to_string(), "1234");
        assert_eq!(serialized, [0x12, 0x34]);
        assert_eq!(IdentifierU16::deserialize(&serialized), Ok(identifier));
        assert_eq!(IdentifierU16::from_slice(&serialized), Ok(identifier));
        assert_eq!(identifier.to_vec(), vec![0x12, 0x34]);
        assert_eq!(
            IdentifierU16::from_slice(&[0x12]),
            Err(Error::InvalidShareElement)
        );
        assert_eq!(IdentifierU16::zero().is_zero().unwrap_u8(), 1);
        assert_eq!(IdentifierU16::one().is_zero().unwrap_u8(), 0);
        assert_eq!(IdentifierU16::ZERO, IdentifierU16::zero());
        assert_eq!(IdentifierU16::ONE, IdentifierU16::one());
    }

    #[test]
    fn primitive_identifier_reference_access_and_arithmetic_work() {
        let mut identifier = IdentifierU16::from(1);
        assert_eq!(*identifier, 1);
        assert_eq!(*identifier.as_ref(), 1);
        *identifier.as_mut() = 2;
        assert_eq!(*identifier, 2);

        identifier.inc(&IdentifierU16::from(u16::MAX));
        assert_eq!(*identifier, u16::MAX);
        assert_eq!(IdentifierU16::one().invert(), Ok(IdentifierU16::one()));
        assert_eq!(
            IdentifierU16::zero().invert(),
            Err(Error::InvalidShareElement)
        );
    }

    #[test]
    fn signed_primitive_identifiers_use_big_endian_display_and_saturating_increment() {
        let mut identifier = IdentifierI16::from(i16::MIN + 1);
        assert_eq!(IdentifierI16::from(-2).to_string(), "fffe");
        identifier.inc(&IdentifierI16::from(-10));
        assert_eq!(*identifier, i16::MIN);
    }

    #[test]
    fn one_byte_identifiers_round_trip() {
        let identifier = IdentifierU8::from(0xab);
        assert_eq!(identifier.to_string(), "ab");
        assert_eq!(identifier.serialize(), [0xab]);
        assert_eq!(IdentifierU8::from_slice(&[0xab]), Ok(identifier));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn primitive_identifier_serde_round_trips_common_formats() {
        let identifier = IdentifierU16::from(0x1234);

        let json = serde_json::to_string(&identifier).unwrap();
        assert_eq!(
            serde_json::from_str::<IdentifierU16>(&json).unwrap(),
            identifier
        );

        let postcard = postcard::to_stdvec(&identifier).unwrap();
        assert_eq!(
            postcard::from_bytes::<IdentifierU16>(&postcard).unwrap(),
            identifier
        );

        let cbor = serde_cbor_2::to_vec(&identifier).unwrap();
        assert_eq!(
            serde_cbor_2::from_slice::<IdentifierU16>(&cbor).unwrap(),
            identifier
        );

        let bare = serde_bare::to_vec(&identifier).unwrap();
        assert_eq!(
            serde_bare::from_slice::<IdentifierU16>(&bare).unwrap(),
            identifier
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn primitive_identifier_serde_round_trips_aliases() {
        assert_eq!(
            serde_json::from_str::<IdentifierU8>(
                &serde_json::to_string(&IdentifierU8::from(1)).unwrap()
            )
            .unwrap(),
            IdentifierU8::from(1)
        );
        assert_eq!(
            serde_json::from_str::<IdentifierU32>(
                &serde_json::to_string(&IdentifierU32::from(2)).unwrap()
            )
            .unwrap(),
            IdentifierU32::from(2)
        );
        assert_eq!(
            serde_json::from_str::<IdentifierU64>(
                &serde_json::to_string(&IdentifierU64::from(3)).unwrap()
            )
            .unwrap(),
            IdentifierU64::from(3)
        );
        assert_eq!(
            serde_json::from_str::<IdentifierUsize>(
                &serde_json::to_string(&IdentifierUsize::from(4)).unwrap()
            )
            .unwrap(),
            IdentifierUsize::from(4)
        );
        assert_eq!(
            serde_json::from_str::<IdentifierI8>(
                &serde_json::to_string(&IdentifierI8::from(-1)).unwrap()
            )
            .unwrap(),
            IdentifierI8::from(-1)
        );
        assert_eq!(
            serde_json::from_str::<IdentifierI16>(
                &serde_json::to_string(&IdentifierI16::from(-2)).unwrap()
            )
            .unwrap(),
            IdentifierI16::from(-2)
        );
        assert_eq!(
            serde_json::from_str::<IdentifierI32>(
                &serde_json::to_string(&IdentifierI32::from(-3)).unwrap()
            )
            .unwrap(),
            IdentifierI32::from(-3)
        );
        assert_eq!(
            serde_json::from_str::<IdentifierI64>(
                &serde_json::to_string(&IdentifierI64::from(-4)).unwrap()
            )
            .unwrap(),
            IdentifierI64::from(-4)
        );
        assert_eq!(
            serde_json::from_str::<IdentifierIsize>(
                &serde_json::to_string(&IdentifierIsize::from(-5)).unwrap()
            )
            .unwrap(),
            IdentifierIsize::from(-5)
        );

        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(
                serde_json::from_str::<IdentifierU128>(
                    &serde_json::to_string(&IdentifierU128::from(6)).unwrap()
                )
                .unwrap(),
                IdentifierU128::from(6)
            );
            assert_eq!(
                serde_json::from_str::<IdentifierI128>(
                    &serde_json::to_string(&IdentifierI128::from(-6)).unwrap()
                )
                .unwrap(),
                IdentifierI128::from(-6)
            );
        }
    }
}
