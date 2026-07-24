//! Share element and identifier implementations using `BoxedUint` from
//! `crypto-bigint`.

use core::{
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut},
};

use crypto_bigint::{BoxedUint, NonZero, RandomBits, Resize};
use rand_core::CryptoRng;
use subtle::Choice;

use super::*;
use crate::*;

/// A share value represented as [`BoxedUint`].
pub type ValueBoxedUint<const BITS: u32> = IdentifierBoxedUint<BITS>;

/// A share identifier represented as a heap-allocated unsigned integer with
/// a fixed bit precision.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct IdentifierBoxedUint<const BITS: u32>(pub BoxedUint);

impl<const BITS: u32> Default for IdentifierBoxedUint<BITS> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<const BITS: u32> Display for IdentifierBoxedUint<BITS> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl<const BITS: u32> Hash for IdentifierBoxedUint<BITS> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_be_bytes().hash(state);
    }
}

impl<const BITS: u32> Deref for IdentifierBoxedUint<BITS> {
    type Target = BoxedUint;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const BITS: u32> DerefMut for IdentifierBoxedUint<BITS> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const BITS: u32> AsRef<BoxedUint> for IdentifierBoxedUint<BITS> {
    fn as_ref(&self) -> &BoxedUint {
        &self.0
    }
}

impl<const BITS: u32> AsMut<BoxedUint> for IdentifierBoxedUint<BITS> {
    fn as_mut(&mut self) -> &mut BoxedUint {
        &mut self.0
    }
}

impl<const BITS: u32> From<BoxedUint> for IdentifierBoxedUint<BITS> {
    fn from(value: BoxedUint) -> Self {
        Self(value.resize_unchecked(BITS))
    }
}

impl<const BITS: u32> From<IdentifierBoxedUint<BITS>> for BoxedUint {
    fn from(value: IdentifierBoxedUint<BITS>) -> Self {
        value.0
    }
}

impl<const BITS: u32> ShareElement for IdentifierBoxedUint<BITS> {
    type Serialization = Vec<u8>;
    type Inner = BoxedUint;

    fn random(mut rng: impl CryptoRng) -> Self {
        Self(BoxedUint::random_bits_with_precision(&mut rng, BITS, BITS))
    }

    fn zero() -> Self {
        Self(BoxedUint::zero_with_precision(BITS))
    }

    fn one() -> Self {
        Self(BoxedUint::one_with_precision(BITS))
    }

    fn is_zero(&self) -> Choice {
        self.0.is_zero().into()
    }

    fn serialize(&self) -> Self::Serialization {
        self.0.to_be_bytes().into()
    }

    fn deserialize(serialized: &Self::Serialization) -> VsssResult<Self> {
        Self::from_slice(serialized)
    }

    fn from_slice(slice: &[u8]) -> VsssResult<Self> {
        let expected_len = (BoxedUint::zero_with_precision(BITS).bits_precision() / 8) as usize;
        if slice.len() != expected_len {
            return Err(Error::InvalidShareElement);
        }
        BoxedUint::from_be_slice(slice, BITS)
            .map(Self)
            .map_err(|_| Error::InvalidShareElement)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.serialize()
    }
}

impl<const BITS: u32> ShareIdentifier for IdentifierBoxedUint<BITS> {
    fn inc(&mut self, increment: &Self) {
        self.0 += &increment.0;
    }

    fn invert(&self) -> VsssResult<Self> {
        let denominator = NonZero::new(self.0.clone()).ok_or(Error::InvalidShareElement)?;
        Ok(Self(BoxedUint::one_with_precision(BITS) / denominator))
    }
}

impl<const BITS: u32> IdentifierBoxedUint<BITS> {
    /// Identifier with the value 0.
    pub fn zero_value() -> Self {
        Self::zero()
    }

    /// Identifier with the value 1.
    pub fn one_value() -> Self {
        Self::one()
    }
}

#[cfg(test)]
mod tests {
    use super::IdentifierBoxedUint;
    use crate::{Error, ShareElement, ShareIdentifier};
    use crypto_bigint::{BoxedUint, Resize};

    type Identifier = IdentifierBoxedUint<128>;

    #[test]
    fn boxed_uint_identifier_share_element_methods_round_trip() {
        let bytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
        let identifier = Identifier::from_slice(&bytes).unwrap();
        let serialized = identifier.serialize();

        assert_eq!(serialized, bytes);
        assert_eq!(Identifier::deserialize(&serialized), Ok(identifier.clone()));
        assert_eq!(identifier.to_vec(), bytes);
        assert_eq!(
            Identifier::from_slice(&[1, 2]),
            Err(Error::InvalidShareElement)
        );
        assert_eq!(Identifier::default(), Identifier::zero());
        assert_eq!(Identifier::zero().is_zero().unwrap_u8(), 1);
        assert_eq!(Identifier::one().is_zero().unwrap_u8(), 0);

        let inner: BoxedUint = identifier.clone().into();
        assert_eq!(Identifier::from(inner), identifier);
    }

    #[test]
    fn boxed_uint_identifier_reference_access_and_arithmetic_work() {
        let mut identifier = Identifier::one();
        assert_eq!(*identifier.as_ref(), BoxedUint::one_with_precision(128));
        *identifier.as_mut() = BoxedUint::from(2u8).resize(128);
        assert_eq!(*identifier, BoxedUint::from(2u8).resize(128));

        identifier.inc(&Identifier::one());
        assert_eq!(*identifier, BoxedUint::from(3u8).resize(128));
        assert_eq!(Identifier::one().invert(), Ok(Identifier::one()));
    }
}
