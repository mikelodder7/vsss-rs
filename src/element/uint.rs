//! Share element and identifier implementations using `Uint<LIMBS>` from
//! `crypto-bigint`.
//!
use core::{
    fmt::{self, Display, Formatter},
    ops::{Deref, DerefMut},
};
use crypto_bigint::{Encoding, Random, Uint};
use rand_core::CryptoRng;
use subtle::Choice;

use super::*;
use crate::*;

/// A share value represented as [`Uint<LIMBS>`]
pub type ValueUint<const LIMBS: usize> = IdentifierUint<LIMBS>;

/// A share identifier represented as a Big unsigned integer with
/// a fixed number of limbs.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct IdentifierUint<const LIMBS: usize>(pub Uint<LIMBS>)
where
    Uint<LIMBS>: Encoding;

impl<const LIMBS: usize> Display for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl<const LIMBS: usize> Deref for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Target = Uint<LIMBS>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LIMBS: usize> DerefMut for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const LIMBS: usize> AsRef<Uint<LIMBS>> for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn as_ref(&self) -> &Uint<LIMBS> {
        &self.0
    }
}

impl<const LIMBS: usize> AsMut<Uint<LIMBS>> for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn as_mut(&mut self) -> &mut Uint<LIMBS> {
        &mut self.0
    }
}

impl<const LIMBS: usize> From<Uint<LIMBS>> for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: Uint<LIMBS>) -> Self {
        Self(value)
    }
}

impl<const LIMBS: usize> From<IdentifierUint<LIMBS>> for Uint<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: IdentifierUint<LIMBS>) -> Self {
        value.0
    }
}

#[cfg(feature = "zeroize")]
impl<const LIMBS: usize> zeroize::DefaultIsZeroes for IdentifierUint<LIMBS> where
    Uint<LIMBS>: Encoding + zeroize::DefaultIsZeroes
{
}

impl<const LIMBS: usize> ShareElement for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Serialization = <Uint<LIMBS> as Encoding>::Repr;
    type Inner = Uint<LIMBS>;

    fn random(mut rng: impl CryptoRng) -> Self {
        let inner = Uint::<LIMBS>::random_from_rng(&mut rng);
        Self(inner)
    }

    fn zero() -> Self {
        Self(Uint::<LIMBS>::ZERO)
    }

    fn one() -> Self {
        Self(Uint::<LIMBS>::ONE)
    }

    fn is_zero(&self) -> Choice {
        self.0.is_zero().into()
    }

    fn serialize(&self) -> Self::Serialization {
        <Uint<LIMBS> as Encoding>::to_be_bytes(&self.0)
    }

    fn deserialize(serialized: &Self::Serialization) -> VsssResult<Self> {
        let inner = <Uint<LIMBS> as Encoding>::from_be_bytes(serialized.clone());
        Ok(Self(inner))
    }

    fn from_slice(vec: &[u8]) -> VsssResult<Self> {
        if vec.len() != Uint::<LIMBS>::BYTES {
            return Err(Error::InvalidShareElement);
        }
        Ok(Self(Uint::<LIMBS>::from_be_slice(vec)))
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.serialize().as_ref().to_vec()
    }
}

impl<const LIMBS: usize> ShareIdentifier for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn inc(&mut self, increment: &Self) {
        self.0 += increment.0;
    }

    fn invert(&self) -> VsssResult<Self> {
        let r = Uint::<LIMBS>::ONE / self.0;
        Ok(Self(r))
    }
}

impl<const LIMBS: usize> IdentifierUint<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    /// Identifier with the value 0.
    pub const ZERO: Self = Self(Uint::<LIMBS>::ZERO);
    /// Identifier with the value 1.
    pub const ONE: Self = Self(Uint::<LIMBS>::ONE);

    /// Convert from a fixed-size byte array.
    pub fn from_fixed_array(array: &<Uint<LIMBS> as Encoding>::Repr) -> Self {
        Self(<Uint<LIMBS> as Encoding>::from_be_bytes(array.clone()))
    }

    /// Convert to a fixed-size byte array.
    pub fn to_fixed_array(self) -> <Uint<LIMBS> as Encoding>::Repr {
        <Uint<LIMBS> as Encoding>::to_be_bytes(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::IdentifierUint;
    use crate::{Error, ShareElement, ShareIdentifier};
    use crypto_bigint::Uint;

    #[test]
    fn crypto_bigint_identifier_share_element_methods_round_trip() {
        let bytes = [0, 0, 0, 0, 0, 0, 0, 9];
        let identifier = IdentifierUint::<1>::from_slice(&bytes).unwrap();
        let serialized = identifier.serialize();

        assert_eq!(serialized.as_ref(), bytes.as_slice());
        assert_eq!(
            IdentifierUint::<1>::deserialize(&serialized),
            Ok(identifier)
        );
        assert_eq!(
            IdentifierUint::<1>::from_fixed_array(&serialized),
            identifier
        );
        assert_eq!(identifier.to_fixed_array().as_ref(), bytes.as_slice());
        assert_eq!(identifier.to_vec(), bytes);
        assert_eq!(
            IdentifierUint::<1>::from_slice(&[1, 2]),
            Err(Error::InvalidShareElement)
        );
        assert_eq!(IdentifierUint::<1>::ZERO, IdentifierUint::<1>::zero());
        assert_eq!(IdentifierUint::<1>::ONE, IdentifierUint::<1>::one());
        assert_eq!(IdentifierUint::<1>::zero().is_zero().unwrap_u8(), 1);
        assert_eq!(IdentifierUint::<1>::one().is_zero().unwrap_u8(), 0);

        let inner: Uint<1> = identifier.into();
        assert_eq!(
            IdentifierUint::<1>::from(inner),
            IdentifierUint::<1>::from_slice(&bytes).unwrap()
        );
    }

    #[test]
    fn crypto_bigint_identifier_reference_access_and_arithmetic_work() {
        let mut identifier = IdentifierUint::<1>::one();
        assert_eq!(*identifier.as_ref(), Uint::<1>::ONE);
        *identifier.as_mut() = Uint::<1>::from_be_slice(&[0, 0, 0, 0, 0, 0, 0, 2]);
        assert_eq!(
            *identifier,
            Uint::<1>::from_be_slice(&[0, 0, 0, 0, 0, 0, 0, 2])
        );

        identifier.inc(&IdentifierUint::<1>::one());
        assert_eq!(
            *identifier,
            Uint::<1>::from_be_slice(&[0, 0, 0, 0, 0, 0, 0, 3])
        );
        assert_eq!(
            IdentifierUint::<1>::one().invert(),
            Ok(IdentifierUint::<1>::one())
        );
    }
}
