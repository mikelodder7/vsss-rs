//! Share element and identifier implementations using `Uint<LIMBS>` from
//! the `elliptic-curve` or `crypto-bigint` version 5 crate.
//!
use core::{
    fmt::{self, Display, Formatter},
    ops::{Deref, DerefMut},
};
use elliptic_curve::bigint::{ArrayEncoding, ByteArray, Encoding, Random, Uint, Zero};
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
pub struct IdentifierUint<const LIMBS: usize>(pub Saturating<LIMBS>)
where
    Uint<LIMBS>: ArrayEncoding;

impl<const LIMBS: usize> Display for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        for &b in &self.to_generic_array() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl<const LIMBS: usize> Deref for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Target = Saturating<LIMBS>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LIMBS: usize> DerefMut for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const LIMBS: usize> AsRef<Saturating<LIMBS>> for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn as_ref(&self) -> &Saturating<LIMBS> {
        &self.0
    }
}

impl<const LIMBS: usize> AsMut<Saturating<LIMBS>> for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn as_mut(&mut self) -> &mut Saturating<LIMBS> {
        &mut self.0
    }
}

impl<const LIMBS: usize> From<Saturating<LIMBS>> for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn from(value: Saturating<LIMBS>) -> Self {
        Self(value)
    }
}

impl<const LIMBS: usize> From<IdentifierUint<LIMBS>> for Saturating<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn from(value: IdentifierUint<LIMBS>) -> Self {
        value.0
    }
}

#[cfg(feature = "zeroize")]
impl<const LIMBS: usize> zeroize::DefaultIsZeroes for IdentifierUint<LIMBS> where
    Uint<LIMBS>: ArrayEncoding + zeroize::DefaultIsZeroes
{
}

impl<const LIMBS: usize> ShareElement for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Serialization = <Uint<LIMBS> as Encoding>::Repr;
    type Inner = Saturating<LIMBS>;

    fn random(mut rng: impl CryptoRng) -> Self {
        let inner = Saturating(Uint::<LIMBS>::random_from_rng(&mut rng));
        Self(inner)
    }

    fn zero() -> Self {
        Self(Saturating(Uint::<LIMBS>::ZERO))
    }

    fn one() -> Self {
        Self(Saturating(Uint::<LIMBS>::ONE))
    }

    fn is_zero(&self) -> Choice {
        self.0.is_zero().into()
    }

    fn serialize(&self) -> Self::Serialization {
        <Uint<LIMBS> as Encoding>::to_be_bytes(&self.0.0)
    }

    fn deserialize(serialized: &Self::Serialization) -> VsssResult<Self> {
        let inner = Saturating(<Uint<LIMBS> as Encoding>::from_be_bytes(serialized.clone()));
        Ok(Self(inner))
    }

    fn from_slice(vec: &[u8]) -> VsssResult<Self> {
        if vec.len() != Uint::<LIMBS>::BYTES {
            return Err(Error::InvalidShareElement);
        }
        Ok(Self(Saturating(Uint::<LIMBS>::from_be_slice(vec))))
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.serialize().as_ref().to_vec()
    }
}

impl<const LIMBS: usize> ShareIdentifier for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn inc(&mut self, increment: &Self) {
        self.0 += increment.0;
    }

    fn invert(&self) -> VsssResult<Self> {
        let r = Saturating(Uint::<LIMBS>::ONE) / self.0;
        Ok(Self(r))
    }
}

impl<const LIMBS: usize> IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    /// Identifier with the value 0.
    pub const ZERO: Self = Self(Saturating(Uint::<LIMBS>::ZERO));
    /// Identifier with the value 1.
    pub const ONE: Self = Self(Saturating(Uint::<LIMBS>::ONE));

    /// Convert from a fixed-size byte array.
    pub fn from_fixed_array(array: &<Uint<LIMBS> as Encoding>::Repr) -> Self {
        Self(Saturating(<Uint<LIMBS> as Encoding>::from_be_bytes(
            array.clone(),
        )))
    }

    /// Convert to a fixed-size byte array.
    pub fn to_fixed_array(self) -> <Uint<LIMBS> as Encoding>::Repr {
        <Uint<LIMBS> as Encoding>::to_be_bytes(&self.0.0)
    }

    /// Convert from a generic byte array.
    pub fn from_generic_array(array: ByteArray<Uint<LIMBS>>) -> Self {
        Self(Saturating(
            <Uint<LIMBS> as ArrayEncoding>::from_be_byte_array(array),
        ))
    }

    /// Convert to a generic byte array.
    pub fn to_generic_array(self) -> ByteArray<Uint<LIMBS>> {
        <Uint<LIMBS> as ArrayEncoding>::to_be_byte_array(&self.0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::IdentifierUint;
    use crate::{Error, ShareElement, ShareIdentifier};
    use elliptic_curve::bigint::{U64, Uint};

    #[test]
    fn elliptic_curve_bigint_identifier_share_element_methods_round_trip() {
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
        assert_eq!(
            IdentifierUint::<1>::from_generic_array(identifier.to_generic_array()),
            identifier
        );
        assert_eq!(identifier.to_vec(), bytes);
        assert_eq!(
            IdentifierUint::<1>::from_slice(&[1, 2]),
            Err(Error::InvalidShareElement)
        );
        assert_eq!(IdentifierUint::<1>::ZERO, IdentifierUint::<1>::zero());
        assert_eq!(IdentifierUint::<1>::ONE, IdentifierUint::<1>::one());
        assert_eq!(IdentifierUint::<1>::zero().is_zero().unwrap_u8(), 1);
        assert_eq!(IdentifierUint::<1>::one().is_zero().unwrap_u8(), 0);

        let inner = identifier.0;
        assert_eq!(IdentifierUint::<1>::from(inner), identifier);
        assert_eq!(identifier.to_vec(), bytes);
    }

    #[test]
    fn elliptic_curve_bigint_identifier_reference_access_and_arithmetic_work() {
        let mut identifier = IdentifierUint::<1>::one();
        assert_eq!(identifier.as_ref().0, U64::ONE);
        *identifier.as_mut() =
            crate::Saturating(Uint::<1>::from_be_slice(&[0, 0, 0, 0, 0, 0, 0, 2]));
        assert_eq!(
            identifier.0.0,
            Uint::<1>::from_be_slice(&[0, 0, 0, 0, 0, 0, 0, 2])
        );

        identifier.inc(&IdentifierUint::<1>::one());
        assert_eq!(
            identifier.0.0,
            Uint::<1>::from_be_slice(&[0, 0, 0, 0, 0, 0, 0, 3])
        );
        assert_eq!(
            IdentifierUint::<1>::one().invert(),
            Ok(IdentifierUint::<1>::one())
        );
    }
}
