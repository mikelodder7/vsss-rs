//! Share element and identifier implementations using `Uint<LIMBS>` from
//! the `crypto-bigint` version 6 crate.
//!
use core::{
    fmt::{self, Display, Formatter},
    ops::{Deref, DerefMut},
};
use crypto_bigint::{Encoding, Random, Uint, Zero};
use rand_core::{CryptoRng, RngCore};
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

    fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        let inner = Uint::<LIMBS>::random(&mut rng);
        Self(inner)
    }

    fn zero() -> Self {
        Self(Uint::<LIMBS>::ZERO)
    }

    fn one() -> Self {
        Self(Uint::<LIMBS>::ONE)
    }

    fn is_zero(&self) -> Choice {
        self.0.is_zero()
    }

    fn serialize(&self) -> Self::Serialization {
        <Uint<LIMBS> as Encoding>::to_be_bytes(&self.0)
    }

    fn deserialize(serialized: &Self::Serialization) -> VsssResult<Self> {
        let inner = <Uint<LIMBS> as Encoding>::from_be_bytes(*serialized);
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
        Self(<Uint<LIMBS> as Encoding>::from_be_bytes(*array))
    }

    /// Convert to a fixed-size byte array.
    pub fn to_fixed_array(self) -> <Uint<LIMBS> as Encoding>::Repr {
        <Uint<LIMBS> as Encoding>::to_be_bytes(&self.0)
    }
}
