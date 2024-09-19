use core::ops::{Deref, DerefMut};
use elliptic_curve::{Field, PrimeField};
use rand_core::{CryptoRng, RngCore};
use subtle::Choice;

use super::*;
use crate::*;

/// A share identifier represented as a prime field element.
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub struct IdentifierPrimeField<F: PrimeField>(pub F);

impl<F: PrimeField> Deref for IdentifierPrimeField<F> {
    type Target = F;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F: PrimeField> DerefMut for IdentifierPrimeField<F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<F: PrimeField> AsRef<F> for IdentifierPrimeField<F> {
    fn as_ref(&self) -> &F {
        &self.0
    }
}

impl<F: PrimeField> AsMut<F> for IdentifierPrimeField<F> {
    fn as_mut(&mut self) -> &mut F {
        &mut self.0
    }
}

impl<F: PrimeField> From<F> for IdentifierPrimeField<F> {
    fn from(value: F) -> Self {
        Self(value)
    }
}

impl<F: PrimeField> ShareIdentifier for IdentifierPrimeField<F> {
    type Serialization = F::Repr;
    type Inner = F;

    fn zero() -> Self {
        Self(<F as Field>::ZERO)
    }

    fn one() -> Self {
        Self(<F as Field>::ONE)
    }

    fn is_zero(&self) -> Choice {
        F::is_zero(self)
    }

    fn serialize(&self) -> Self::Serialization {
        self.to_repr()
    }

    fn deserialize(serialized: &Self::Serialization) -> VsssResult<Self> {
        Option::from(F::from_repr(*serialized).map(Self)).ok_or(Error::InvalidShareIdentifier)
    }

    fn random(rng: impl RngCore + CryptoRng) -> Self {
        Self(<F as Field>::random(rng))
    }

    fn invert(&self) -> VsssResult<Self> {
        Option::from(self.0.invert())
            .map(Self)
            .ok_or(Error::InvalidShareIdentifier)
    }

    fn from_slice(vec: &[u8]) -> VsssResult<Self> {
        let mut repr = F::Repr::default();
        if vec.len() != repr.as_ref().len() {
            return Err(Error::InvalidShareIdentifier);
        }
        repr.as_mut().copy_from_slice(vec);
        Option::from(F::from_repr(repr))
            .map(Self)
            .ok_or(Error::InvalidShareIdentifier)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.to_repr().as_ref().to_vec()
    }
}

impl<F: PrimeField> IdentifierPrimeField<F> {
    /// Returns additive identity.
    pub const ZERO: Self = Self(F::ZERO);
    /// Returns multiplicative identity.
    pub const ONE: Self = Self(F::ONE);
}

#[cfg(feature = "serde")]
impl<F: PrimeField> serde::Serialize for IdentifierPrimeField<F> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serdect::array::serialize_hex_lower_or_bin(&self.0.to_repr(), s)
    }
}

#[cfg(feature = "serde")]
impl<'de, F: PrimeField> serde::Deserialize<'de> for IdentifierPrimeField<F> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut repr = F::Repr::default();
        serdect::array::deserialize_hex_or_bin(repr.as_mut(), d)?;
        Option::from(F::from_repr(repr).map(Self))
            .ok_or_else(|| serde::de::Error::custom("invalid share identifier"))
    }
}
