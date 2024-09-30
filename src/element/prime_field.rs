use super::*;
use crate::*;
use core::{
    cmp::Ordering,
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut, Mul},
};
use crypto_bigint::modular::constant_mod::ResidueParams;
use crypto_bigint::ArrayEncoding;
use elliptic_curve::{bigint::Uint, ops::Reduce, scalar::IsHigh, Field, PrimeField};
use zeroize::*;

/// A share identifier represented as a prime field element.
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct IdentifierPrimeField<F: PrimeField>(
    #[cfg_attr(feature = "serde", serde(with = "elliptic_curve_tools::prime_field"))] pub F,
);

impl<F: PrimeField> Display for IdentifierPrimeField<F> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        for &b in self.0.to_repr().as_ref() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl<F: PrimeField> Hash for IdentifierPrimeField<F> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_repr().as_ref().hash(state);
    }
}

#[allow(clippy::non_canonical_partial_ord_impl)]
impl<F: PrimeField + IsHigh> PartialOrd for IdentifierPrimeField<F> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self.0.is_high().unwrap_u8(), other.0.is_high().unwrap_u8()) {
            (1, 1) => Some(other.0.to_repr().as_ref().cmp(self.0.to_repr().as_ref())),
            (0, 0) => Some(self.0.to_repr().as_ref().cmp(other.0.to_repr().as_ref())),
            (1, 0) => Some(Ordering::Less),
            (0, 1) => Some(Ordering::Greater),
            (_, _) => None,
        }
    }
}

impl<F: PrimeField + IsHigh> Ord for IdentifierPrimeField<F> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).expect("invalid share identifier")
    }
}

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

impl<F: PrimeField> From<&IdentifierPrimeField<F>> for IdentifierPrimeField<F> {
    fn from(value: &IdentifierPrimeField<F>) -> Self {
        *value
    }
}

impl<F: PrimeField, P: Primitive<BYTES>, const BYTES: usize> From<&IdentifierPrimitive<P, BYTES>>
    for IdentifierPrimeField<F>
{
    fn from(value: &IdentifierPrimitive<P, BYTES>) -> Self {
        #[cfg(target_pointer_width = "64")]
        {
            if BYTES * 8 <= 64 {
                Self(F::from(value.0.to_u64().expect("invalid share identifier")))
            } else {
                Self(F::from_u128(
                    value.0.to_u128().expect("invalid share identifier"),
                ))
            }
        }
        #[cfg(target_pointer_width = "32")]
        {
            Self(F::from(value.0.to_u64().expect("invalid share identifier")))
        }
    }
}

impl<F: PrimeField + Reduce<Uint<LIMBS>>, const LIMBS: usize> From<&IdentifierUint<LIMBS>>
    for IdentifierPrimeField<F>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn from(value: &IdentifierUint<LIMBS>) -> Self {
        if LIMBS * 8 != F::Repr::default().as_ref().len() {
            panic!("cannot convert from IdentifierUint to IdentifierPrimeField with different limb size");
        }
        Self(F::reduce(value.0 .0))
    }
}

impl<F: PrimeField + Reduce<Uint<LIMBS>>, MOD: ResidueParams<LIMBS>, const LIMBS: usize>
    From<&IdentifierResidue<MOD, LIMBS>> for IdentifierPrimeField<F>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn from(value: &IdentifierResidue<MOD, LIMBS>) -> Self {
        let t = value.0.retrieve();
        Self(F::reduce(t))
    }
}

impl<F: PrimeField> Mul<&IdentifierPrimeField<F>> for IdentifierPrimeField<F> {
    type Output = IdentifierPrimeField<F>;

    fn mul(self, rhs: &IdentifierPrimeField<F>) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl<F: PrimeField, P: Primitive<BYTES>, const BYTES: usize> Mul<&IdentifierPrimitive<P, BYTES>>
    for IdentifierPrimeField<F>
{
    type Output = IdentifierPrimeField<F>;

    fn mul(self, rhs: &IdentifierPrimitive<P, BYTES>) -> Self::Output {
        let rhs = IdentifierPrimeField::<F>::from(rhs);
        Self(self.0 * rhs.0)
    }
}

impl<F: PrimeField + Reduce<Uint<LIMBS>>, const LIMBS: usize> Mul<&IdentifierUint<LIMBS>>
    for IdentifierPrimeField<F>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Output = IdentifierPrimeField<F>;

    fn mul(self, rhs: &IdentifierUint<LIMBS>) -> Self::Output {
        let rhs = IdentifierPrimeField::<F>::from(rhs);
        Self(self.0 * rhs.0)
    }
}

impl<F: PrimeField + Reduce<Uint<LIMBS>>, MOD: ResidueParams<LIMBS>, const LIMBS: usize>
    Mul<&IdentifierResidue<MOD, LIMBS>> for IdentifierPrimeField<F>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Output = IdentifierPrimeField<F>;

    fn mul(self, rhs: &IdentifierResidue<MOD, LIMBS>) -> Self::Output {
        let rhs = IdentifierPrimeField::<F>::from(rhs);
        Self(self.0 * rhs.0)
    }
}

impl<F: PrimeField + DefaultIsZeroes> DefaultIsZeroes for IdentifierPrimeField<F> {}

impl<F: PrimeField> ShareElement for IdentifierPrimeField<F> {
    type Serialization = F::Repr;
    type Inner = F;

    fn random(rng: impl RngCore + CryptoRng) -> Self {
        Self(F::random(rng))
    }

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
        Option::from(F::from_repr(*serialized).map(Self)).ok_or(Error::InvalidShareElement)
    }

    fn from_slice(vec: &[u8]) -> VsssResult<Self> {
        let mut repr = F::Repr::default();
        if vec.len() != repr.as_ref().len() {
            return Err(Error::InvalidShareElement);
        }
        repr.as_mut().copy_from_slice(vec);
        Option::from(F::from_repr(repr))
            .map(Self)
            .ok_or(Error::InvalidShareElement)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.to_repr().as_ref().to_vec()
    }
}

impl<F: PrimeField> ShareIdentifier for IdentifierPrimeField<F> {
    fn inc(&mut self, increment: &Self) {
        self.0 += increment.0;
    }

    fn invert(&self) -> VsssResult<Self> {
        Option::from(self.0.invert())
            .map(Self)
            .ok_or(Error::InvalidShareElement)
    }
}

impl<F: PrimeField> IdentifierPrimeField<F> {
    /// Returns additive identity.
    pub const ZERO: Self = Self(F::ZERO);
    /// Returns multiplicative identity.
    pub const ONE: Self = Self(F::ONE);
}
