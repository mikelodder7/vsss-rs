use core::{
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut, Mul},
};
use elliptic_curve::bigint::modular::constant_mod::{Residue, ResidueParams};
use elliptic_curve::bigint::{ArrayEncoding, Uint};

use super::*;
use crate::*;

/// A share value represented as a [`Residue<MOD, LIMBS>`]
pub type ValueResidue<MOD, const LIMBS: usize> = IdentifierResidue<MOD, LIMBS>;

/// A share identifier represented as a residue modulo known at compile time.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct IdentifierResidue<MOD: ResidueParams<LIMBS>, const LIMBS: usize>(
    pub Residue<MOD, LIMBS>,
)
where
    Uint<LIMBS>: ArrayEncoding;

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> Display for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for &b in &self.0.retrieve().to_be_byte_array() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> Hash for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.retrieve().hash(state);
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> Ord for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.retrieve().cmp(&other.0.retrieve())
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> PartialOrd for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> Deref for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Target = Residue<MOD, LIMBS>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> DerefMut for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> AsRef<Residue<MOD, LIMBS>>
    for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn as_ref(&self) -> &Residue<MOD, LIMBS> {
        &self.0
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> AsMut<Residue<MOD, LIMBS>>
    for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn as_mut(&mut self) -> &mut Residue<MOD, LIMBS> {
        &mut self.0
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> From<Residue<MOD, LIMBS>>
    for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn from(value: Residue<MOD, LIMBS>) -> Self {
        Self(value)
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> From<&Residue<MOD, LIMBS>>
    for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn from(value: &Residue<MOD, LIMBS>) -> Self {
        Self(*value)
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> From<&IdentifierResidue<MOD, LIMBS>>
    for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn from(value: &IdentifierResidue<MOD, LIMBS>) -> Self {
        Self(value.0)
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> From<IdentifierResidue<MOD, LIMBS>>
    for Residue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn from(value: IdentifierResidue<MOD, LIMBS>) -> Self {
        value.0
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> Mul<&IdentifierResidue<MOD, LIMBS>>
    for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Output = IdentifierResidue<MOD, LIMBS>;

    fn mul(self, rhs: &IdentifierResidue<MOD, LIMBS>) -> Self {
        Self(Residue::<MOD, LIMBS>::mul(&self, &rhs))
    }
}

#[cfg(feature = "zeroize")]
impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> zeroize::DefaultIsZeroes
    for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding + zeroize::DefaultIsZeroes,
    Residue<MOD, LIMBS>: zeroize::DefaultIsZeroes,
{
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> ShareElement for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Serialization = <Uint<LIMBS> as Encoding>::Repr;
    type Inner = Residue<MOD, LIMBS>;

    fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        let inner = Uint::<LIMBS>::random(&mut rng);
        Self(Residue::<MOD, LIMBS>::new(&inner))
    }

    fn zero() -> Self {
        Self(Residue::<MOD, LIMBS>::ZERO)
    }

    fn one() -> Self {
        Self(Residue::<MOD, LIMBS>::ONE)
    }

    fn is_zero(&self) -> Choice {
        self.0.is_zero()
    }

    fn serialize(&self) -> Self::Serialization {
        self.0.retrieve().to_be_bytes()
    }

    fn deserialize(serialized: &Self::Serialization) -> VsssResult<Self> {
        IdentifierUint::<LIMBS>::deserialize(serialized)
            .map(|inner| Self(Residue::<MOD, LIMBS>::new(&inner.0 .0)))
    }

    fn from_slice(vec: &[u8]) -> VsssResult<Self> {
        IdentifierUint::<LIMBS>::from_slice(vec)
            .map(|inner| Self(Residue::<MOD, LIMBS>::new(&inner.0 .0)))
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.serialize().as_ref().to_vec()
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> ShareIdentifier
    for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn inc(&mut self, increment: &Self) {
        self.0 += increment.0;
    }

    fn invert(&self) -> VsssResult<Self> {
        let (value, succeeded) = self.0.invert();
        if !bool::from(succeeded) {
            return Err(Error::InvalidShareElement);
        }
        Ok(Self(value))
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    /// Identifier with the value 0.
    pub const ZERO: Self = Self(Residue::<MOD, LIMBS>::ZERO);
    /// Identifier with the value 1.
    pub const ONE: Self = Self(Residue::<MOD, LIMBS>::ONE);
}
