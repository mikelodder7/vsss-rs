//! Share element and identifier implementations using [`ConstMontyForm`] and [`MontyForm`]
//! from the `crypto-bigint` 0.6 crate (Montgomery form residue).
//!
//! For a **constant modulus** (compile-time), use [`IdentifierConstMontyResidue`] with
//! [`crypto_bigint::impl_modulus!`]:
//!
//! ```ignore
//! use crypto_bigint::{impl_modulus, U256};
//! use vsss_rs::IdentifierConstMontyResidue;
//!
//! impl_modulus!(MyModulus, U256, "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
//!
//! type MyResidue = IdentifierConstMontyResidue<MyModulus, 4>;
//! ```
//!
//! For a **runtime modulus**, use [`IdentifierMontyResidue`] with [`MontyParams`];
//! create values via `zero_with_params`, `one_with_params`, `new`, and `random_with_params`.

use core::{
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut, Mul},
};
use crypto_bigint::{
    Encoding, Odd, PrecomputeInverter, RandomMod, Uint,
    modular::{ConstMontyForm, ConstMontyParams, MontyForm, MontyParams, SafeGcdInverter},
};
use rand_core::{CryptoRng, RngCore};
use subtle::Choice;

use super::*;
use crate::*;

// =============================================================================
// ConstMontyForm (compile-time modulus)
// =============================================================================

/// A share value represented as a [`ConstMontyForm<MOD, LIMBS>`].
pub type ValueConstMontyResidue<MOD, const LIMBS: usize> = IdentifierConstMontyResidue<MOD, LIMBS>;

/// A share identifier represented as a residue in Montgomery form modulo a constant modulus
/// (crypto-bigint 0.6 [`ConstMontyForm`]).
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct IdentifierConstMontyResidue<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize>(
    pub ConstMontyForm<MOD, LIMBS>,
)
where
    Uint<LIMBS>: Encoding;

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Display
    for IdentifierConstMontyResidue<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let bytes = <Uint<LIMBS> as Encoding>::to_be_bytes(&self.0.retrieve());
        for &b in bytes.as_ref() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Hash
    for IdentifierConstMontyResidue<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.retrieve().hash(state);
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Ord
    for IdentifierConstMontyResidue<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.retrieve().cmp(&other.0.retrieve())
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> PartialOrd
    for IdentifierConstMontyResidue<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Deref
    for IdentifierConstMontyResidue<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Target = ConstMontyForm<MOD, LIMBS>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> DerefMut
    for IdentifierConstMontyResidue<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> AsRef<ConstMontyForm<MOD, LIMBS>>
    for IdentifierConstMontyResidue<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn as_ref(&self) -> &ConstMontyForm<MOD, LIMBS> {
        &self.0
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> AsMut<ConstMontyForm<MOD, LIMBS>>
    for IdentifierConstMontyResidue<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn as_mut(&mut self) -> &mut ConstMontyForm<MOD, LIMBS> {
        &mut self.0
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> From<ConstMontyForm<MOD, LIMBS>>
    for IdentifierConstMontyResidue<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: ConstMontyForm<MOD, LIMBS>) -> Self {
        Self(value)
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> From<&ConstMontyForm<MOD, LIMBS>>
    for IdentifierConstMontyResidue<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: &ConstMontyForm<MOD, LIMBS>) -> Self {
        Self(*value)
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize>
    From<&IdentifierConstMontyResidue<MOD, LIMBS>> for IdentifierConstMontyResidue<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: &IdentifierConstMontyResidue<MOD, LIMBS>) -> Self {
        Self(value.0)
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> From<IdentifierConstMontyResidue<MOD, LIMBS>>
    for ConstMontyForm<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: IdentifierConstMontyResidue<MOD, LIMBS>) -> Self {
        value.0
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Mul<&IdentifierConstMontyResidue<MOD, LIMBS>>
    for IdentifierConstMontyResidue<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = IdentifierConstMontyResidue<MOD, LIMBS>;

    fn mul(self, rhs: &IdentifierConstMontyResidue<MOD, LIMBS>) -> Self {
        Self(ConstMontyForm::<MOD, LIMBS>::mul(&self.0, &rhs.0))
    }
}

#[cfg(feature = "zeroize")]
impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> zeroize::DefaultIsZeroes
    for IdentifierConstMontyResidue<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding + zeroize::DefaultIsZeroes,
    ConstMontyForm<MOD, LIMBS>: zeroize::DefaultIsZeroes,
{
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> ShareElement
    for IdentifierConstMontyResidue<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Serialization = <Uint<LIMBS> as Encoding>::Repr;
    type Inner = ConstMontyForm<MOD, LIMBS>;

    fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        let raw = Uint::<LIMBS>::random_mod(&mut rng, MOD::MODULUS.as_nz_ref());
        Self(ConstMontyForm::<MOD, LIMBS>::new(&raw))
    }

    fn zero() -> Self {
        Self(ConstMontyForm::<MOD, LIMBS>::ZERO)
    }

    fn one() -> Self {
        Self(ConstMontyForm::<MOD, LIMBS>::ONE)
    }

    fn is_zero(&self) -> Choice {
        self.0.ct_eq(&ConstMontyForm::<MOD, LIMBS>::ZERO)
    }

    fn serialize(&self) -> Self::Serialization {
        <Uint<LIMBS> as Encoding>::to_be_bytes(&self.0.retrieve())
    }

    fn deserialize(serialized: &Self::Serialization) -> VsssResult<Self> {
        uint::IdentifierUint::<LIMBS>::deserialize(serialized)
            .map(|inner| Self(ConstMontyForm::<MOD, LIMBS>::new(&inner.0)))
    }

    fn from_slice(vec: &[u8]) -> VsssResult<Self> {
        uint::IdentifierUint::<LIMBS>::from_slice(vec)
            .map(|inner| Self(ConstMontyForm::<MOD, LIMBS>::new(&inner.0)))
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.serialize().as_ref().to_vec()
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize, const UNSAT_LIMBS: usize> ShareIdentifier
    for IdentifierConstMontyResidue<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
    Odd<Uint<LIMBS>>:
        PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>, Output = Uint<LIMBS>>,
{
    fn inc(&mut self, increment: &Self) {
        self.0 += increment.0;
    }

    fn invert(&self) -> VsssResult<Self> {
        Option::from(self.0.inv())
            .map(Self)
            .ok_or(Error::InvalidShareElement)
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> IdentifierConstMontyResidue<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    /// Identifier with the value 0.
    pub const ZERO: Self = Self(ConstMontyForm::<MOD, LIMBS>::ZERO);
    /// Identifier with the value 1.
    pub const ONE: Self = Self(ConstMontyForm::<MOD, LIMBS>::ONE);
}

// =============================================================================
// MontyForm (runtime modulus)
// =============================================================================

/// A share value represented as a [`MontyForm<LIMBS>`] (runtime modulus).
pub type ValueMontyResidue<const LIMBS: usize> = IdentifierMontyResidue<LIMBS>;

/// A share identifier represented as a residue in Montgomery form modulo a modulus
/// chosen at runtime (crypto-bigint 0.6 [`MontyForm`]).
///
/// Use [`IdentifierMontyResidue::zero_with_params`], [`IdentifierMontyResidue::one_with_params`],
/// [`IdentifierMontyResidue::new`], and [`IdentifierMontyResidue::random_with_params`] to create
/// values; the modulus is not known at compile time so this type does not implement
/// [`ShareElement`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct IdentifierMontyResidue<const LIMBS: usize>(pub MontyForm<LIMBS>)
where
    Uint<LIMBS>: Encoding;

impl<const LIMBS: usize> IdentifierMontyResidue<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    /// Create the additive identity (zero) for the given params.
    pub fn zero_with_params(params: MontyParams<LIMBS>) -> Self {
        Self(MontyForm::<LIMBS>::zero(params))
    }

    /// Create the multiplicative identity (one) for the given params.
    pub fn one_with_params(params: MontyParams<LIMBS>) -> Self {
        Self(MontyForm::<LIMBS>::one(params))
    }

    /// Create a residue representing `integer` mod the modulus in `params`.
    pub fn new(integer: &Uint<LIMBS>, params: MontyParams<LIMBS>) -> Self {
        Self(MontyForm::<LIMBS>::new(integer, params))
    }

    /// Generate a random residue mod the modulus in `params`.
    pub fn random_with_params(
        mut rng: impl RngCore + CryptoRng,
        params: MontyParams<LIMBS>,
    ) -> Self {
        let raw = Uint::<LIMBS>::random_mod(&mut rng, params.modulus().as_nz_ref());
        Self(MontyForm::<LIMBS>::new(&raw, params))
    }

    /// Params (modulus etc.) for this residue.
    pub fn params(&self) -> &MontyParams<LIMBS> {
        self.0.params()
    }
}

impl<const LIMBS: usize> Display for IdentifierMontyResidue<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let bytes = <Uint<LIMBS> as Encoding>::to_be_bytes(&self.0.retrieve());
        for &b in bytes.as_ref() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl<const LIMBS: usize> Hash for IdentifierMontyResidue<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.retrieve().hash(state);
    }
}

impl<const LIMBS: usize> Ord for IdentifierMontyResidue<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.retrieve().cmp(&other.0.retrieve())
    }
}

impl<const LIMBS: usize> PartialOrd for IdentifierMontyResidue<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<const LIMBS: usize> Deref for IdentifierMontyResidue<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Target = MontyForm<LIMBS>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LIMBS: usize> DerefMut for IdentifierMontyResidue<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const LIMBS: usize> AsRef<MontyForm<LIMBS>> for IdentifierMontyResidue<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn as_ref(&self) -> &MontyForm<LIMBS> {
        &self.0
    }
}

impl<const LIMBS: usize> AsMut<MontyForm<LIMBS>> for IdentifierMontyResidue<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn as_mut(&mut self) -> &mut MontyForm<LIMBS> {
        &mut self.0
    }
}

impl<const LIMBS: usize> From<MontyForm<LIMBS>> for IdentifierMontyResidue<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: MontyForm<LIMBS>) -> Self {
        Self(value)
    }
}

impl<const LIMBS: usize> From<&MontyForm<LIMBS>> for IdentifierMontyResidue<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: &MontyForm<LIMBS>) -> Self {
        Self(*value)
    }
}

impl<const LIMBS: usize> From<IdentifierMontyResidue<LIMBS>> for MontyForm<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: IdentifierMontyResidue<LIMBS>) -> Self {
        value.0
    }
}

impl<const LIMBS: usize> Mul<&IdentifierMontyResidue<LIMBS>> for IdentifierMontyResidue<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = IdentifierMontyResidue<LIMBS>;

    fn mul(self, rhs: &IdentifierMontyResidue<LIMBS>) -> Self {
        Self(MontyForm::<LIMBS>::mul(&self.0, &rhs.0))
    }
}
