//! Share identifiers for secret sharing schemes.

#[cfg(any(feature = "alloc", feature = "std"))]
use crate::Vec;
use crate::{Error, VsssResult};

use core::{
    fmt::Debug,
    ops::{Add, AddAssign, Deref, Mul, MulAssign, Sub, SubAssign},
};
use elliptic_curve::{
    bigint::{
        modular::constant_mod::{Residue, ResidueParams},
        ArrayEncoding, ByteArray, Concat, Encoding, NonZero, Random, Split, Uint,
        Zero as CryptoZero,
    },
    Field, PrimeField,
};
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// A value used to represent the identifier for secret shares.
pub trait ShareIdentifier:
    Sized
    + Debug
    + Eq
    + Clone
    + Default
    + 'static
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + Mul<Self, Output = Self>
    + AddAssign
    + SubAssign
    + MulAssign
    + for<'a> AddAssign<&'a Self>
    + for<'a> SubAssign<&'a Self>
    + for<'a> MulAssign<&'a Self>
{
    /// The serialized form of the share identifier.
    type Serialization: AsRef<[u8]> + AsMut<[u8]> + 'static;
    /// Identifier with the value 0.
    fn zero() -> Self;
    /// Identifier with the value 1.
    fn one() -> Self;
    /// Check if the share identifier is zero.
    fn is_zero(&self) -> Choice;
    /// Serialize the share identifier.
    fn serialize(&self) -> Self::Serialization;
    /// Deserialize the share identifier.
    fn deserialize(serialized: &Self::Serialization) -> VsssResult<Self>;
    /// Generate a random share identifier.
    fn random(rng: impl RngCore + CryptoRng) -> Self;
    /// Invert the share identifier.
    fn invert(&self) -> VsssResult<Self>;
    /// Create a share identifier from a byte slice.
    fn from_slice(vec: &[u8]) -> VsssResult<Self>;
    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Serialize the share identifier to a byte vector.
    fn to_vec(&self) -> Vec<u8>;
}

impl<F: PrimeField + Sized> ShareIdentifier for F {
    type Serialization = F::Repr;

    fn zero() -> Self {
        <F as Field>::ZERO
    }

    fn one() -> Self {
        <F as Field>::ONE
    }

    fn is_zero(&self) -> Choice {
        F::is_zero(self)
    }

    fn serialize(&self) -> Self::Serialization {
        self.to_repr()
    }

    fn deserialize(serialized: &Self::Serialization) -> VsssResult<Self> {
        Option::from(F::from_repr(*serialized)).ok_or(Error::InvalidShareIdentifier)
    }

    fn random(rng: impl RngCore + CryptoRng) -> Self {
        <F as Field>::random(rng)
    }

    fn invert(&self) -> VsssResult<Self> {
        Option::from(self.invert()).ok_or(Error::InvalidShareIdentifier)
    }

    fn from_slice(vec: &[u8]) -> VsssResult<Self> {
        let mut repr = F::Repr::default();
        if vec.len() != repr.as_ref().len() {
            return Err(Error::InvalidShareIdentifier);
        }
        repr.as_mut().copy_from_slice(&vec);
        Option::from(F::from_repr(repr)).ok_or(Error::InvalidShareIdentifier)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.to_repr().as_ref().to_vec()
    }
}

macro_rules! impl_primitive_identifier {
    ($($name:ident => $primitive:ident),+$(,)*) => {
        $(
            /// A share identifier represented as a primitive integer.
            #[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
            pub struct $name(pub $primitive);

            impl ConditionallySelectable for $name {
                fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
                    $name($primitive::conditional_select(&a.0, &b.0, choice))
                }
            }

            impl ConstantTimeEq for $name {
                fn ct_eq(&self, other: &Self) -> subtle::Choice {
                    self.0.ct_eq(&other.0)
                }
            }

            impl Add for $name {
                type Output = Self;

                fn add(self, rhs: Self) -> Self::Output {
                    $name(self.0.wrapping_add(rhs.0))
                }
            }

            impl Sub for $name {
                type Output = Self;

                fn sub(self, rhs: Self) -> Self::Output {
                    $name(self.0.wrapping_sub(rhs.0))
                }
            }

            impl Mul for $name {
                type Output = Self;

                fn mul(self, rhs: Self) -> Self::Output {
                    $name(self.0.wrapping_mul(rhs.0))
                }
            }

            impl AddAssign for $name {
                fn add_assign(&mut self, rhs: Self) {
                    self.0 = self.0.wrapping_add(rhs.0);
                }
            }

            impl AddAssign<&$name> for $name {
                fn add_assign(&mut self, rhs: &$name) {
                    self.0 = self.0.wrapping_add(rhs.0);
                }
            }

            impl SubAssign for $name {
                fn sub_assign(&mut self, rhs: Self) {
                    self.0 = self.0.wrapping_sub(rhs.0);
                }
            }

            impl SubAssign<&$name> for $name {
                fn sub_assign(&mut self, rhs: &$name) {
                    self.0 = self.0.wrapping_sub(rhs.0);
                }
            }

            impl MulAssign for $name {
                fn mul_assign(&mut self, rhs: Self) {
                    self.0 = self.0.wrapping_mul(rhs.0);
                }
            }

            impl MulAssign<&$name> for $name {
                fn mul_assign(&mut self, rhs: &$name) {
                    self.0 = self.0.wrapping_mul(rhs.0);
                }
            }

            impl Deref for $name {
                type Target = $primitive;

                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }

            impl From<$primitive> for $name {
                fn from(value: $primitive) -> Self {
                    Self(value)
                }
            }

            impl From<$name> for $primitive {
                fn from(value: $name) -> Self {
                    value.0
                }
            }

            impl From<&$primitive> for $name {
                fn from(value: &$primitive) -> Self {
                    Self(*value)
                }
            }

            impl From<&$name> for $primitive {
                fn from(value: &$name) -> Self {
                    value.0
                }
            }

            impl ShareIdentifier for $name {
                type Serialization = [u8; core::mem::size_of::<$primitive>()];

                fn serialize(&self) -> Self::Serialization {
                    self.0.to_be_bytes()
                }

                fn deserialize(serialized: &Self::Serialization) -> VsssResult<Self> {
                    Ok(Self($primitive::from_be_bytes(*serialized)))
                }

                fn zero() -> Self {
                    Self(0)
                }

                fn one() -> Self {
                    Self(1)
                }

                fn is_zero(&self) -> Choice {
                    self.0.ct_eq(&0)
                }

                fn random(mut rng: impl RngCore + CryptoRng) -> Self {
                    let mut buf = [0u8; core::mem::size_of::<$primitive>()];
                    rng.fill_bytes(&mut buf);
                    Self($primitive::from_be_bytes(buf))
                }

                fn invert(&self) -> VsssResult<Self> {
                    let r = Self::ONE.checked_div(self.0).ok_or(Error::InvalidShareIdentifier)?;
                    Ok(Self(r))
                }

                #[cfg(any(feature = "alloc", feature = "std"))]
                fn to_vec(&self) -> crate::Vec<u8> {
                    self.serialize().to_vec()
                }

                fn from_slice(vec: &[u8]) -> VsssResult<Self> {
                    if vec.len() != core::mem::size_of::<$primitive>() {
                        return Err(Error::InvalidShareIdentifier);
                    }
                    let repr: [u8; core::mem::size_of::<$primitive>()] = vec.try_into().expect("size to be correct");
                    Ok(Self($primitive::from_be_bytes(repr)))
                }
            }

            impl $name {
                /// Identifier with the value 1.
                pub const ONE: Self = Self(1);
            }
        )+
    };
    ($($name:ident => $primitive:ident AS $alt:ident),+$(,)*) => {
        $(
            /// A share identifier represented as a primitive integer.
            #[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
            pub struct $name(pub $primitive);

            impl ConditionallySelectable for $name {
                fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
                    let a = a.0 as $alt;
                    let b = b.0 as $alt;
                    let c = $alt::conditional_select(&a, &b, choice);
                    $name(c as $primitive)
                }
            }

            impl ConstantTimeEq for $name {
                fn ct_eq(&self, other: &Self) -> subtle::Choice {
                    self.0.ct_eq(&other.0)
                }
            }

            impl Add for $name {
                type Output = Self;

                fn add(self, rhs: Self) -> Self::Output {
                    $name(self.0.wrapping_add(rhs.0))
                }
            }

            impl Sub for $name {
                type Output = Self;

                fn sub(self, rhs: Self) -> Self::Output {
                    $name(self.0.wrapping_sub(rhs.0))
                }
            }

            impl Mul for $name {
                type Output = Self;

                fn mul(self, rhs: Self) -> Self::Output {
                    $name(self.0.wrapping_mul(rhs.0))
                }
            }

            impl AddAssign for $name {
                fn add_assign(&mut self, rhs: Self) {
                    self.0 = self.0.wrapping_add(rhs.0);
                }
            }

            impl AddAssign<&$name> for $name {
                fn add_assign(&mut self, rhs: &$name) {
                    self.0 = self.0.wrapping_add(rhs.0);
                }
            }

            impl SubAssign for $name {
                fn sub_assign(&mut self, rhs: Self) {
                    self.0 = self.0.wrapping_sub(rhs.0);
                }
            }

            impl SubAssign<&$name> for $name {
                fn sub_assign(&mut self, rhs: &$name) {
                    self.0 = self.0.wrapping_sub(rhs.0);
                }
            }

            impl MulAssign for $name {
                fn mul_assign(&mut self, rhs: Self) {
                    self.0 = self.0.wrapping_mul(rhs.0);
                }
            }

            impl MulAssign<&$name> for $name {
                fn mul_assign(&mut self, rhs: &$name) {
                    self.0 = self.0.wrapping_mul(rhs.0);
                }
            }

            impl Deref for $name {
                type Target = $primitive;

                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }

            impl From<$primitive> for $name {
                fn from(value: $primitive) -> Self {
                    Self(value)
                }
            }

            impl From<$name> for $primitive {
                fn from(value: $name) -> Self {
                    value.0
                }
            }

            impl From<&$primitive> for $name {
                fn from(value: &$primitive) -> Self {
                    Self(*value)
                }
            }

            impl From<&$name> for $primitive {
                fn from(value: &$name) -> Self {
                    value.0
                }
            }

            impl ShareIdentifier for $name {
                type Serialization = [u8; core::mem::size_of::<$primitive>()];

                fn serialize(&self) -> Self::Serialization {
                    (self.0 as $alt).to_be_bytes()
                }

                fn deserialize(serialized: &Self::Serialization) -> VsssResult<Self> {
                    Ok(Self($alt::from_be_bytes(*serialized) as $primitive))
                }

                fn zero() -> Self {
                    Self(0)
                }

                fn one() -> Self {
                    Self(1)
                }

                fn is_zero(&self) -> Choice {
                    self.0.ct_eq(&0)
                }

                fn random(mut rng: impl RngCore + CryptoRng) -> Self {
                    let mut buf = [0u8; core::mem::size_of::<$primitive>()];
                    rng.fill_bytes(&mut buf);
                    Self($primitive::from_be_bytes(buf))
                }

                fn invert(&self) -> VsssResult<Self> {
                    let r = Self::ONE.checked_div(self.0).ok_or(Error::InvalidShareIdentifier)?;
                    Ok(Self(r))
                }

                #[cfg(any(feature = "alloc", feature = "std"))]
                fn to_vec(&self) -> crate::Vec<u8> {
                    self.serialize().to_vec()
                }

                fn from_slice(vec: &[u8]) -> VsssResult<Self> {
                    if vec.len() != core::mem::size_of::<$primitive>() {
                        return Err(Error::InvalidShareIdentifier);
                    }
                    let repr: [u8; core::mem::size_of::<$primitive>()] = vec.try_into().expect("size to be correct");
                    Ok(Self($primitive::from_be_bytes(repr)))
                }
            }

            impl $name {
                /// Identifier with the value 1.
                pub const ONE: Self = Self(1);
            }
        )+
    };
}

impl_primitive_identifier!(
    IdentifierU8 => u8,
    IdentifierU16 => u16,
    IdentifierU32 => u32,
    IdentifierU64 => u64,
    IdentifierU128 => u128,
    IdentifierI8 => i8,
    IdentifierI16 => i16,
    IdentifierI32 => i32,
    IdentifierI64 => i64,
    IdentifierI128 => i128,
);

impl_primitive_identifier!(
    IdentifierIsize => isize AS i64,
    IdentifierUsize => usize AS u64,
);

/// A share identifier represented as a Big unsigned integer with
/// a fixed number of limbs.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct IdentifierUint<const LIMBS: usize>(pub Uint<LIMBS>)
where
    Uint<LIMBS>: ArrayEncoding;

impl<const LIMBS: usize> ConditionallySelectable for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let a = a.0;
        let b = b.0;
        let c = Uint::<LIMBS>::conditional_select(&a, &b, choice);
        Self(c)
    }
}

impl<const LIMBS: usize> ConstantTimeEq for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<const LIMBS: usize> Add for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.wrapping_add(&rhs.0))
    }
}

impl<const LIMBS: usize> Sub for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.wrapping_sub(&rhs.0))
    }
}

impl<const LIMBS: usize> Mul for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.wrapping_mul(&rhs.0))
    }
}

impl<const LIMBS: usize> AddAssign for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn add_assign(&mut self, rhs: Self) {
        self.0 = self.0.wrapping_add(&rhs.0);
    }
}

impl<const LIMBS: usize> AddAssign<&Self> for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn add_assign(&mut self, rhs: &Self) {
        self.0 = self.0.wrapping_add(&rhs.0);
    }
}

impl<const LIMBS: usize> SubAssign for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = self.0.wrapping_sub(&rhs.0);
    }
}

impl<const LIMBS: usize> SubAssign<&Self> for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn sub_assign(&mut self, rhs: &Self) {
        self.0 = self.0.wrapping_sub(&rhs.0);
    }
}

impl<const LIMBS: usize> MulAssign for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn mul_assign(&mut self, rhs: Self) {
        self.0 = self.0.wrapping_mul(&rhs.0);
    }
}

impl<const LIMBS: usize> MulAssign<&Self> for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn mul_assign(&mut self, rhs: &Self) {
        self.0 = self.0.wrapping_mul(&rhs.0);
    }
}

impl<const LIMBS: usize> Deref for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Target = Uint<LIMBS>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LIMBS: usize> From<Uint<LIMBS>> for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn from(value: Uint<LIMBS>) -> Self {
        Self(value)
    }
}

impl<const LIMBS: usize> From<&Uint<LIMBS>> for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn from(value: &Uint<LIMBS>) -> Self {
        Self(*value)
    }
}

impl<const LIMBS: usize> From<IdentifierUint<LIMBS>> for Uint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn from(value: IdentifierUint<LIMBS>) -> Self {
        value.0
    }
}

impl<const LIMBS: usize> ShareIdentifier for IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Serialization = <Uint<LIMBS> as Encoding>::Repr;

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

    fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        let inner = Uint::<LIMBS>::random(&mut rng);
        Self(inner)
    }

    fn invert(&self) -> VsssResult<Self> {
        let (den, is_zero) = NonZero::<Uint<LIMBS>>::const_new(self.0);
        if is_zero.into() {
            return Err(Error::InvalidShareIdentifier);
        }
        let r = Uint::<LIMBS>::ONE / den;
        Ok(Self(r))
    }

    fn from_slice(vec: &[u8]) -> VsssResult<Self> {
        if vec.len() != Uint::<LIMBS>::BYTES {
            return Err(Error::InvalidShareIdentifier);
        }
        Ok(Self(Uint::<LIMBS>::from_be_slice(vec)))
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.serialize().as_ref().to_vec()
    }
}

impl<const LIMBS: usize> IdentifierUint<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
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

    /// Convert from a generic byte array.
    pub fn from_generic_array(array: ByteArray<Uint<LIMBS>>) -> Self {
        Self(<Uint<LIMBS> as ArrayEncoding>::from_be_byte_array(array))
    }

    /// Convert to a generic byte array.
    pub fn to_generic_array(self) -> ByteArray<Uint<LIMBS>> {
        <Uint<LIMBS> as ArrayEncoding>::to_be_byte_array(&self.0)
    }
}

/// A share identifier represented as a residue modulo known at compile time.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct IdentifierResidue<MOD: ResidueParams<LIMBS>, const LIMBS: usize>(
    pub Residue<MOD, LIMBS>,
)
where
    Uint<LIMBS>: ArrayEncoding;

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> ConditionallySelectable
    for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let a = a.0;
        let b = b.0;
        let c = Residue::<MOD, LIMBS>::conditional_select(&a, &b, choice);
        Self(c)
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> ConstantTimeEq for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> Add for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> Sub for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> Mul for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> AddAssign for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> AddAssign<&Self>
    for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn add_assign(&mut self, rhs: &Self) {
        self.0 += rhs.0;
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> SubAssign for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> SubAssign<&Self>
    for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn sub_assign(&mut self, rhs: &Self) {
        self.0 -= rhs.0;
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> MulAssign for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn mul_assign(&mut self, rhs: Self) {
        self.0 *= rhs.0;
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> MulAssign<&Self>
    for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn mul_assign(&mut self, rhs: &Self) {
        self.0 *= rhs.0;
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

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> From<IdentifierResidue<MOD, LIMBS>>
    for Residue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn from(value: IdentifierResidue<MOD, LIMBS>) -> Self {
        value.0
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> ShareIdentifier
    for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Serialization = <Uint<LIMBS> as Encoding>::Repr;

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
            .map(|inner| Self(Residue::<MOD, LIMBS>::new(&inner.0)))
    }

    fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        let inner = Uint::<LIMBS>::random(&mut rng);
        Self(Residue::<MOD, LIMBS>::new(&inner))
    }

    fn invert(&self) -> VsssResult<Self> {
        let (value, succeeded) = self.0.invert();
        if !bool::from(succeeded) {
            return Err(Error::InvalidShareIdentifier);
        }
        Ok(Self(value))
    }

    fn from_slice(vec: &[u8]) -> VsssResult<Self> {
        IdentifierUint::<LIMBS>::from_slice(vec)
            .map(|inner| Self(Residue::<MOD, LIMBS>::new(&inner.0)))
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.serialize().as_ref().to_vec()
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    /// Identifier with the value 1.
    pub const ONE: Self = Self(Residue::<MOD, LIMBS>::ONE);
}

// /// A share identifier represented as a residue modulo known at runtime.
// #[derive(Copy, Clone, Debug, Eq, PartialEq)]
// pub struct IdentifierDynResidue<const LIMBS: usize>(pub DynResidue<LIMBS>)
//     where Uint<LIMBS>: ArrayEncoding;
//
// impl<const LIMBS: usize> Default for IdentifierDynResidue<LIMBS>
//     where Uint<LIMBS>: ArrayEncoding
// {
//     fn default() -> Self {
//         Self(DynResidue::<LIMBS>::zero(DynResidueParams::new(&Uint::<LIMBS>::ONE)))
//     }
// }
//
// impl<const LIMBS: usize> ConditionallySelectable for IdentifierDynResidue<LIMBS>
//     where Uint<LIMBS>: ArrayEncoding
// {
//     fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
//         let a = a.0;
//         let b = b.0;
//         let c = DynResidue::<LIMBS>::conditional_select(&a, &b, choice);
//         Self(c)
//     }
// }
//
// impl<const LIMBS: usize> ConstantTimeEq for IdentifierDynResidue<LIMBS>
//     where Uint<LIMBS>: ArrayEncoding
// {
//     fn ct_eq(&self, other: &Self) -> Choice {
//         self.0.ct_eq(&other.0)
//     }
// }
//
// impl<const LIMBS: usize> Add for IdentifierDynResidue<LIMBS>
//     where Uint<LIMBS>: ArrayEncoding
// {
//     type Output = Self;
//
//     fn add(self, rhs: Self) -> Self::Output {
//         Self(self.0 + rhs.0)
//     }
// }
//
// impl<const LIMBS: usize> Sub for IdentifierDynResidue<LIMBS>
//     where Uint<LIMBS>: ArrayEncoding
// {
//     type Output = Self;
//
//     fn sub(self, rhs: Self) -> Self::Output {
//         Self(self.0 - rhs.0)
//     }
// }
//
// impl<const LIMBS: usize> Mul for IdentifierDynResidue<LIMBS>
//     where Uint<LIMBS>: ArrayEncoding
// {
//     type Output = Self;
//
//     fn mul(self, rhs: Self) -> Self::Output {
//         Self(self.0 * rhs.0)
//     }
// }
//
// impl<const LIMBS: usize> AddAssign for IdentifierDynResidue<LIMBS>
//     where Uint<LIMBS>: ArrayEncoding
// {
//     fn add_assign(&mut self, rhs: Self) {
//         self.0 += rhs.0;
//     }
// }
//
// impl<const LIMBS: usize> AddAssign<&Self> for IdentifierDynResidue<LIMBS>
//     where Uint<LIMBS>: ArrayEncoding
// {
//     fn add_assign(&mut self, rhs: &Self) {
//         self.0 += rhs.0;
//     }
// }
//
// impl<const LIMBS: usize> SubAssign for IdentifierDynResidue<LIMBS>
//     where Uint<LIMBS>: ArrayEncoding
// {
//     fn sub_assign(&mut self, rhs: Self) {
//         self.0 -= rhs.0;
//     }
// }
//
// impl<const LIMBS: usize> SubAssign<&Self> for IdentifierDynResidue<LIMBS>
//     where Uint<LIMBS>: ArrayEncoding
// {
//     fn sub_assign(&mut self, rhs: &Self) {
//         self.0 -= rhs.0;
//     }
// }
//
// impl<const LIMBS: usize> MulAssign for IdentifierDynResidue<LIMBS>
//     where Uint<LIMBS>: ArrayEncoding
// {
//     fn mul_assign(&mut self, rhs: Self) {
//         self.0 *= rhs.0;
//     }
// }
//
// impl<const LIMBS: usize> MulAssign<&Self> for IdentifierDynResidue<LIMBS>
//     where Uint<LIMBS>: ArrayEncoding
// {
//     fn mul_assign(&mut self, rhs: &Self) {
//         self.0 *= rhs.0;
//     }
// }
//
// impl<const LIMBS: usize> Deref for IdentifierDynResidue<LIMBS>
//     where Uint<LIMBS>: ArrayEncoding
// {
//     type Target = DynResidue<LIMBS>;
//
//     fn deref(&self) -> &Self::Target {
//         &self.0
//     }
// }
//
// impl<const LIMBS: usize> From<DynResidue<LIMBS>> for IdentifierDynResidue<LIMBS>
//     where Uint<LIMBS>: ArrayEncoding
// {
//     fn from(value: DynResidue<LIMBS>) -> Self {
//         Self(value)
//     }
// }
//
// impl<const LIMBS: usize> From<&DynResidue<LIMBS>> for IdentifierDynResidue<LIMBS>
//     where Uint<LIMBS>: ArrayEncoding
// {
//     fn from(value: &DynResidue<LIMBS>) -> Self {
//         Self(*value)
//     }
// }
//
// impl<const LIMBS: usize> From<IdentifierDynResidue<LIMBS>> for DynResidue<LIMBS>
//     where Uint<LIMBS>: ArrayEncoding
// {
//     fn from(value: IdentifierDynResidue<LIMBS>) -> Self {
//         value.0
//     }
// }
//
// impl<const LIMBS: usize, const WIDE_LIMBS: usize> ShareIdentifier for IdentifierDynResidue<LIMBS>
//     where Uint<LIMBS>: ArrayEncoding + Concat<Output = Uint<WIDE_LIMBS>>,
//             Uint<WIDE_LIMBS>: ArrayEncoding + Split<Output = Uint<LIMBS>>,
// {
//     type Serialization = <Uint<WIDE_LIMBS> as Encoding>::Repr;
//
//     fn serialize(&self) -> Self::Serialization {
//         let modulus = self.0.params().modulus();
//         let value = self.0.retrieve();
//         let wide_value = <Uint::<LIMBS> as Concat>::concat(&value, modulus);
//         wide_value.to_be_bytes()
//     }
//
//     fn deserialize(serialized: &Self::Serialization) -> VsssResult<Self> {
//         let wide_value = <Uint::<WIDE_LIMBS> as Encoding>::from_be_bytes(*serialized);
//         let (modulus, value) = <Uint::<WIDE_LIMBS> as Split>::split(&wide_value);
//         let params = DynResidueParams::new(&modulus);
//         Ok(Self(DynResidue::<LIMBS>::new(&value, params)))
//     }
//
//     fn is_zero(&self) -> Choice {
//         self.0.retrieve().is_zero()
//     }
//
//     fn random(mut rng: impl RngCore + CryptoRng) -> Self {
//         let inner = DynResidue::<LIMBS>::random(&mut rng);
//         Self(DynResidue::<LIMBS>::new(&inner))
//     }
//
//     fn invert(&self) -> VsssResult<Self> {
//         let (value, succeeded) = self.0.invert();
//         if !bool::from(succeeded) {
//             return Err(Error::InvalidShareIdentifier);
//         }
//         Ok(Self(value))
//     }
//
//     fn from_slice(vec: &[u8]) -> VsssResult<Self> {
//         if vec.len() != Uint::<WIDE_LIMBS>::BYTES {
//             return Err(Error::InvalidShareIdentifier);
//         }
//         let wide_value = Uint::<WIDE_LIMBS>::from_be_slice(vec);
//         let (modulus, value) = <Uint::<WIDE_LIMBS> as Split>::split(&wide_value);
//         let params = DynResidueParams::new(&modulus);
//         Ok(Self(DynResidue::<LIMBS>::new(&value, params)))
//     }
//
//     #[cfg(any(feature = "alloc", feature = "std"))]
//     fn to_vec(&self) -> Vec<u8> {
//         self.serialize().as_ref().to_vec()
//     }
// }
//
#[cfg(any(feature = "alloc", feature = "std"))]
pub use bigint::IdentifierVec;

#[cfg(any(feature = "alloc", feature = "std"))]
mod bigint {
    use super::ShareIdentifier;
    use crate::{Box, Error, Vec, VsssResult};
    use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
    use num_bigint::BigUint;
    use num_traits::Zero;
    use rand_core::{CryptoRng, RngCore};
    use subtle::Choice;

    /// A share identifier represented as a big endian byte sequence.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    pub struct IdentifierVec(pub(crate) BigUint);

    impl Add for IdentifierVec {
        type Output = Self;

        fn add(self, rhs: Self) -> Self::Output {
            Self(self.0 + rhs.0)
        }
    }

    impl Sub for IdentifierVec {
        type Output = Self;

        fn sub(self, rhs: Self) -> Self::Output {
            Self(self.0 - rhs.0)
        }
    }

    impl Mul for IdentifierVec {
        type Output = Self;

        fn mul(self, rhs: Self) -> Self::Output {
            Self(self.0 * rhs.0)
        }
    }

    impl AddAssign for IdentifierVec {
        fn add_assign(&mut self, rhs: Self) {
            self.0 += rhs.0;
        }
    }

    impl AddAssign<&Self> for IdentifierVec {
        fn add_assign(&mut self, rhs: &Self) {
            self.0 += &rhs.0;
        }
    }

    impl SubAssign for IdentifierVec {
        fn sub_assign(&mut self, rhs: Self) {
            self.0 -= rhs.0;
        }
    }

    impl SubAssign<&Self> for IdentifierVec {
        fn sub_assign(&mut self, rhs: &Self) {
            self.0 -= &rhs.0;
        }
    }

    impl MulAssign for IdentifierVec {
        fn mul_assign(&mut self, rhs: Self) {
            self.0 *= rhs.0;
        }
    }

    impl MulAssign<&Self> for IdentifierVec {
        fn mul_assign(&mut self, rhs: &Self) {
            self.0 *= &rhs.0;
        }
    }

    impl From<Vec<u8>> for IdentifierVec {
        fn from(value: Vec<u8>) -> Self {
            Self::from(value.as_slice())
        }
    }

    impl From<&Vec<u8>> for IdentifierVec {
        fn from(value: &Vec<u8>) -> Self {
            Self::from(value.as_slice())
        }
    }

    impl From<&[u8]> for IdentifierVec {
        fn from(value: &[u8]) -> Self {
            Self(BigUint::from_bytes_be(value))
        }
    }

    impl From<Box<[u8]>> for IdentifierVec {
        fn from(value: Box<[u8]>) -> Self {
            Self::from(value.as_ref())
        }
    }

    impl From<IdentifierVec> for Vec<u8> {
        fn from(value: IdentifierVec) -> Self {
            value.0.to_bytes_be()
        }
    }

    impl From<&IdentifierVec> for Vec<u8> {
        fn from(value: &IdentifierVec) -> Self {
            value.0.to_bytes_be()
        }
    }

    impl ShareIdentifier for IdentifierVec {
        type Serialization = Vec<u8>;

        fn zero() -> Self {
            Self(BigUint::zero())
        }

        fn one() -> Self {
            Self(BigUint::one())
        }

        fn is_zero(&self) -> Choice {
            Choice::from(if self.0.is_zero() { 1 } else { 0 })
        }

        fn serialize(&self) -> Self::Serialization {
            self.0.to_bytes_be()
        }

        fn deserialize(serialized: &Self::Serialization) -> VsssResult<Self> {
            Ok(IdentifierVec(BigUint::from_bytes_be(serialized)))
        }

        fn random(mut rng: impl RngCore + CryptoRng) -> Self {
            let mut buf = vec![0u8; 32];
            rng.fill_bytes(&mut buf);
            IdentifierVec(BigUint::from_bytes_be(&buf))
        }

        fn invert(&self) -> VsssResult<Self> {
            if self.0.is_zero() {
                return Err(Error::InvalidShareIdentifier);
            }
            let r = Self::one().0 / &self.0;
            Ok(Self(r))
        }

        fn from_slice(vec: &[u8]) -> VsssResult<Self> {
            Ok(IdentifierVec(BigUint::from_bytes_be(vec)))
        }

        #[cfg(any(feature = "alloc", feature = "std"))]
        fn to_vec(&self) -> Vec<u8> {
            self.0.to_bytes_be()
        }
    }

    impl IdentifierVec {
        /// Create a new identifier with the value 1.
        pub fn one() -> Self {
            Self(BigUint::from(1u8))
        }
    }
}
