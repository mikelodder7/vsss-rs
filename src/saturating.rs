use core::{
    fmt::{self, Binary, Display, Formatter, LowerHex, Octal, UpperHex},
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Rem, RemAssign, Sub, SubAssign},
};
use elliptic_curve::{
    bigint::{ArrayEncoding, Random, Uint, Zero},
    rand_core::CryptoRngCore,
};
use num::traits::{SaturatingAdd, SaturatingMul, SaturatingSub};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

/// Provides intentionally-saturating arithmetic on `T`.
///
/// This is analogous to the [`core::num::Saturating`] but allows this crate to
/// define trait impls for [`crypto-bigint::Uint`].
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Hash, Zeroize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct Saturating<const LIMBS: usize>(pub Uint<LIMBS>)
where
    Uint<LIMBS>: ArrayEncoding;

impl<const LIMBS: usize> Zero for Saturating<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    const ZERO: Self = Self(Uint::<LIMBS>::ZERO);
}

impl<const LIMBS: usize> Display for Saturating<LIMBS>
where
    Uint<LIMBS>: Display + ArrayEncoding,
{
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        <Uint<LIMBS> as Display>::fmt(&self.0, f)
    }
}

impl<const LIMBS: usize> Binary for Saturating<LIMBS>
where
    Uint<LIMBS>: Binary + ArrayEncoding,
{
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        <Uint<LIMBS> as Binary>::fmt(&self.0, f)
    }
}

impl<const LIMBS: usize> Octal for Saturating<LIMBS>
where
    Uint<LIMBS>: Octal + ArrayEncoding,
{
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        <Uint<LIMBS> as Octal>::fmt(&self.0, f)
    }
}

impl<const LIMBS: usize> LowerHex for Saturating<LIMBS>
where
    Uint<LIMBS>: LowerHex + ArrayEncoding,
{
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        <Uint<LIMBS> as LowerHex>::fmt(&self.0, f)
    }
}

impl<const LIMBS: usize> UpperHex for Saturating<LIMBS>
where
    Uint<LIMBS>: UpperHex + ArrayEncoding,
{
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        <Uint<LIMBS> as UpperHex>::fmt(&self.0, f)
    }
}

impl<const LIMBS: usize> ConditionallySelectable for Saturating<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(Uint::<LIMBS>::conditional_select(&a.0, &b.0, choice))
    }
}

impl<const LIMBS: usize> ConstantTimeEq for Saturating<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<const LIMBS: usize> Random for Saturating<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self(Uint::<LIMBS>::random(rng))
    }
}

macro_rules! impl_arithmetic_ops {
    ($($op_trait:ident AS $op_name:ident => $func_name:ident),+$(,)*) => {
        $(
            impl<const LIMBS: usize> $op_trait for Saturating<LIMBS>
                where Uint<LIMBS>: ArrayEncoding
            {
                type Output = Self;

                fn $op_name(self, other: Self) -> Self {
                    Self(self.0.$func_name(&other.0))
                }
            }

            impl<const LIMBS: usize> $op_trait<&Saturating<LIMBS>> for Saturating<LIMBS>
                where Uint<LIMBS>: ArrayEncoding
            {
                type Output = Self;

                fn $op_name(self, other: &Self) -> Self {
                    Self(self.0.$func_name(&other.0))
                }
            }

            impl<const LIMBS: usize> $op_trait<Saturating<LIMBS>> for &Saturating<LIMBS>
                where Uint<LIMBS>: ArrayEncoding
            {
                type Output = Saturating<LIMBS>;

                fn $op_name(self, other: Saturating<LIMBS>) -> Saturating<LIMBS> {
                    Saturating(self.0.$func_name(&other.0))
                }
            }

            impl<const LIMBS: usize> $op_trait<&Saturating<LIMBS>> for &Saturating<LIMBS>
                where Uint<LIMBS>: ArrayEncoding
            {
                type Output = Saturating<LIMBS>;

                fn $op_name(self, other: &Saturating<LIMBS>) -> Saturating<LIMBS> {
                    Saturating(self.0.$func_name(&other.0))
                }
            }
        )+
    };
}

macro_rules! impl_arithmetic_assign_ops {
    ($($op_trait:ident AS $op_name:ident => $op:tt),+$(,)*) => {
        $(
            impl<const LIMBS: usize> $op_trait for Saturating<LIMBS>
                where Uint<LIMBS>: ArrayEncoding
            {
                fn $op_name(&mut self, other: Self) {
                    *self = *self $op other;
                }
            }

            impl<const LIMBS: usize> $op_trait<&Saturating<LIMBS>> for Saturating<LIMBS>
                where Uint<LIMBS>: ArrayEncoding
            {
                fn $op_name(&mut self, other: &Self) {
                    *self = *self $op *other;
                }
            }
        )+
    };
}

impl_arithmetic_ops!(
    Add AS add => saturating_add,
    Sub AS sub => saturating_sub,
    Mul AS mul => saturating_mul,
);

impl_arithmetic_assign_ops!(
    AddAssign AS add_assign => +,
    SubAssign AS sub_assign => -,
    MulAssign AS mul_assign => *,
    DivAssign AS div_assign => /,
    RemAssign AS rem_assign => %,
);

impl<const LIMBS: usize> Div for Saturating<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Output = Self;

    fn div(self, other: Self) -> Self {
        Self(
            self.0
                .checked_div(&other.0)
                .unwrap_or_else(|| Uint::<LIMBS>::MAX),
        )
    }
}

impl<const LIMBS: usize> Div<&Saturating<LIMBS>> for Saturating<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Output = Self;

    fn div(self, other: &Self) -> Self {
        self / *other
    }
}

impl<const LIMBS: usize> Div<Saturating<LIMBS>> for &Saturating<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Output = Saturating<LIMBS>;

    fn div(self, other: Saturating<LIMBS>) -> Self::Output {
        (*self) / other
    }
}

impl<const LIMBS: usize> Div<&Saturating<LIMBS>> for &Saturating<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Output = Saturating<LIMBS>;

    fn div(self, other: &Saturating<LIMBS>) -> Self::Output {
        (*self) / *other
    }
}

impl<const LIMBS: usize> Rem for Saturating<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Output = Self;

    fn rem(self, other: Self) -> Self {
        Self(
            self.0
                .checked_rem(&other.0)
                .unwrap_or_else(|| Uint::<LIMBS>::ZERO),
        )
    }
}

impl<const LIMBS: usize> Rem<&Saturating<LIMBS>> for Saturating<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Output = Self;

    fn rem(self, other: &Self) -> Self {
        self % *other
    }
}

impl<const LIMBS: usize> Rem<Saturating<LIMBS>> for &Saturating<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Output = Saturating<LIMBS>;

    fn rem(self, other: Saturating<LIMBS>) -> Self::Output {
        (*self) % other
    }
}

impl<const LIMBS: usize> Rem<&Saturating<LIMBS>> for &Saturating<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Output = Saturating<LIMBS>;

    fn rem(self, other: &Saturating<LIMBS>) -> Self::Output {
        (*self) % *other
    }
}

impl<const LIMBS: usize> SaturatingAdd for Saturating<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn saturating_add(&self, v: &Self) -> Self {
        Self(self.0.saturating_add(&v.0))
    }
}

impl<const LIMBS: usize> SaturatingSub for Saturating<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn saturating_sub(&self, v: &Self) -> Self {
        Self(self.0.saturating_sub(&v.0))
    }
}

impl<const LIMBS: usize> SaturatingMul for Saturating<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn saturating_mul(&self, v: &Self) -> Self {
        Self(self.0.saturating_mul(&v.0))
    }
}
