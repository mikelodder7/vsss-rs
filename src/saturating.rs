use core::{
    fmt::{self, Binary, Display, Formatter, LowerHex, Octal, UpperHex},
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Rem, RemAssign, Sub, SubAssign},
};
use crypto_bigint::{
    ArrayEncoding, Choice as BigintChoice, CtEq as BigintCtEq, Random, Uint, Zero,
};
use num_traits::{SaturatingAdd, SaturatingMul, SaturatingSub};
use rand_core::{Rng, TryRng};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Provides intentionally saturating arithmetic on `T`.
///
/// This is analogous to the [`core::num::Saturating`] but allows this crate to
/// define trait impls for [`Uint`](https://docs.rs/crypto-bigint/latest/crypto_bigint/struct.Uint.html).
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize))]
#[repr(transparent)]
pub struct Saturating<const LIMBS: usize>(pub Uint<LIMBS>)
where
    Uint<LIMBS>: ArrayEncoding;

impl<const LIMBS: usize> Zero for Saturating<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn zero() -> Self {
        Self(Uint::<LIMBS>::ZERO)
    }
}

impl<const LIMBS: usize> BigintCtEq for Saturating<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn ct_eq(&self, other: &Self) -> BigintChoice {
        BigintCtEq::ct_eq(&self.0, &other.0)
    }
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
        ConstantTimeEq::ct_eq(&self.0, &other.0)
    }
}

impl<const LIMBS: usize> Random for Saturating<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn try_random_from_rng<R: TryRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        Uint::<LIMBS>::try_random_from_rng(rng).map(Self)
    }

    fn random_from_rng<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Self(Uint::<LIMBS>::random_from_rng(rng))
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
        Self(self.0.checked_div(&other.0).unwrap_or(Uint::<LIMBS>::MAX))
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
        Self(self.0.checked_rem(&other.0).unwrap_or(Uint::<LIMBS>::ZERO))
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

#[cfg(test)]
mod tests {
    use super::Saturating;
    use core::ops::{Add, Div, Mul, Rem, Sub};
    use elliptic_curve::bigint::{Uint, Zero};
    use num_traits::{SaturatingAdd, SaturatingMul, SaturatingSub};
    use std::{format, string::ToString};
    use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

    fn n(value: u8) -> Saturating<1> {
        Saturating(Uint::<1>::from_be_slice(&[0, 0, 0, 0, 0, 0, 0, value]))
    }

    #[test]
    fn formatting_and_constant_time_traits_delegate_to_inner_uint() {
        let zero = Saturating::<1>::zero();
        let one = n(1);

        assert_eq!(zero.to_string(), "0000000000000000");
        assert_eq!(format!("{one:b}"), format!("{:b}", one.0));
        assert_eq!(format!("{one:x}"), format!("{:x}", one.0));
        assert_eq!(format!("{one:X}"), format!("{:X}", one.0));
        assert_eq!(ConstantTimeEq::ct_eq(&one, &one).unwrap_u8(), 1);
        assert_eq!(ConstantTimeEq::ct_eq(&one, &zero).unwrap_u8(), 0);
        assert_eq!(
            Saturating::conditional_select(&zero, &one, Choice::from(1u8)),
            one
        );
    }

    #[test]
    fn arithmetic_operators_and_assignments_saturate() {
        let one = n(1);
        let two = n(2);
        let three = n(3);

        assert_eq!(one + two, three);
        assert_eq!(
            <Saturating<1> as Add<&Saturating<1>>>::add(one, &two),
            three
        );
        assert_eq!(
            <&Saturating<1> as Add<Saturating<1>>>::add(&one, two),
            three
        );
        assert_eq!(
            <&Saturating<1> as Add<&Saturating<1>>>::add(&one, &two),
            three
        );
        assert_eq!(three - two, one);
        assert_eq!(
            <Saturating<1> as Sub<&Saturating<1>>>::sub(three, &two),
            one
        );
        assert_eq!(
            <&Saturating<1> as Sub<Saturating<1>>>::sub(&three, two),
            one
        );
        assert_eq!(
            <&Saturating<1> as Sub<&Saturating<1>>>::sub(&three, &two),
            one
        );
        assert_eq!(two * three, n(6));
        assert_eq!(
            <Saturating<1> as Mul<&Saturating<1>>>::mul(two, &three),
            n(6)
        );
        assert_eq!(
            <&Saturating<1> as Mul<Saturating<1>>>::mul(&two, three),
            n(6)
        );
        assert_eq!(
            <&Saturating<1> as Mul<&Saturating<1>>>::mul(&two, &three),
            n(6)
        );
        assert_eq!(three / one, three);
        assert_eq!(
            <Saturating<1> as Div<&Saturating<1>>>::div(three, &one),
            three
        );
        assert_eq!(
            <&Saturating<1> as Div<Saturating<1>>>::div(&three, one),
            three
        );
        assert_eq!(
            <&Saturating<1> as Div<&Saturating<1>>>::div(&three, &one),
            three
        );
        assert_eq!(three % two, one);
        assert_eq!(
            <Saturating<1> as Rem<&Saturating<1>>>::rem(three, &two),
            one
        );
        assert_eq!(
            <&Saturating<1> as Rem<Saturating<1>>>::rem(&three, two),
            one
        );
        assert_eq!(
            <&Saturating<1> as Rem<&Saturating<1>>>::rem(&three, &two),
            one
        );

        let mut assigned = one;
        assigned += two;
        assert_eq!(assigned, three);
        assigned -= &one;
        assert_eq!(assigned, two);
        assigned *= three;
        assert_eq!(assigned, n(6));
        assigned /= &two;
        assert_eq!(assigned, three);
        assigned %= two;
        assert_eq!(assigned, one);

        assert_eq!(SaturatingAdd::saturating_add(&two, &three), n(5));
        assert_eq!(SaturatingSub::saturating_sub(&two, &three), n(0));
        assert_eq!(SaturatingMul::saturating_mul(&two, &three), n(6));
        assert_eq!(one / Saturating::<1>::zero(), Saturating(Uint::<1>::MAX));
        assert_eq!(one % Saturating::<1>::zero(), Saturating::<1>::zero());
    }
}
