use crate::util::CtIsZero;
use crate::{Error, ShareIdentifier, VsssResult};
use core::{
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::Hash,
    ops::{
        Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div,
        DivAssign, Index, IndexMut, Mul, MulAssign, Neg, Not, Range, RangeFrom, RangeFull,
        RangeInclusive, RangeTo, RangeToInclusive, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign,
        Sub, SubAssign,
    },
    str::FromStr,
};
use elliptic_curve::PrimeField;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};
use zeroize::Zeroize;

/// Encapsulate a fixed-size array of big-endian bytes that can be used as a share identifier
/// to represent bigger than 1 byte integer values.
///
/// For example, u16, u32, u64, u128 should use
/// [`SmallArray<2>`], [`SmallArray<4>`], [`SmallArray<8>`], [`SmallArray<16>`] respectively.
///
/// This type implements the common operations to avoid having to convert to and from
/// big-endian byte arrays.
#[derive(Debug, Clone)]
pub struct SmallArray<const N: usize>(pub [u8; N]);

impl<const N: usize> AsRef<[u8]> for SmallArray<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> AsMut<[u8]> for SmallArray<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<const N: usize> Index<usize> for SmallArray<N> {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<const N: usize> Index<Range<usize>> for SmallArray<N> {
    type Output = [u8];

    fn index(&self, index: Range<usize>) -> &Self::Output {
        &self.0[index]
    }
}

impl<const N: usize> Index<RangeFrom<usize>> for SmallArray<N> {
    type Output = [u8];

    fn index(&self, index: RangeFrom<usize>) -> &Self::Output {
        &self.0[index]
    }
}

impl<const N: usize> Index<RangeTo<usize>> for SmallArray<N> {
    type Output = [u8];

    fn index(&self, index: RangeTo<usize>) -> &Self::Output {
        &self.0[index]
    }
}

impl<const N: usize> Index<RangeInclusive<usize>> for SmallArray<N> {
    type Output = [u8];

    fn index(&self, index: RangeInclusive<usize>) -> &Self::Output {
        &self.0[index]
    }
}

impl<const N: usize> Index<RangeToInclusive<usize>> for SmallArray<N> {
    type Output = [u8];

    fn index(&self, index: RangeToInclusive<usize>) -> &Self::Output {
        &self.0[index]
    }
}

impl<const N: usize> Index<RangeFull> for SmallArray<N> {
    type Output = [u8];

    fn index(&self, index: RangeFull) -> &Self::Output {
        &self.0[index]
    }
}

impl<const N: usize> IndexMut<usize> for SmallArray<N> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<const N: usize> Default for SmallArray<N> {
    fn default() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> From<[u8; N]> for SmallArray<N> {
    fn from(arr: [u8; N]) -> Self {
        Self::from_be_bytes(arr)
    }
}

impl<const N: usize> From<&[u8; N]> for SmallArray<N> {
    fn from(arr: &[u8; N]) -> Self {
        Self(*arr)
    }
}

impl<const N: usize> Zeroize for SmallArray<N> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> SmallArray<N> {
    /// Convert a big endian byte array into a [`SmallArray<N>`].
    pub fn from_be_bytes(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Convert a little endian byte array into a [`SmallArray<N>`].
    pub fn from_le_bytes(mut bytes: [u8; N]) -> Self {
        bytes.reverse();
        Self(bytes)
    }

    /// Try to convert a big endian byte slice into a [`SmallArray<N>`].
    pub fn try_from_be_slice(bytes: &[u8]) -> VsssResult<Self> {
        if bytes.len() != N {
            return Err(Error::InvalidShareConversion);
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Try to convert a little endian byte slice into a [`SmallArray<N>`].
    pub fn try_from_le_slice(bytes: &[u8]) -> VsssResult<Self> {
        if bytes.len() != N {
            return Err(Error::InvalidShareConversion);
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(bytes);
        arr.reverse();
        Ok(Self(arr))
    }

    /// Convert a [`SmallArray<N>`] into a big endian byte array.
    pub fn to_be_bytes(&self) -> [u8; N] {
        self.0
    }

    /// Convert a [`SmallArray<N>`] into a little endian byte array.
    pub fn to_le_bytes(&self) -> [u8; N] {
        let mut arr = self.0;
        arr.reverse();
        arr
    }
}

impl<const N: usize> ConstantTimeEq for SmallArray<N> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

macro_rules! trait_impl {
    (LHS = $lhs:path, RHS = $rhs:ident) => {
        impl Add<&$rhs> for &$lhs {
            type Output = $lhs;

            fn add(self, rhs: &$rhs) -> Self::Output {
                *self + *rhs
            }
        }

        impl Add<&$rhs> for $lhs {
            type Output = $lhs;

            fn add(self, rhs: &$rhs) -> Self::Output {
                self + *rhs
            }
        }

        impl Add<$rhs> for &$lhs {
            type Output = $lhs;

            fn add(self, rhs: $rhs) -> Self::Output {
                *self + rhs
            }
        }

        impl Add<$rhs> for $lhs {
            type Output = $lhs;

            fn add(self, rhs: $rhs) -> Self::Output {
                let l = $rhs::from(self);
                let r = $rhs::from(rhs);
                (l + r).into()
            }
        }

        impl Add<&$lhs> for &$rhs {
            type Output = $lhs;

            fn add(self, rhs: &$lhs) -> Self::Output {
                *self + *rhs
            }
        }

        impl Add<&$lhs> for $rhs {
            type Output = $lhs;

            fn add(self, rhs: &$lhs) -> Self::Output {
                self + *rhs
            }
        }

        impl Add<$lhs> for &$rhs {
            type Output = $lhs;

            fn add(self, rhs: $lhs) -> Self::Output {
                *self + rhs
            }
        }

        impl Add<$lhs> for $rhs {
            type Output = $lhs;

            fn add(self, rhs: $lhs) -> Self::Output {
                let l = $rhs::from(self);
                let r = $rhs::from(rhs);
                (l + r).into()
            }
        }

        impl AddAssign<&$rhs> for $lhs {
            fn add_assign(&mut self, rhs: &$rhs) {
                *self += *rhs;
            }
        }

        impl AddAssign<$rhs> for $lhs {
            fn add_assign(&mut self, rhs: $rhs) {
                let l = $rhs::from(*self);
                let r = $rhs::from(rhs);
                self.0.copy_from_slice((l + r).to_be_bytes().as_ref());
            }
        }

        impl AddAssign<&$lhs> for $rhs {
            fn add_assign(&mut self, rhs: &$lhs) {
                *self += $rhs::from(*rhs);
            }
        }

        impl AddAssign<$lhs> for $rhs {
            fn add_assign(&mut self, rhs: $lhs) {
                *self += $rhs::from(rhs);
            }
        }

        impl Sub<&$rhs> for &$lhs {
            type Output = $lhs;

            fn sub(self, rhs: &$rhs) -> Self::Output {
                *self - *rhs
            }
        }

        impl Sub<&$rhs> for $lhs {
            type Output = $lhs;

            fn sub(self, rhs: &$rhs) -> Self::Output {
                self - *rhs
            }
        }

        impl Sub<$rhs> for &$lhs {
            type Output = $lhs;

            fn sub(self, rhs: $rhs) -> Self::Output {
                *self - rhs
            }
        }

        impl Sub<$rhs> for $lhs {
            type Output = $lhs;

            fn sub(self, rhs: $rhs) -> Self::Output {
                let l = $rhs::from(self);
                let r = $rhs::from(rhs);
                (l - r).into()
            }
        }

        impl Sub<&$lhs> for &$rhs {
            type Output = $lhs;

            fn sub(self, rhs: &$lhs) -> Self::Output {
                *self - *rhs
            }
        }

        impl Sub<&$lhs> for $rhs {
            type Output = $lhs;

            fn sub(self, rhs: &$lhs) -> Self::Output {
                self - *rhs
            }
        }

        impl Sub<$lhs> for &$rhs {
            type Output = $lhs;

            fn sub(self, rhs: $lhs) -> Self::Output {
                *self - rhs
            }
        }

        impl Sub<$lhs> for $rhs {
            type Output = $lhs;

            fn sub(self, rhs: $lhs) -> Self::Output {
                let l = $rhs::from(self);
                let r = $rhs::from(rhs);
                (l - r).into()
            }
        }

        impl SubAssign<&$rhs> for $lhs {
            fn sub_assign(&mut self, rhs: &$rhs) {
                *self -= *rhs;
            }
        }

        impl SubAssign<$rhs> for $lhs {
            fn sub_assign(&mut self, rhs: $rhs) {
                let l = $rhs::from(*self);
                let r = $rhs::from(rhs);
                self.0.copy_from_slice((l - r).to_be_bytes().as_ref());
            }
        }

        impl SubAssign<&$lhs> for $rhs {
            fn sub_assign(&mut self, rhs: &$lhs) {
                *self -= $rhs::from(*rhs);
            }
        }

        impl SubAssign<$lhs> for $rhs {
            fn sub_assign(&mut self, rhs: $lhs) {
                *self -= $rhs::from(rhs);
            }
        }

        impl Mul<&$rhs> for &$lhs {
            type Output = $lhs;

            fn mul(self, rhs: &$rhs) -> Self::Output {
                *self * *rhs
            }
        }

        impl Mul<&$rhs> for $lhs {
            type Output = $lhs;

            fn mul(self, rhs: &$rhs) -> Self::Output {
                self * *rhs
            }
        }

        impl Mul<$rhs> for &$lhs {
            type Output = $lhs;

            fn mul(self, rhs: $rhs) -> Self::Output {
                *self * rhs
            }
        }

        impl Mul<$rhs> for $lhs {
            type Output = $lhs;

            fn mul(self, rhs: $rhs) -> Self::Output {
                let l = $rhs::from(self);
                let r = $rhs::from(rhs);
                (l * r).into()
            }
        }

        impl Mul<&$lhs> for &$rhs {
            type Output = $lhs;

            fn mul(self, rhs: &$lhs) -> Self::Output {
                *self * *rhs
            }
        }

        impl Mul<&$lhs> for $rhs {
            type Output = $lhs;

            fn mul(self, rhs: &$lhs) -> Self::Output {
                self * *rhs
            }
        }

        impl Mul<$lhs> for &$rhs {
            type Output = $lhs;

            fn mul(self, rhs: $lhs) -> Self::Output {
                *self * rhs
            }
        }

        impl Mul<$lhs> for $rhs {
            type Output = $lhs;

            fn mul(self, rhs: $lhs) -> Self::Output {
                let l = $rhs::from(self);
                let r = $rhs::from(rhs);
                (l * r).into()
            }
        }

        impl MulAssign<&$rhs> for $lhs {
            fn mul_assign(&mut self, rhs: &$rhs) {
                *self *= *rhs;
            }
        }

        impl MulAssign<$rhs> for $lhs {
            fn mul_assign(&mut self, rhs: $rhs) {
                let l = $rhs::from(*self);
                let r = $rhs::from(rhs);
                self.0.copy_from_slice((l * r).to_be_bytes().as_ref());
            }
        }

        impl MulAssign<&$lhs> for $rhs {
            fn mul_assign(&mut self, rhs: &$lhs) {
                *self *= $rhs::from(rhs);
            }
        }

        impl MulAssign<$lhs> for $rhs {
            fn mul_assign(&mut self, rhs: $lhs) {
                *self *= $rhs::from(rhs);
            }
        }

        impl Div<&$rhs> for &$lhs {
            type Output = $lhs;

            fn div(self, rhs: &$rhs) -> Self::Output {
                *self / *rhs
            }
        }

        impl Div<&$rhs> for $lhs {
            type Output = $lhs;

            fn div(self, rhs: &$rhs) -> Self::Output {
                self / *rhs
            }
        }

        impl Div<$rhs> for &$lhs {
            type Output = $lhs;

            fn div(self, rhs: $rhs) -> Self::Output {
                *self / rhs
            }
        }

        impl Div<$rhs> for $lhs {
            type Output = $lhs;

            fn div(self, rhs: $rhs) -> Self::Output {
                let l = $rhs::from(self);
                let r = $rhs::from(rhs);
                (l / r).into()
            }
        }

        impl Div<&$lhs> for &$rhs {
            type Output = $lhs;

            fn div(self, rhs: &$lhs) -> Self::Output {
                *self / *rhs
            }
        }

        impl Div<&$lhs> for $rhs {
            type Output = $lhs;

            fn div(self, rhs: &$lhs) -> Self::Output {
                self / *rhs
            }
        }

        impl Div<$lhs> for &$rhs {
            type Output = $lhs;

            fn div(self, rhs: $lhs) -> Self::Output {
                *self / rhs
            }
        }

        impl Div<$lhs> for $rhs {
            type Output = $lhs;

            fn div(self, rhs: $lhs) -> Self::Output {
                let l = $rhs::from(self);
                let r = $rhs::from(rhs);
                (l / r).into()
            }
        }

        impl DivAssign<&$rhs> for $lhs {
            fn div_assign(&mut self, rhs: &$rhs) {
                *self /= *rhs;
            }
        }

        impl DivAssign<$rhs> for $lhs {
            fn div_assign(&mut self, rhs: $rhs) {
                let l = $rhs::from(*self);
                let r = $rhs::from(rhs);
                self.0.copy_from_slice((l / r).to_be_bytes().as_ref());
            }
        }

        impl DivAssign<&$lhs> for $rhs {
            fn div_assign(&mut self, rhs: &$lhs) {
                *self /= *rhs;
            }
        }

        impl DivAssign<$lhs> for $rhs {
            fn div_assign(&mut self, rhs: $lhs) {
                *self /= $rhs::from(rhs);
            }
        }

        impl Rem<&$rhs> for &$lhs {
            type Output = $lhs;

            fn rem(self, rhs: &$rhs) -> Self::Output {
                *self % *rhs
            }
        }

        impl Rem<&$rhs> for $lhs {
            type Output = $lhs;

            fn rem(self, rhs: &$rhs) -> Self::Output {
                self % *rhs
            }
        }

        impl Rem<$rhs> for &$lhs {
            type Output = $lhs;

            fn rem(self, rhs: $rhs) -> Self::Output {
                *self % rhs
            }
        }

        impl Rem<$rhs> for $lhs {
            type Output = $lhs;

            fn rem(self, rhs: $rhs) -> Self::Output {
                let l = $rhs::from(self);
                let r = $rhs::from(rhs);
                (l % r).into()
            }
        }

        impl Rem<&$lhs> for &$rhs {
            type Output = $lhs;

            fn rem(self, rhs: &$lhs) -> Self::Output {
                *self % *rhs
            }
        }

        impl Rem<&$lhs> for $rhs {
            type Output = $lhs;

            fn rem(self, rhs: &$lhs) -> Self::Output {
                self % *rhs
            }
        }

        impl Rem<$lhs> for &$rhs {
            type Output = $lhs;

            fn rem(self, rhs: $lhs) -> Self::Output {
                *self % rhs
            }
        }

        impl Rem<$lhs> for $rhs {
            type Output = $lhs;

            fn rem(self, rhs: $lhs) -> Self::Output {
                let l = $rhs::from(self);
                let r = $rhs::from(rhs);
                (l % r).into()
            }
        }

        impl RemAssign<&$rhs> for $lhs {
            fn rem_assign(&mut self, rhs: &$rhs) {
                *self %= *rhs;
            }
        }

        impl RemAssign<$rhs> for $lhs {
            fn rem_assign(&mut self, rhs: $rhs) {
                let l = $rhs::from(*self);
                let r = $rhs::from(rhs);
                self.0.copy_from_slice((l % r).to_be_bytes().as_ref());
            }
        }

        impl RemAssign<&$lhs> for $rhs {
            fn rem_assign(&mut self, rhs: &$lhs) {
                *self %= $rhs::from(*rhs);
            }
        }

        impl RemAssign<$lhs> for $rhs {
            fn rem_assign(&mut self, rhs: $lhs) {
                *self %= $rhs::from(rhs);
            }
        }

        impl BitAnd<&$rhs> for &$lhs {
            type Output = $lhs;

            fn bitand(self, rhs: &$rhs) -> Self::Output {
                *self & *rhs
            }
        }

        impl BitAnd<&$rhs> for $lhs {
            type Output = $lhs;

            fn bitand(self, rhs: &$rhs) -> Self::Output {
                self & *rhs
            }
        }

        impl BitAnd<$rhs> for &$lhs {
            type Output = $lhs;

            fn bitand(self, rhs: $rhs) -> Self::Output {
                *self & rhs
            }
        }

        impl BitAnd<$rhs> for $lhs {
            type Output = $lhs;

            fn bitand(self, rhs: $rhs) -> Self::Output {
                let l = $rhs::from(self);
                let r = $rhs::from(rhs);
                (l & r).into()
            }
        }

        impl BitAnd<&$lhs> for &$rhs {
            type Output = $lhs;

            fn bitand(self, rhs: &$lhs) -> Self::Output {
                *self & *rhs
            }
        }

        impl BitAnd<&$lhs> for $rhs {
            type Output = $lhs;

            fn bitand(self, rhs: &$lhs) -> Self::Output {
                self & *rhs
            }
        }

        impl BitAnd<$lhs> for &$rhs {
            type Output = $lhs;

            fn bitand(self, rhs: $lhs) -> Self::Output {
                *self & rhs
            }
        }

        impl BitAnd<$lhs> for $rhs {
            type Output = $lhs;

            fn bitand(self, rhs: $lhs) -> Self::Output {
                let l = $rhs::from(self);
                let r = $rhs::from(rhs);
                (l & r).into()
            }
        }

        impl BitAndAssign<&$rhs> for $lhs {
            fn bitand_assign(&mut self, rhs: &$rhs) {
                *self &= *rhs;
            }
        }

        impl BitAndAssign<$rhs> for $lhs {
            fn bitand_assign(&mut self, rhs: $rhs) {
                let l = $rhs::from(*self);
                let r = $rhs::from(rhs);
                self.0.copy_from_slice((l & r).to_be_bytes().as_ref());
            }
        }

        impl BitAndAssign<&$lhs> for $rhs {
            fn bitand_assign(&mut self, rhs: &$lhs) {
                *self &= $rhs::from(*rhs);
            }
        }

        impl BitAndAssign<$lhs> for $rhs {
            fn bitand_assign(&mut self, rhs: $lhs) {
                *self &= $rhs::from(rhs);
            }
        }

        impl BitOr<&$rhs> for &$lhs {
            type Output = $lhs;

            fn bitor(self, rhs: &$rhs) -> Self::Output {
                *self | *rhs
            }
        }

        impl BitOr<&$rhs> for $lhs {
            type Output = $lhs;

            fn bitor(self, rhs: &$rhs) -> Self::Output {
                self | *rhs
            }
        }

        impl BitOr<$rhs> for &$lhs {
            type Output = $lhs;

            fn bitor(self, rhs: $rhs) -> Self::Output {
                *self | rhs
            }
        }

        impl BitOr<$rhs> for $lhs {
            type Output = $lhs;

            fn bitor(self, rhs: $rhs) -> Self::Output {
                let l = $rhs::from(self);
                let r = $rhs::from(rhs);
                (l | r).into()
            }
        }

        impl BitOr<&$lhs> for &$rhs {
            type Output = $lhs;

            fn bitor(self, rhs: &$lhs) -> Self::Output {
                *self | *rhs
            }
        }

        impl BitOr<&$lhs> for $rhs {
            type Output = $lhs;

            fn bitor(self, rhs: &$lhs) -> Self::Output {
                self | *rhs
            }
        }

        impl BitOr<$lhs> for &$rhs {
            type Output = $lhs;

            fn bitor(self, rhs: $lhs) -> Self::Output {
                *self | rhs
            }
        }

        impl BitOr<$lhs> for $rhs {
            type Output = $lhs;

            fn bitor(self, rhs: $lhs) -> Self::Output {
                let l = $rhs::from(self);
                let r = $rhs::from(rhs);
                (l | r).into()
            }
        }

        impl BitOrAssign<&$rhs> for $lhs {
            fn bitor_assign(&mut self, rhs: &$rhs) {
                *self |= *rhs;
            }
        }

        impl BitOrAssign<$rhs> for $lhs {
            fn bitor_assign(&mut self, rhs: $rhs) {
                let l = $rhs::from(*self);
                let r = $rhs::from(rhs);
                self.0.copy_from_slice((l | r).to_be_bytes().as_ref());
            }
        }

        impl BitOrAssign<&$lhs> for $rhs {
            fn bitor_assign(&mut self, rhs: &$lhs) {
                *self |= $rhs::from(*rhs);
            }
        }

        impl BitOrAssign<$lhs> for $rhs {
            fn bitor_assign(&mut self, rhs: $lhs) {
                *self |= $rhs::from(rhs);
            }
        }

        impl BitXor<&$rhs> for &$lhs {
            type Output = $lhs;

            fn bitxor(self, rhs: &$rhs) -> Self::Output {
                *self ^ *rhs
            }
        }

        impl BitXor<&$rhs> for $lhs {
            type Output = $lhs;

            fn bitxor(self, rhs: &$rhs) -> Self::Output {
                self ^ *rhs
            }
        }

        impl BitXor<$rhs> for &$lhs {
            type Output = $lhs;

            fn bitxor(self, rhs: $rhs) -> Self::Output {
                *self ^ rhs
            }
        }

        impl BitXor<$rhs> for $lhs {
            type Output = $lhs;

            fn bitxor(self, rhs: $rhs) -> Self::Output {
                let l = $rhs::from(self);
                let r = $rhs::from(rhs);
                (l ^ r).into()
            }
        }

        impl BitXor<&$lhs> for &$rhs {
            type Output = $lhs;

            fn bitxor(self, rhs: &$lhs) -> Self::Output {
                *self ^ *rhs
            }
        }

        impl BitXor<&$lhs> for $rhs {
            type Output = $lhs;

            fn bitxor(self, rhs: &$lhs) -> Self::Output {
                self ^ *rhs
            }
        }

        impl BitXor<$lhs> for &$rhs {
            type Output = $lhs;

            fn bitxor(self, rhs: $lhs) -> Self::Output {
                *self ^ rhs
            }
        }

        impl BitXor<$lhs> for $rhs {
            type Output = $lhs;

            fn bitxor(self, rhs: $lhs) -> Self::Output {
                let l = $rhs::from(self);
                let r = $rhs::from(rhs);
                (l ^ r).into()
            }
        }

        impl BitXorAssign<&$rhs> for $lhs {
            fn bitxor_assign(&mut self, rhs: &$rhs) {
                *self ^= *rhs;
            }
        }

        impl BitXorAssign<$rhs> for $lhs {
            fn bitxor_assign(&mut self, rhs: $rhs) {
                let l = $rhs::from(*self);
                let r = $rhs::from(rhs);
                self.0.copy_from_slice((l ^ r).to_be_bytes().as_ref());
            }
        }

        impl BitXorAssign<&$lhs> for $rhs {
            fn bitxor_assign(&mut self, rhs: &$lhs) {
                *self ^= $rhs::from(*rhs);
            }
        }

        impl BitXorAssign<$lhs> for $rhs {
            fn bitxor_assign(&mut self, rhs: $lhs) {
                *self ^= $rhs::from(rhs);
            }
        }

        impl Shl<&i8> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: &i8) -> Self::Output {
                *self << *rhs
            }
        }

        impl Shl<&i8> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: &i8) -> Self::Output {
                self << *rhs
            }
        }

        impl Shl<i8> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: i8) -> Self::Output {
                *self << rhs
            }
        }

        impl Shl<i8> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: i8) -> Self::Output {
                let l = $rhs::from(self);
                (l << rhs).into()
            }
        }

        impl Shl<&i16> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: &i16) -> Self::Output {
                *self << *rhs
            }
        }

        impl Shl<&i16> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: &i16) -> Self::Output {
                self << *rhs
            }
        }

        impl Shl<i16> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: i16) -> Self::Output {
                *self << rhs
            }
        }

        impl Shl<i16> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: i16) -> Self::Output {
                let l = $rhs::from(self);
                (l << rhs).into()
            }
        }

        impl Shl<&i32> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: &i32) -> Self::Output {
                *self << *rhs
            }
        }

        impl Shl<&i32> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: &i32) -> Self::Output {
                self << *rhs
            }
        }

        impl Shl<i32> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: i32) -> Self::Output {
                *self << rhs
            }
        }

        impl Shl<i32> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: i32) -> Self::Output {
                let l = $rhs::from(self);
                (l << rhs).into()
            }
        }

        impl Shl<&i64> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: &i64) -> Self::Output {
                *self << *rhs
            }
        }

        impl Shl<&i64> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: &i64) -> Self::Output {
                self << *rhs
            }
        }

        impl Shl<i64> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: i64) -> Self::Output {
                *self << rhs
            }
        }

        impl Shl<i64> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: i64) -> Self::Output {
                let l = $rhs::from(self);
                (l << rhs).into()
            }
        }

        impl Shl<&i128> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: &i128) -> Self::Output {
                *self << *rhs
            }
        }

        impl Shl<&i128> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: &i128) -> Self::Output {
                self << *rhs
            }
        }

        impl Shl<i128> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: i128) -> Self::Output {
                *self << rhs
            }
        }

        impl Shl<i128> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: i128) -> Self::Output {
                let l = $rhs::from(self);
                (l << rhs).into()
            }
        }

        impl Shl<&isize> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: &isize) -> Self::Output {
                *self << *rhs
            }
        }

        impl Shl<&isize> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: &isize) -> Self::Output {
                self << *rhs
            }
        }

        impl Shl<isize> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: isize) -> Self::Output {
                *self << rhs
            }
        }

        impl Shl<isize> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: isize) -> Self::Output {
                let l = $rhs::from(self);
                (l << rhs).into()
            }
        }

        impl Shl<&u8> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: &u8) -> Self::Output {
                *self << *rhs
            }
        }

        impl Shl<&u8> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: &u8) -> Self::Output {
                self << *rhs
            }
        }

        impl Shl<u8> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: u8) -> Self::Output {
                *self << rhs
            }
        }

        impl Shl<&u16> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: &u16) -> Self::Output {
                *self << *rhs
            }
        }

        impl Shl<&u16> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: &u16) -> Self::Output {
                self << *rhs
            }
        }

        impl Shl<u16> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: u16) -> Self::Output {
                *self << rhs
            }
        }

        impl Shl<u16> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: u16) -> Self::Output {
                let l = $rhs::from(self);
                (l << rhs).into()
            }
        }

        impl Shl<u8> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: u8) -> Self::Output {
                let l = $rhs::from(self);
                (l << rhs).into()
            }
        }

        impl Shl<&u32> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: &u32) -> Self::Output {
                *self << *rhs
            }
        }

        impl Shl<&u32> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: &u32) -> Self::Output {
                self << *rhs
            }
        }

        impl Shl<u32> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: u32) -> Self::Output {
                *self << rhs
            }
        }

        impl Shl<u32> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: u32) -> Self::Output {
                let l = $rhs::from(self);
                (l << rhs).into()
            }
        }

        impl Shl<&u64> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: &u64) -> Self::Output {
                *self << *rhs
            }
        }

        impl Shl<&u64> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: &u64) -> Self::Output {
                self << *rhs
            }
        }

        impl Shl<u64> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: u64) -> Self::Output {
                *self << rhs
            }
        }

        impl Shl<u64> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: u64) -> Self::Output {
                let l = $rhs::from(self);
                (l << rhs).into()
            }
        }

        impl Shl<&u128> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: &u128) -> Self::Output {
                *self << *rhs
            }
        }

        impl Shl<&u128> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: &u128) -> Self::Output {
                self << *rhs
            }
        }

        impl Shl<u128> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: u128) -> Self::Output {
                *self << rhs
            }
        }

        impl Shl<u128> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: u128) -> Self::Output {
                let l = $rhs::from(self);
                (l << rhs).into()
            }
        }

        impl Shl<&usize> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: &usize) -> Self::Output {
                *self << *rhs
            }
        }

        impl Shl<&usize> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: &usize) -> Self::Output {
                self << *rhs
            }
        }

        impl Shl<usize> for &$lhs {
            type Output = $lhs;

            fn shl(self, rhs: usize) -> Self::Output {
                *self << rhs
            }
        }

        impl Shl<usize> for $lhs {
            type Output = $lhs;

            fn shl(self, rhs: usize) -> Self::Output {
                let l = $rhs::from(self);
                (l << rhs).into()
            }
        }

        impl ShlAssign<&i8> for $lhs {
            fn shl_assign(&mut self, rhs: &i8) {
                *self <<= *rhs;
            }
        }

        impl ShlAssign<i8> for $lhs {
            fn shl_assign(&mut self, rhs: i8) {
                let l = $rhs::from(*self);
                self.0.copy_from_slice((l << rhs).to_be_bytes().as_ref());
            }
        }

        impl ShlAssign<&i16> for $lhs {
            fn shl_assign(&mut self, rhs: &i16) {
                *self <<= *rhs;
            }
        }

        impl ShlAssign<i16> for $lhs {
            fn shl_assign(&mut self, rhs: i16) {
                let l = $rhs::from(*self);
                self.0.copy_from_slice((l << rhs).to_be_bytes().as_ref());
            }
        }

        impl ShlAssign<&i32> for $lhs {
            fn shl_assign(&mut self, rhs: &i32) {
                *self <<= *rhs;
            }
        }

        impl ShlAssign<i32> for $lhs {
            fn shl_assign(&mut self, rhs: i32) {
                let l = $rhs::from(*self);
                self.0.copy_from_slice((l << rhs).to_be_bytes().as_ref());
            }
        }

        impl ShlAssign<&i64> for $lhs {
            fn shl_assign(&mut self, rhs: &i64) {
                *self <<= *rhs;
            }
        }

        impl ShlAssign<i64> for $lhs {
            fn shl_assign(&mut self, rhs: i64) {
                let l = $rhs::from(*self);
                self.0.copy_from_slice((l << rhs).to_be_bytes().as_ref());
            }
        }

        impl ShlAssign<&isize> for $lhs {
            fn shl_assign(&mut self, rhs: &isize) {
                *self <<= *rhs;
            }
        }

        impl ShlAssign<isize> for $lhs {
            fn shl_assign(&mut self, rhs: isize) {
                let l = $rhs::from(*self);
                self.0.copy_from_slice((l << rhs).to_be_bytes().as_ref());
            }
        }

        impl ShlAssign<&u8> for $lhs {
            fn shl_assign(&mut self, rhs: &u8) {
                *self <<= *rhs;
            }
        }

        impl ShlAssign<u8> for $lhs {
            fn shl_assign(&mut self, rhs: u8) {
                let l = $rhs::from(*self);
                self.0.copy_from_slice((l << rhs).to_be_bytes().as_ref());
            }
        }

        impl ShlAssign<&u16> for $lhs {
            fn shl_assign(&mut self, rhs: &u16) {
                *self <<= *rhs;
            }
        }

        impl ShlAssign<u16> for $lhs {
            fn shl_assign(&mut self, rhs: u16) {
                let l = $rhs::from(*self);
                self.0.copy_from_slice((l << rhs).to_be_bytes().as_ref());
            }
        }

        impl ShlAssign<&u32> for $lhs {
            fn shl_assign(&mut self, rhs: &u32) {
                *self <<= *rhs;
            }
        }

        impl ShlAssign<u32> for $lhs {
            fn shl_assign(&mut self, rhs: u32) {
                let l = $rhs::from(*self);
                self.0.copy_from_slice((l << rhs).to_be_bytes().as_ref());
            }
        }

        impl ShlAssign<&u64> for $lhs {
            fn shl_assign(&mut self, rhs: &u64) {
                *self <<= *rhs;
            }
        }

        impl ShlAssign<u64> for $lhs {
            fn shl_assign(&mut self, rhs: u64) {
                let l = $rhs::from(*self);
                self.0.copy_from_slice((l << rhs).to_be_bytes().as_ref());
            }
        }

        impl ShlAssign<&u128> for $lhs {
            fn shl_assign(&mut self, rhs: &u128) {
                *self <<= *rhs;
            }
        }

        impl ShlAssign<u128> for $lhs {
            fn shl_assign(&mut self, rhs: u128) {
                let l = $rhs::from(*self);
                self.0.copy_from_slice((l << rhs).to_be_bytes().as_ref());
            }
        }

        impl ShlAssign<&usize> for $lhs {
            fn shl_assign(&mut self, rhs: &usize) {
                *self <<= *rhs;
            }
        }

        impl ShlAssign<usize> for $lhs {
            fn shl_assign(&mut self, rhs: usize) {
                let l = $rhs::from(*self);
                self.0.copy_from_slice((l << rhs).to_be_bytes().as_ref());
            }
        }

        impl Shr<&i8> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: &i8) -> Self::Output {
                *self >> *rhs
            }
        }

        impl Shr<&i8> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: &i8) -> Self::Output {
                self >> *rhs
            }
        }

        impl Shr<i8> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: i8) -> Self::Output {
                *self >> rhs
            }
        }

        impl Shr<i8> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: i8) -> Self::Output {
                let l = $rhs::from(self);
                (l >> rhs).into()
            }
        }

        impl Shr<&i16> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: &i16) -> Self::Output {
                *self >> *rhs
            }
        }

        impl Shr<&i16> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: &i16) -> Self::Output {
                self >> *rhs
            }
        }

        impl Shr<i16> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: i16) -> Self::Output {
                *self >> rhs
            }
        }

        impl Shr<i16> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: i16) -> Self::Output {
                let l = $rhs::from(self);
                (l >> rhs).into()
            }
        }

        impl Shr<&i32> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: &i32) -> Self::Output {
                *self >> *rhs
            }
        }

        impl Shr<&i32> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: &i32) -> Self::Output {
                self >> *rhs
            }
        }

        impl Shr<i32> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: i32) -> Self::Output {
                *self >> rhs
            }
        }

        impl Shr<i32> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: i32) -> Self::Output {
                let l = $rhs::from(self);
                (l >> rhs).into()
            }
        }

        impl Shr<&i64> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: &i64) -> Self::Output {
                *self >> *rhs
            }
        }

        impl Shr<&i64> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: &i64) -> Self::Output {
                self >> *rhs
            }
        }

        impl Shr<i64> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: i64) -> Self::Output {
                *self >> rhs
            }
        }

        impl Shr<i64> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: i64) -> Self::Output {
                let l = $rhs::from(self);
                (l >> rhs).into()
            }
        }

        impl Shr<&i128> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: &i128) -> Self::Output {
                *self >> *rhs
            }
        }

        impl Shr<&i128> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: &i128) -> Self::Output {
                self >> *rhs
            }
        }

        impl Shr<i128> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: i128) -> Self::Output {
                *self >> rhs
            }
        }

        impl Shr<i128> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: i128) -> Self::Output {
                let l = $rhs::from(self);
                (l >> rhs).into()
            }
        }

        impl Shr<&isize> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: &isize) -> Self::Output {
                *self >> *rhs
            }
        }

        impl Shr<&isize> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: &isize) -> Self::Output {
                self >> *rhs
            }
        }

        impl Shr<isize> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: isize) -> Self::Output {
                *self >> rhs
            }
        }

        impl Shr<isize> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: isize) -> Self::Output {
                let l = $rhs::from(self);
                (l >> rhs).into()
            }
        }

        impl Shr<&u8> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: &u8) -> Self::Output {
                *self >> *rhs
            }
        }

        impl Shr<&u8> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: &u8) -> Self::Output {
                self >> *rhs
            }
        }

        impl Shr<u8> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: u8) -> Self::Output {
                *self >> rhs
            }
        }

        impl Shr<u8> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: u8) -> Self::Output {
                let l = $rhs::from(self);
                (l >> rhs).into()
            }
        }

        impl Shr<&u16> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: &u16) -> Self::Output {
                *self >> *rhs
            }
        }

        impl Shr<&u16> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: &u16) -> Self::Output {
                self >> *rhs
            }
        }

        impl Shr<u16> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: u16) -> Self::Output {
                *self >> rhs
            }
        }

        impl Shr<u16> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: u16) -> Self::Output {
                let l = $rhs::from(self);
                (l >> rhs).into()
            }
        }

        impl Shr<&u32> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: &u32) -> Self::Output {
                *self >> *rhs
            }
        }

        impl Shr<&u32> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: &u32) -> Self::Output {
                self >> *rhs
            }
        }

        impl Shr<u32> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: u32) -> Self::Output {
                *self >> rhs
            }
        }

        impl Shr<u32> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: u32) -> Self::Output {
                let l = $rhs::from(self);
                (l >> rhs).into()
            }
        }

        impl Shr<&u64> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: &u64) -> Self::Output {
                *self >> *rhs
            }
        }

        impl Shr<&u64> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: &u64) -> Self::Output {
                self >> *rhs
            }
        }

        impl Shr<u64> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: u64) -> Self::Output {
                *self >> rhs
            }
        }

        impl Shr<u64> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: u64) -> Self::Output {
                let l = $rhs::from(self);
                (l >> rhs).into()
            }
        }

        impl Shr<&u128> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: &u128) -> Self::Output {
                *self >> *rhs
            }
        }

        impl Shr<&u128> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: &u128) -> Self::Output {
                self >> *rhs
            }
        }

        impl Shr<u128> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: u128) -> Self::Output {
                *self >> rhs
            }
        }

        impl Shr<u128> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: u128) -> Self::Output {
                let l = $rhs::from(self);
                (l >> rhs).into()
            }
        }

        impl Shr<&usize> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: &usize) -> Self::Output {
                *self >> *rhs
            }
        }

        impl Shr<&usize> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: &usize) -> Self::Output {
                self >> *rhs
            }
        }

        impl Shr<usize> for &$lhs {
            type Output = $lhs;

            fn shr(self, rhs: usize) -> Self::Output {
                *self >> rhs
            }
        }

        impl Shr<usize> for $lhs {
            type Output = $lhs;

            fn shr(self, rhs: usize) -> Self::Output {
                let l = $rhs::from(self);
                (l >> rhs).into()
            }
        }

        impl ShrAssign<&i8> for $lhs {
            fn shr_assign(&mut self, rhs: &i8) {
                *self >>= *rhs;
            }
        }

        impl ShrAssign<i8> for $lhs {
            fn shr_assign(&mut self, rhs: i8) {
                let l = $rhs::from(*self);
                self.0.copy_from_slice((l >> rhs).to_be_bytes().as_ref());
            }
        }

        impl ShrAssign<&i16> for $lhs {
            fn shr_assign(&mut self, rhs: &i16) {
                *self >>= *rhs;
            }
        }

        impl ShrAssign<i16> for $lhs {
            fn shr_assign(&mut self, rhs: i16) {
                let l = $rhs::from(*self);
                self.0.copy_from_slice((l >> rhs).to_be_bytes().as_ref());
            }
        }

        impl ShrAssign<&i32> for $lhs {
            fn shr_assign(&mut self, rhs: &i32) {
                *self >>= *rhs;
            }
        }

        impl ShrAssign<i32> for $lhs {
            fn shr_assign(&mut self, rhs: i32) {
                let l = $rhs::from(*self);
                self.0.copy_from_slice((l >> rhs).to_be_bytes().as_ref());
            }
        }

        impl ShrAssign<&i64> for $lhs {
            fn shr_assign(&mut self, rhs: &i64) {
                *self >>= *rhs;
            }
        }

        impl ShrAssign<i64> for $lhs {
            fn shr_assign(&mut self, rhs: i64) {
                let l = $rhs::from(*self);
                self.0.copy_from_slice((l >> rhs).to_be_bytes().as_ref());
            }
        }

        impl ShrAssign<&i128> for $lhs {
            fn shr_assign(&mut self, rhs: &i128) {
                *self >>= *rhs;
            }
        }

        impl ShrAssign<i128> for $lhs {
            fn shr_assign(&mut self, rhs: i128) {
                let l = $rhs::from(*self);
                self.0.copy_from_slice((l >> rhs).to_be_bytes().as_ref());
            }
        }

        impl ShrAssign<&isize> for $lhs {
            fn shr_assign(&mut self, rhs: &isize) {
                *self >>= *rhs;
            }
        }

        impl ShrAssign<isize> for $lhs {
            fn shr_assign(&mut self, rhs: isize) {
                let l = $rhs::from(*self);
                self.0.copy_from_slice((l >> rhs).to_be_bytes().as_ref());
            }
        }

        impl ShrAssign<&u8> for $lhs {
            fn shr_assign(&mut self, rhs: &u8) {
                *self >>= *rhs;
            }
        }

        impl ShrAssign<u8> for $lhs {
            fn shr_assign(&mut self, rhs: u8) {
                let l = $rhs::from(*self);
                self.0.copy_from_slice((l >> rhs).to_be_bytes().as_ref());
            }
        }

        impl ShrAssign<&u16> for $lhs {
            fn shr_assign(&mut self, rhs: &u16) {
                *self >>= *rhs;
            }
        }

        impl ShrAssign<u16> for $lhs {
            fn shr_assign(&mut self, rhs: u16) {
                let l = $rhs::from(*self);
                self.0.copy_from_slice((l >> rhs).to_be_bytes().as_ref());
            }
        }

        impl ShrAssign<&u32> for $lhs {
            fn shr_assign(&mut self, rhs: &u32) {
                *self >>= *rhs;
            }
        }

        impl ShrAssign<u32> for $lhs {
            fn shr_assign(&mut self, rhs: u32) {
                let l = $rhs::from(*self);
                self.0.copy_from_slice((l >> rhs).to_be_bytes().as_ref());
            }
        }

        impl ShrAssign<&u64> for $lhs {
            fn shr_assign(&mut self, rhs: &u64) {
                *self >>= *rhs;
            }
        }

        impl ShrAssign<u64> for $lhs {
            fn shr_assign(&mut self, rhs: u64) {
                let l = $rhs::from(*self);
                self.0.copy_from_slice((l >> rhs).to_be_bytes().as_ref());
            }
        }

        impl ShrAssign<&u128> for $lhs {
            fn shr_assign(&mut self, rhs: &u128) {
                *self >>= *rhs;
            }
        }

        impl ShrAssign<u128> for $lhs {
            fn shr_assign(&mut self, rhs: u128) {
                let l = $rhs::from(*self);
                self.0.copy_from_slice((l >> rhs).to_be_bytes().as_ref());
            }
        }

        impl ShrAssign<&usize> for $lhs {
            fn shr_assign(&mut self, rhs: &usize) {
                *self >>= *rhs;
            }
        }

        impl ShrAssign<usize> for $lhs {
            fn shr_assign(&mut self, rhs: usize) {
                let l = $rhs::from(*self);
                self.0.copy_from_slice((l >> rhs).to_be_bytes().as_ref());
            }
        }

        impl From<$rhs> for $lhs {
            fn from(n: $rhs) -> Self {
                $lhs(n.to_be_bytes())
            }
        }

        impl From<&$rhs> for $lhs {
            fn from(n: &$rhs) -> Self {
                Self::from(*n)
            }
        }

        impl From<$lhs> for $rhs {
            fn from(arr: $lhs) -> Self {
                $rhs::from_be_bytes(arr.0)
            }
        }

        impl From<&$lhs> for $rhs {
            fn from(arr: &$lhs) -> Self {
                Self::from(*arr)
            }
        }

        #[cfg(any(features = "alloc", features = "std"))]
        impl From<&lhs> for Vec<u8> {
            fn from(arr: &$lhs) -> Self {
                Self::from(*arr)
            }
        }
        #[cfg(any(features = "alloc", features = "std"))]
        impl From<lhs> for Vec<u8> {
            fn from(arr: &$lhs) -> Self {
                arr.0.to_vec()
            }
        }
        #[cfg(any(features = "alloc", features = "std"))]
        impl TryFrom<Vec<u8>> for $lhs {
            type Error = Error;

            fn try_from(vec: Vec<u8>) -> VsssResult<Self> {
                Self::try_from(&vec)
            }
        }
        #[cfg(any(features = "alloc", features = "std"))]
        impl TryFrom<&Vec<u8>> for $lhs {
            type Error = Error;

            fn try_from(vec: Vec<u8>) -> VsssResult<Self> {
                Self::try_from(vec.as_slice())
            }
        }
        #[cfg(any(features = "alloc", features = "std"))]
        impl TryFrom<&[u8]> for $lhs {
            type Error = Error;

            fn try_from(bytes: &[u8]) -> VsssResult<Self> {
                Self::try_from_be_slice(bytes)
            }
        }
        #[cfg(any(features = "alloc", features = "std"))]
        impl TryFrom<Box<[u8]>> for $lhs {
            type Error = Error;

            fn try_from(bytes: Box<[u8]>) -> VsssResult<Self> {
                Self::try_from(bytes.as_ref())
            }
        }

        impl PartialEq for $lhs {
            fn eq(&self, other: &Self) -> bool {
                $rhs::from(self) == $rhs::from(other)
            }
        }

        impl Eq for $lhs {}

        impl PartialEq<$rhs> for $lhs {
            fn eq(&self, other: &$rhs) -> bool {
                $rhs::from(self) == *other
            }
        }

        impl PartialOrd for $lhs {
            fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
                Some($rhs::from(self).cmp(&$rhs::from(other)))
            }
        }

        impl PartialOrd<$rhs> for $lhs {
            fn partial_cmp(&self, other: &$rhs) -> Option<core::cmp::Ordering> {
                $rhs::from(self).partial_cmp(other)
            }
        }

        impl Ord for $lhs {
            fn cmp(&self, other: &Self) -> core::cmp::Ordering {
                $rhs::from(self).cmp(&$rhs::from(other))
            }
        }

        impl Hash for $lhs {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                $rhs::from(self).hash(state)
            }
        }

        impl ConditionallySelectable for $lhs {
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                let mut result = Self::default();
                for (i, c) in result.0.iter_mut().enumerate() {
                    *c = u8::conditional_select(&a.0[i], &b.0[i], choice);
                }
                result
            }
        }

        impl ConstantTimeGreater for $lhs {
            fn ct_gt(&self, other: &Self) -> Choice {
                let l = $rhs::from(self);
                let r = $rhs::from(other);
                l.ct_gt(&r)
            }
        }

        impl Not for $lhs {
            type Output = $lhs;

            fn not(self) -> Self::Output {
                let l = $rhs::from(self);
                Self::from(!l)
            }
        }

        impl Not for &$lhs {
            type Output = $lhs;

            fn not(self) -> Self::Output {
                !*self
            }
        }

        impl Neg for $lhs {
            type Output = $lhs;

            fn neg(self) -> Self::Output {
                let l = $rhs::from(self);
                Self::from(l.wrapping_neg())
            }
        }

        impl Neg for &$lhs {
            type Output = $lhs;

            fn neg(self) -> Self::Output {
                -*self
            }
        }

        impl serde::Serialize for $lhs {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                $rhs::from(self).serialize(serializer)
            }
        }

        impl<'de> serde::Deserialize<'de> for $lhs {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let n = $rhs::deserialize(deserializer)?;
                Ok(Self::from(n))
            }
        }

        impl Display for $lhs {
            fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
                write!(f, "{}", $rhs::from(self))
            }
        }

        impl Copy for $lhs {}

        impl FromStr for $lhs {
            type Err = Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let n = s
                    .parse::<$rhs>()
                    .map_err(|_e| Error::InvalidShareConversion)?;
                Ok(Self::from(n))
            }
        }
    };
}

trait_impl!(LHS = SmallArray<2>, RHS = u16);
impl ShareIdentifier for SmallArray<2> {
    fn from_field_element<F: PrimeField>(element: F) -> VsssResult<Self> {
        let repr = element.to_repr();
        // Assume little endian encoding first
        // then try big endian
        let bytes = repr.as_ref();
        let len = bytes.len();
        if bytes[2..].ct_is_zero().into() {
            Ok(Self([bytes[1], bytes[0]]))
        } else if bytes[..len - 3].ct_is_zero().into() {
            Ok(Self([bytes[len - 2], bytes[len - 1]]))
        } else {
            Err(Error::InvalidShareConversion)
        }
    }

    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
        let v = u16::from(self);
        Ok(F::from(v as u64))
    }

    fn is_zero(&self) -> Choice {
        self.0.ct_is_zero()
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

trait_impl!(LHS = SmallArray<4>, RHS = u32);
impl ShareIdentifier for SmallArray<4> {
    fn from_field_element<F: PrimeField>(element: F) -> VsssResult<Self> {
        let repr = element.to_repr();
        // Assume little endian encoding first
        // then try big endian
        let bytes = repr.as_ref();
        if bytes[4..].ct_is_zero().into() {
            Ok(Self([bytes[3], bytes[2], bytes[1], bytes[0]]))
        } else if bytes[..bytes.len() - 5].ct_is_zero().into() {
            Ok(Self([
                bytes[bytes.len() - 4],
                bytes[bytes.len() - 3],
                bytes[bytes.len() - 2],
                bytes[bytes.len() - 1],
            ]))
        } else {
            Err(Error::InvalidShareConversion)
        }
    }

    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
        let v = u32::from(self);
        Ok(F::from(v as u64))
    }

    fn is_zero(&self) -> Choice {
        self.0.ct_is_zero()
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

trait_impl!(LHS = SmallArray<8>, RHS = u64);
impl ShareIdentifier for SmallArray<8> {
    fn from_field_element<F: PrimeField>(element: F) -> VsssResult<Self> {
        let repr = element.to_repr();
        // Assume little endian encoding first
        // then try big endian
        let bytes = repr.as_ref();
        let len = bytes.len();
        if bytes[8..].ct_is_zero().into() {
            Ok(Self([
                bytes[7], bytes[6], bytes[5], bytes[4], bytes[3], bytes[2], bytes[1], bytes[0],
            ]))
        } else if bytes[..len - 9].ct_is_zero().into() {
            Ok(Self([
                bytes[len - 8],
                bytes[len - 7],
                bytes[len - 6],
                bytes[len - 5],
                bytes[len - 4],
                bytes[len - 3],
                bytes[len - 2],
                bytes[len - 1],
            ]))
        } else {
            Err(Error::InvalidShareConversion)
        }
    }

    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
        let v = u64::from(self);
        Ok(F::from(v))
    }

    fn is_zero(&self) -> Choice {
        self.0.ct_is_zero()
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

trait_impl!(LHS = SmallArray<16>, RHS = u128);
impl ShareIdentifier for SmallArray<16> {
    fn from_field_element<F: PrimeField>(element: F) -> VsssResult<Self> {
        let repr = element.to_repr();
        // Assume little endian encoding first
        // then try big endian
        let bytes = repr.as_ref();
        let len = bytes.len();
        if bytes[16..].ct_is_zero().into() {
            Ok(Self([
                bytes[15], bytes[14], bytes[13], bytes[12], bytes[11], bytes[10], bytes[9],
                bytes[8], bytes[7], bytes[6], bytes[5], bytes[4], bytes[3], bytes[2], bytes[1],
                bytes[0],
            ]))
        } else if bytes[..len - 17].ct_is_zero().into() {
            Ok(Self([
                bytes[len - 16],
                bytes[len - 15],
                bytes[len - 14],
                bytes[len - 13],
                bytes[len - 12],
                bytes[len - 11],
                bytes[len - 10],
                bytes[len - 9],
                bytes[len - 8],
                bytes[len - 7],
                bytes[len - 6],
                bytes[len - 5],
                bytes[len - 4],
                bytes[len - 3],
                bytes[len - 2],
                bytes[len - 1],
            ]))
        } else {
            Err(Error::InvalidShareConversion)
        }
    }

    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
        Ok(F::from_u128(u128::from(self)))
    }

    fn is_zero(&self) -> Choice {
        self.0.ct_is_zero()
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
