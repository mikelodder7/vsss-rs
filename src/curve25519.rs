/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
/// Curve25519 is not a prime order curve
/// Since this crate relies on the ff::PrimeField
/// and Curve25519 does work with secret sharing schemes
/// This code wraps the Ristretto points and scalars in a facade
/// to be compliant to work with this library.
/// The intent is the consumer will not have to use these directly since
/// the wrappers implement the [`From`] and [`Into`] traits.
use core::{
    borrow::Borrow,
    iter::Sum,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, IsIdentity},
};
use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};
use rand_chacha::ChaChaRng;
use rand_core::{RngCore, SeedableRng};
use subtle::{Choice, ConditionallySelectable, CtOption};

/// Wraps a curve25519 point
#[derive(Copy, Clone, Debug, Eq)]
pub struct WrappedPoint(pub RistrettoPoint);

impl Group for WrappedPoint {
    type Scalar = WrappedScalar;

    fn random(mut rng: impl RngCore) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let mut crng = ChaChaRng::from_seed(seed);
        Self(RistrettoPoint::random(&mut crng))
    }

    fn identity() -> Self {
        Self(RistrettoPoint::identity())
    }

    fn generator() -> Self {
        Self(RISTRETTO_BASEPOINT_POINT)
    }

    fn is_identity(&self) -> Choice {
        Choice::from(u8::from(self.0.is_identity()))
    }

    fn double(&self) -> Self {
        Self(self.0 + self.0)
    }
}

impl<T> Sum<T> for WrappedPoint
where
    T: Borrow<WrappedPoint>,
{
    fn sum<I: Iterator<Item = T>>(iter: I) -> Self {
        iter.fold(Self::identity(), |acc, item| acc + item.borrow())
    }
}

impl<'a> Neg for &'a WrappedPoint {
    type Output = WrappedPoint;

    #[inline]
    fn neg(self) -> Self::Output {
        WrappedPoint(self.0.neg())
    }
}

impl Neg for WrappedPoint {
    type Output = WrappedPoint;

    #[inline]
    fn neg(self) -> Self::Output {
        -&self
    }
}

impl PartialEq for WrappedPoint {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<'a, 'b> Add<&'b WrappedPoint> for &'a WrappedPoint {
    type Output = WrappedPoint;

    #[inline]
    fn add(self, rhs: &'b WrappedPoint) -> Self::Output {
        WrappedPoint(self.0 + rhs.0)
    }
}

impl<'b> Add<&'b WrappedPoint> for WrappedPoint {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &'b WrappedPoint) -> Self::Output {
        &self + rhs
    }
}

impl<'a> Add<WrappedPoint> for &'a WrappedPoint {
    type Output = WrappedPoint;

    #[inline]
    fn add(self, rhs: WrappedPoint) -> Self::Output {
        self + &rhs
    }
}

impl Add for WrappedPoint {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        &self + &rhs
    }
}

impl AddAssign for WrappedPoint {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = &*self + &rhs;
    }
}

impl<'b> AddAssign<&'b WrappedPoint> for WrappedPoint {
    #[inline]
    fn add_assign(&mut self, rhs: &'b WrappedPoint) {
        *self = &*self + rhs;
    }
}

impl<'a, 'b> Sub<&'b WrappedPoint> for &'a WrappedPoint {
    type Output = WrappedPoint;

    #[inline]
    fn sub(self, rhs: &'b WrappedPoint) -> Self::Output {
        WrappedPoint(self.0 - rhs.0)
    }
}

impl<'b> Sub<&'b WrappedPoint> for WrappedPoint {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &'b WrappedPoint) -> Self::Output {
        &self - rhs
    }
}

impl<'a> Sub<WrappedPoint> for &'a WrappedPoint {
    type Output = WrappedPoint;

    #[inline]
    fn sub(self, rhs: WrappedPoint) -> Self::Output {
        self - &rhs
    }
}

impl Sub for WrappedPoint {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        &self - &rhs
    }
}

impl SubAssign for WrappedPoint {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = &*self - &rhs;
    }
}

impl<'b> SubAssign<&'b WrappedPoint> for WrappedPoint {
    #[inline]
    fn sub_assign(&mut self, rhs: &'b WrappedPoint) {
        *self = &*self - rhs;
    }
}

impl<'a, 'b> Mul<&'b WrappedScalar> for &'a WrappedPoint {
    type Output = WrappedPoint;

    #[inline]
    fn mul(self, rhs: &'b WrappedScalar) -> Self::Output {
        WrappedPoint(self.0 * rhs.0)
    }
}

impl<'b> Mul<&'b WrappedScalar> for WrappedPoint {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &'b WrappedScalar) -> Self::Output {
        &self * rhs
    }
}

impl<'a> Mul<WrappedScalar> for &'a WrappedPoint {
    type Output = WrappedPoint;

    #[inline]
    fn mul(self, rhs: WrappedScalar) -> Self::Output {
        self * &rhs
    }
}

impl Mul<WrappedScalar> for WrappedPoint {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: WrappedScalar) -> Self::Output {
        &self * &rhs
    }
}

impl MulAssign<WrappedScalar> for WrappedPoint {
    #[inline]
    fn mul_assign(&mut self, rhs: WrappedScalar) {
        *self = &*self * &rhs;
    }
}

impl<'b> MulAssign<&'b WrappedScalar> for WrappedPoint {
    #[inline]
    fn mul_assign(&mut self, rhs: &'b WrappedScalar) {
        *self = &*self * rhs;
    }
}

impl GroupEncoding for WrappedPoint {
    type Repr = [u8; 32];

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        let p = CompressedRistretto(*bytes);
        match p.decompress() {
            None => CtOption::new(Self(RistrettoPoint::identity()), Choice::from(0u8)),
            Some(rp) => CtOption::new(Self(rp), Choice::from(1u8)),
        }
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Self::Repr {
        self.0.compress().0
    }
}

impl Default for WrappedPoint {
    fn default() -> Self {
        Self(RistrettoPoint::identity())
    }
}

impl From<WrappedPoint> for RistrettoPoint {
    fn from(p: WrappedPoint) -> RistrettoPoint {
        p.0
    }
}

/// Wraps a curve25519 scalar
#[derive(Copy, Clone, Debug, Hash, Eq)]
pub struct WrappedScalar(pub Scalar);

impl Field for WrappedScalar {
    fn random(mut rng: impl RngCore) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let mut crng = ChaChaRng::from_seed(seed);
        Self(Scalar::random(&mut crng))
    }

    fn zero() -> Self {
        Self(Scalar::zero())
    }

    fn one() -> Self {
        Self(Scalar::one())
    }

    fn is_zero(&self) -> bool {
        self.0 == Scalar::zero()
    }

    fn square(&self) -> Self {
        Self(self.0 * self.0)
    }

    fn double(&self) -> Self {
        Self(self.0 + self.0)
    }

    fn invert(&self) -> CtOption<Self> {
        CtOption::new(Self(self.0.invert()), Choice::from(1u8))
    }

    fn sqrt(&self) -> CtOption<Self> {
        // Not used for secret sharing
        unimplemented!()
    }
}

impl PrimeField for WrappedScalar {
    type Repr = [u8; 32];

    fn from_repr(bytes: Self::Repr) -> Option<Self> {
        Some(Self(Scalar::from_bits(bytes)))
    }

    fn to_repr(&self) -> Self::Repr {
        self.0.to_bytes()
    }

    fn is_odd(&self) -> bool {
        self.0[0] & 1 == 1
    }

    const NUM_BITS: u32 = 255;
    const CAPACITY: u32 = Self::NUM_BITS - 1;

    fn multiplicative_generator() -> Self {
        unimplemented!();
    }

    const S: u32 = 32;

    fn root_of_unity() -> Self {
        unimplemented!();
    }
}

impl From<u64> for WrappedScalar {
    fn from(d: u64) -> WrappedScalar {
        Self(Scalar::from(d))
    }
}

impl ConditionallySelectable for WrappedScalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(Scalar::conditional_select(&a.0, &b.0, choice))
    }
}

impl PartialEq for WrappedScalar {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Default for WrappedScalar {
    fn default() -> Self {
        Self(Scalar::default())
    }
}

impl<'a, 'b> Add<&'b WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn add(self, rhs: &'b WrappedScalar) -> Self::Output {
        WrappedScalar(self.0 + rhs.0)
    }
}

impl<'b> Add<&'b WrappedScalar> for WrappedScalar {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &'b WrappedScalar) -> Self::Output {
        &self + rhs
    }
}

impl<'a> Add<WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn add(self, rhs: WrappedScalar) -> Self::Output {
        self + &rhs
    }
}

impl Add for WrappedScalar {
    type Output = Self;

    #[inline]
    fn add(self, rhs: WrappedScalar) -> Self::Output {
        &self + &rhs
    }
}

impl AddAssign for WrappedScalar {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = &*self + &rhs;
    }
}

impl<'b> AddAssign<&'b WrappedScalar> for WrappedScalar {
    #[inline]
    fn add_assign(&mut self, rhs: &'b WrappedScalar) {
        *self = &*self + rhs;
    }
}

impl<'a, 'b> Sub<&'b WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn sub(self, rhs: &'b WrappedScalar) -> Self::Output {
        WrappedScalar(self.0 - rhs.0)
    }
}

impl<'b> Sub<&'b WrappedScalar> for WrappedScalar {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &'b WrappedScalar) -> Self::Output {
        &self - rhs
    }
}

impl<'a> Sub<WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn sub(self, rhs: WrappedScalar) -> Self::Output {
        self - &rhs
    }
}

impl Sub for WrappedScalar {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: WrappedScalar) -> Self::Output {
        &self - &rhs
    }
}

impl SubAssign for WrappedScalar {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = &*self - &rhs;
    }
}

impl<'b> SubAssign<&'b WrappedScalar> for WrappedScalar {
    #[inline]
    fn sub_assign(&mut self, rhs: &'b WrappedScalar) {
        *self = &*self - rhs;
    }
}

impl<'a, 'b> Mul<&'b WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn mul(self, rhs: &'b WrappedScalar) -> Self::Output {
        WrappedScalar(self.0 * rhs.0)
    }
}

impl<'b> Mul<&'b WrappedScalar> for WrappedScalar {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &'b WrappedScalar) -> Self::Output {
        &self * rhs
    }
}

impl<'a> Mul<WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn mul(self, rhs: WrappedScalar) -> Self::Output {
        self * &rhs
    }
}

impl Mul for WrappedScalar {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: WrappedScalar) -> Self::Output {
        &self * &rhs
    }
}

impl MulAssign for WrappedScalar {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = &*self * &rhs;
    }
}

impl<'b> MulAssign<&'b WrappedScalar> for WrappedScalar {
    #[inline]
    fn mul_assign(&mut self, rhs: &'b WrappedScalar) {
        *self = &*self * rhs;
    }
}

impl<'a> Neg for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn neg(self) -> Self::Output {
        WrappedScalar(self.0.neg())
    }
}

impl Neg for WrappedScalar {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self::Output {
        -&self
    }
}

impl From<WrappedScalar> for Scalar {
    fn from(s: WrappedScalar) -> Scalar {
        s.0
    }
}
