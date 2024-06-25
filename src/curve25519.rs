/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Curve25519 is not a prime order curve
//! Since this crate relies on the ff::PrimeField
//! and Curve25519 does work with secret sharing schemes
//! This code wraps the Ristretto points and scalars in a facade
//! to be compliant to work with this library.
//! The intent is the consumer will not have to use these directly since
//! the wrappers implement the [`From`] and [`Into`] traits.
use core::fmt::{self, Display, Formatter, LowerHex, UpperHex};
use core::{
    borrow::Borrow,
    iter::{Iterator, Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT, RISTRETTO_BASEPOINT_POINT},
    edwards::{CompressedEdwardsY, EdwardsPoint},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use elliptic_curve::{
    ff::{helpers, Field, PrimeField},
    group::{Group, GroupEncoding},
};
use rand_core::RngCore;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

/// Wraps a ristretto25519 point
#[derive(Copy, Clone, Debug, Default, Eq)]
pub struct WrappedRistretto(pub RistrettoPoint);

impl Group for WrappedRistretto {
    type Scalar = WrappedScalar;

    fn random(mut rng: impl RngCore) -> Self {
        let mut seed = [0u8; 64];
        rng.fill_bytes(&mut seed);
        Self(RistrettoPoint::from_uniform_bytes(&seed))
    }

    fn identity() -> Self {
        Self(RistrettoPoint::default())
    }

    fn generator() -> Self {
        Self(RISTRETTO_BASEPOINT_POINT)
    }

    fn is_identity(&self) -> Choice {
        Group::is_identity(&self.0)
    }

    fn double(&self) -> Self {
        Self(self.0 + self.0)
    }
}

impl<T> Sum<T> for WrappedRistretto
where
    T: Borrow<WrappedRistretto>,
{
    fn sum<I: Iterator<Item = T>>(iter: I) -> Self {
        iter.fold(Self::identity(), |acc, item| acc + item.borrow())
    }
}

impl<'a> Neg for &'a WrappedRistretto {
    type Output = WrappedRistretto;

    #[inline]
    fn neg(self) -> Self::Output {
        WrappedRistretto(self.0.neg())
    }
}

impl Neg for WrappedRistretto {
    type Output = WrappedRistretto;

    #[inline]
    fn neg(self) -> Self::Output {
        -&self
    }
}

impl PartialEq for WrappedRistretto {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<'a, 'b> Add<&'b WrappedRistretto> for &'a WrappedRistretto {
    type Output = WrappedRistretto;

    #[inline]
    fn add(self, rhs: &'b WrappedRistretto) -> Self::Output {
        *self + *rhs
    }
}

impl<'b> Add<&'b WrappedRistretto> for WrappedRistretto {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &'b WrappedRistretto) -> Self::Output {
        self + *rhs
    }
}

impl<'a> Add<WrappedRistretto> for &'a WrappedRistretto {
    type Output = WrappedRistretto;

    #[inline]
    fn add(self, rhs: WrappedRistretto) -> Self::Output {
        *self + rhs
    }
}

impl Add for WrappedRistretto {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        WrappedRistretto(self.0 + rhs.0)
    }
}

impl AddAssign for WrappedRistretto {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<'b> AddAssign<&'b WrappedRistretto> for WrappedRistretto {
    #[inline]
    fn add_assign(&mut self, rhs: &'b WrappedRistretto) {
        *self = *self + *rhs;
    }
}

impl<'a, 'b> Sub<&'b WrappedRistretto> for &'a WrappedRistretto {
    type Output = WrappedRistretto;

    #[inline]
    fn sub(self, rhs: &'b WrappedRistretto) -> Self::Output {
        *self - *rhs
    }
}

impl<'b> Sub<&'b WrappedRistretto> for WrappedRistretto {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &'b WrappedRistretto) -> Self::Output {
        self - *rhs
    }
}

impl<'a> Sub<WrappedRistretto> for &'a WrappedRistretto {
    type Output = WrappedRistretto;

    #[inline]
    fn sub(self, rhs: WrappedRistretto) -> Self::Output {
        *self - rhs
    }
}

impl Sub for WrappedRistretto {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        WrappedRistretto(self.0 - rhs.0)
    }
}

impl SubAssign for WrappedRistretto {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<'b> SubAssign<&'b WrappedRistretto> for WrappedRistretto {
    #[inline]
    fn sub_assign(&mut self, rhs: &'b WrappedRistretto) {
        *self = *self - *rhs;
    }
}

impl<'a, 'b> Mul<&'b WrappedScalar> for &'a WrappedRistretto {
    type Output = WrappedRistretto;

    #[inline]
    fn mul(self, rhs: &'b WrappedScalar) -> Self::Output {
        *self * *rhs
    }
}

impl<'b> Mul<&'b WrappedScalar> for WrappedRistretto {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &'b WrappedScalar) -> Self::Output {
        self * *rhs
    }
}

impl<'a> Mul<WrappedScalar> for &'a WrappedRistretto {
    type Output = WrappedRistretto;

    #[inline]
    fn mul(self, rhs: WrappedScalar) -> Self::Output {
        *self * rhs
    }
}

impl Mul<WrappedScalar> for WrappedRistretto {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: WrappedScalar) -> Self::Output {
        WrappedRistretto(self.0 * rhs.0)
    }
}

impl MulAssign<WrappedScalar> for WrappedRistretto {
    #[inline]
    fn mul_assign(&mut self, rhs: WrappedScalar) {
        *self = *self * rhs;
    }
}

impl<'b> MulAssign<&'b WrappedScalar> for WrappedRistretto {
    #[inline]
    fn mul_assign(&mut self, rhs: &'b WrappedScalar) {
        *self = *self * *rhs;
    }
}

impl GroupEncoding for WrappedRistretto {
    type Repr = [u8; 32];

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        let p = CompressedRistretto(*bytes);
        match p.decompress() {
            None => CtOption::new(Self(RistrettoPoint::default()), Choice::from(0u8)),
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

impl From<WrappedRistretto> for RistrettoPoint {
    fn from(p: WrappedRistretto) -> RistrettoPoint {
        p.0
    }
}

impl From<RistrettoPoint> for WrappedRistretto {
    fn from(p: RistrettoPoint) -> Self {
        Self(p)
    }
}

impl Serialize for WrappedRistretto {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.0.compress().to_bytes();
        serialize_arr(&bytes, serializer)
    }
}

impl<'de> Deserialize<'de> for WrappedRistretto {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserialize_arr(deserializer)?;
        // deserialize compressed ristretto, then decompress
        let pt = CompressedRistretto::from_slice(&bytes).map_err(|e| {
            de::Error::custom(format!("failed to deserialize CompressedRistretto: {}", e))
        })?;
        if let Some(ep) = pt.decompress() {
            return Ok(WrappedRistretto(ep));
        }
        Err(de::Error::custom(
            "failed to deserialize CompressedRistretto",
        ))
    }
}

impl LowerHex for WrappedRistretto {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let tmp = self.0.compress().to_bytes();
        for &b in tmp.iter() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl UpperHex for WrappedRistretto {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let tmp = self.0.compress().to_bytes();
        for &b in tmp.iter() {
            write!(f, "{:02X}", b)?;
        }
        Ok(())
    }
}

impl Display for WrappedRistretto {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl ConditionallySelectable for WrappedRistretto {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(RistrettoPoint::conditional_select(&a.0, &b.0, choice))
    }
}

impl ConstantTimeEq for WrappedRistretto {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Wraps an ed25519 point
#[derive(Copy, Clone, Debug, Default, Eq)]
pub struct WrappedEdwards(pub EdwardsPoint);

impl Group for WrappedEdwards {
    type Scalar = WrappedScalar;

    fn random(mut rng: impl RngCore) -> Self {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let pt = RistrettoPoint::from_uniform_bytes(&bytes);
        Self::from(WrappedRistretto(pt))
    }

    fn identity() -> Self {
        Self(EdwardsPoint::default())
    }

    fn generator() -> Self {
        Self(ED25519_BASEPOINT_POINT)
    }

    fn is_identity(&self) -> Choice {
        Group::is_identity(&self.0)
    }

    fn double(&self) -> Self {
        Self(self.0 + self.0)
    }
}

impl<T> Sum<T> for WrappedEdwards
where
    T: Borrow<WrappedEdwards>,
{
    fn sum<I: Iterator<Item = T>>(iter: I) -> Self {
        iter.fold(Self::identity(), |acc, item| acc + item.borrow())
    }
}

impl<'a> Neg for &'a WrappedEdwards {
    type Output = WrappedEdwards;

    #[inline]
    fn neg(self) -> Self::Output {
        WrappedEdwards(self.0.neg())
    }
}

impl Neg for WrappedEdwards {
    type Output = WrappedEdwards;

    #[inline]
    fn neg(self) -> Self::Output {
        -&self
    }
}

impl PartialEq for WrappedEdwards {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<'a, 'b> Add<&'b WrappedEdwards> for &'a WrappedEdwards {
    type Output = WrappedEdwards;

    #[inline]
    fn add(self, rhs: &'b WrappedEdwards) -> Self::Output {
        *self + *rhs
    }
}

impl<'b> Add<&'b WrappedEdwards> for WrappedEdwards {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &'b WrappedEdwards) -> Self::Output {
        self + *rhs
    }
}

impl<'a> Add<WrappedEdwards> for &'a WrappedEdwards {
    type Output = WrappedEdwards;

    #[inline]
    fn add(self, rhs: WrappedEdwards) -> Self::Output {
        *self + rhs
    }
}

impl Add for WrappedEdwards {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        WrappedEdwards(self.0 + rhs.0)
    }
}

impl AddAssign for WrappedEdwards {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<'b> AddAssign<&'b WrappedEdwards> for WrappedEdwards {
    #[inline]
    fn add_assign(&mut self, rhs: &'b WrappedEdwards) {
        *self = *self + *rhs;
    }
}

impl<'a, 'b> Sub<&'b WrappedEdwards> for &'a WrappedEdwards {
    type Output = WrappedEdwards;

    #[inline]
    fn sub(self, rhs: &'b WrappedEdwards) -> Self::Output {
        *self - *rhs
    }
}

impl<'b> Sub<&'b WrappedEdwards> for WrappedEdwards {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &'b WrappedEdwards) -> Self::Output {
        self - *rhs
    }
}

impl<'a> Sub<WrappedEdwards> for &'a WrappedEdwards {
    type Output = WrappedEdwards;

    #[inline]
    fn sub(self, rhs: WrappedEdwards) -> Self::Output {
        *self - rhs
    }
}

impl Sub for WrappedEdwards {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        WrappedEdwards(self.0 - rhs.0)
    }
}

impl SubAssign for WrappedEdwards {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<'b> SubAssign<&'b WrappedEdwards> for WrappedEdwards {
    #[inline]
    fn sub_assign(&mut self, rhs: &'b WrappedEdwards) {
        *self = *self - *rhs;
    }
}

impl<'a, 'b> Mul<&'b WrappedScalar> for &'a WrappedEdwards {
    type Output = WrappedEdwards;

    #[inline]
    fn mul(self, rhs: &'b WrappedScalar) -> Self::Output {
        *self * *rhs
    }
}

impl<'b> Mul<&'b WrappedScalar> for WrappedEdwards {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &'b WrappedScalar) -> Self::Output {
        self * *rhs
    }
}

impl<'a> Mul<WrappedScalar> for &'a WrappedEdwards {
    type Output = WrappedEdwards;

    #[inline]
    fn mul(self, rhs: WrappedScalar) -> Self::Output {
        *self * rhs
    }
}

impl Mul<WrappedScalar> for WrappedEdwards {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: WrappedScalar) -> Self::Output {
        WrappedEdwards(self.0 * rhs.0)
    }
}

impl MulAssign<WrappedScalar> for WrappedEdwards {
    #[inline]
    fn mul_assign(&mut self, rhs: WrappedScalar) {
        *self = *self * rhs;
    }
}

impl<'b> MulAssign<&'b WrappedScalar> for WrappedEdwards {
    #[inline]
    fn mul_assign(&mut self, rhs: &'b WrappedScalar) {
        *self = *self * *rhs;
    }
}

impl GroupEncoding for WrappedEdwards {
    type Repr = [u8; 32];

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        let p = CompressedEdwardsY(*bytes);
        match p.decompress() {
            None => CtOption::new(Self(EdwardsPoint::default()), Choice::from(0u8)),
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

impl From<WrappedEdwards> for EdwardsPoint {
    fn from(p: WrappedEdwards) -> EdwardsPoint {
        p.0
    }
}

impl From<EdwardsPoint> for WrappedEdwards {
    fn from(p: EdwardsPoint) -> Self {
        Self(p)
    }
}

impl From<WrappedRistretto> for WrappedEdwards {
    fn from(p: WrappedRistretto) -> Self {
        struct Ed25519(EdwardsPoint);

        // can't just return the inner underlying point, since it may not be of order 8.
        // compute [8^{-1}][8]P to clear any cofactor
        // this is the byte representation of 8^{-1} mod q
        let eight_inv = Scalar::from_canonical_bytes([
            121, 47, 220, 226, 41, 229, 6, 97, 208, 218, 28, 125, 179, 157, 211, 7, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6,
        ])
        .unwrap();

        let r = unsafe { core::mem::transmute::<RistrettoPoint, Ed25519>(p.0) };

        WrappedEdwards(r.0.mul_by_cofactor() * eight_inv)
    }
}

impl Serialize for WrappedEdwards {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.0.compress().to_bytes();
        serialize_arr(&bytes, serializer)
    }
}

impl<'de> Deserialize<'de> for WrappedEdwards {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserialize_arr(d)?;
        // deserialize compressed edwards y, then decompress
        let pt = CompressedEdwardsY::from_slice(&bytes).map_err(|e| {
            de::Error::custom(format!("failed to deserialize CompressedEdwardsY: {}", e))
        })?;
        if let Some(ep) = pt.decompress() {
            return Ok(WrappedEdwards(ep));
        }
        Err(de::Error::custom(
            "failed to deserialize CompressedEdwardsY",
        ))
    }
}

impl LowerHex for WrappedEdwards {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let tmp = self.0.compress().to_bytes();
        for &b in tmp.iter() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl UpperHex for WrappedEdwards {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let tmp = self.0.compress().to_bytes();
        for &b in tmp.iter() {
            write!(f, "{:02X}", b)?;
        }
        Ok(())
    }
}

impl Display for WrappedEdwards {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl ConditionallySelectable for WrappedEdwards {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(EdwardsPoint::conditional_select(&a.0, &b.0, choice))
    }
}

impl ConstantTimeEq for WrappedEdwards {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Wraps a curve25519 scalar
#[derive(Copy, Clone, Debug, Eq, Default)]
pub struct WrappedScalar(pub Scalar);

impl Field for WrappedScalar {
    const ZERO: Self = Self(Scalar::ZERO);
    const ONE: Self = Self(Scalar::ONE);

    fn random(mut rng: impl RngCore) -> Self {
        let mut seed = [0u8; 64];
        rng.fill_bytes(&mut seed);
        Self(Scalar::from_bytes_mod_order_wide(&seed))
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

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        helpers::sqrt_ratio_generic(num, div)
    }
}

impl PrimeField for WrappedScalar {
    type Repr = <Scalar as PrimeField>::Repr;

    fn from_repr(mut bytes: Self::Repr) -> CtOption<Self> {
        Scalar::from_canonical_bytes(bytes)
            .or_else(|| {
                // Assume big endian like the rest of the Scalars that implement PrimeField
                bytes.reverse();
                CtOption::new(Scalar::from_bytes_mod_order(bytes), Choice::from(1u8))
            })
            .map(Self)
    }

    fn to_repr(&self) -> Self::Repr {
        self.0.to_bytes()
    }

    fn is_odd(&self) -> Choice {
        Choice::from(self.0[0] & 1)
    }

    const MODULUS: &'static str = <Scalar as PrimeField>::MODULUS;
    const NUM_BITS: u32 = <Scalar as PrimeField>::NUM_BITS;
    const CAPACITY: u32 = <Scalar as PrimeField>::CAPACITY;
    const TWO_INV: Self = Self(<Scalar as PrimeField>::TWO_INV);
    const MULTIPLICATIVE_GENERATOR: Self = Self(<Scalar as PrimeField>::MULTIPLICATIVE_GENERATOR);
    const S: u32 = <Scalar as PrimeField>::S;
    const ROOT_OF_UNITY: Self = Self(<Scalar as PrimeField>::ROOT_OF_UNITY);
    const ROOT_OF_UNITY_INV: Self = Self(<Scalar as PrimeField>::ROOT_OF_UNITY_INV);
    const DELTA: Self = Self(<Scalar as PrimeField>::DELTA);
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

impl ConstantTimeEq for WrappedScalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for WrappedScalar {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<'a, 'b> Add<&'b WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn add(self, rhs: &'b WrappedScalar) -> Self::Output {
        *self + *rhs
    }
}

impl<'b> Add<&'b WrappedScalar> for WrappedScalar {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &'b WrappedScalar) -> Self::Output {
        self + *rhs
    }
}

impl<'a> Add<WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn add(self, rhs: WrappedScalar) -> Self::Output {
        *self + rhs
    }
}

impl Add for WrappedScalar {
    type Output = Self;

    #[inline]
    fn add(self, rhs: WrappedScalar) -> Self::Output {
        WrappedScalar(self.0 + rhs.0)
    }
}

impl AddAssign for WrappedScalar {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<'b> AddAssign<&'b WrappedScalar> for WrappedScalar {
    #[inline]
    fn add_assign(&mut self, rhs: &'b WrappedScalar) {
        *self = *self + rhs;
    }
}

impl<'a, 'b> Sub<&'b WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn sub(self, rhs: &'b WrappedScalar) -> Self::Output {
        *self - *rhs
    }
}

impl<'b> Sub<&'b WrappedScalar> for WrappedScalar {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &'b WrappedScalar) -> Self::Output {
        self - *rhs
    }
}

impl<'a> Sub<WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn sub(self, rhs: WrappedScalar) -> Self::Output {
        *self - rhs
    }
}

impl Sub for WrappedScalar {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: WrappedScalar) -> Self::Output {
        WrappedScalar(self.0 - rhs.0)
    }
}

impl SubAssign for WrappedScalar {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<'b> SubAssign<&'b WrappedScalar> for WrappedScalar {
    #[inline]
    fn sub_assign(&mut self, rhs: &'b WrappedScalar) {
        *self = *self - rhs;
    }
}

impl<'a, 'b> Mul<&'b WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn mul(self, rhs: &'b WrappedScalar) -> Self::Output {
        *self * *rhs
    }
}

impl<'b> Mul<&'b WrappedScalar> for WrappedScalar {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &'b WrappedScalar) -> Self::Output {
        self * *rhs
    }
}

impl<'a> Mul<WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn mul(self, rhs: WrappedScalar) -> Self::Output {
        *self * rhs
    }
}

impl Mul for WrappedScalar {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: WrappedScalar) -> Self::Output {
        WrappedScalar(self.0 * rhs.0)
    }
}

impl MulAssign for WrappedScalar {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl<'b> MulAssign<&'b WrappedScalar> for WrappedScalar {
    #[inline]
    fn mul_assign(&mut self, rhs: &'b WrappedScalar) {
        *self = *self * rhs;
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

impl From<Scalar> for WrappedScalar {
    fn from(s: Scalar) -> WrappedScalar {
        Self(s)
    }
}

impl zeroize::DefaultIsZeroes for WrappedScalar {}

impl Serialize for WrappedScalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.0.as_bytes();
        serialize_arr(bytes, serializer)
    }
}

impl<'de> Deserialize<'de> for WrappedScalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserialize_arr(deserializer)?;
        let sc = Option::from(Scalar::from_canonical_bytes(bytes)).ok_or_else(|| {
            de::Error::custom("failed to deserialize Scalar from canonical bytes")
        })?;
        Ok(WrappedScalar(sc))
    }
}

impl LowerHex for WrappedScalar {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let tmp = self.0.to_bytes();
        for &b in tmp.iter() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl UpperHex for WrappedScalar {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let tmp = self.0.to_bytes();
        for &b in tmp.iter() {
            write!(f, "{:02X}", b)?;
        }
        Ok(())
    }
}

impl Sum for WrappedScalar {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut acc = Scalar::ZERO;
        for s in iter {
            acc += s.0;
        }
        Self(acc)
    }
}

impl<'a> Sum<&'a WrappedScalar> for WrappedScalar {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        let mut acc = Scalar::ZERO;
        for s in iter {
            acc += s.0;
        }
        Self(acc)
    }
}

impl Product for WrappedScalar {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut acc = Scalar::ONE;
        for s in iter {
            acc *= s.0;
        }
        Self(acc)
    }
}

impl<'a> Product<&'a WrappedScalar> for WrappedScalar {
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        let mut acc = Scalar::ONE;
        for s in iter {
            acc *= s.0;
        }
        Self(acc)
    }
}

fn serialize_arr<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
    if s.is_human_readable() {
        let mut space = [0u8; 64];
        hex::encode_to_slice(bytes, &mut space).unwrap();
        unsafe { core::str::from_utf8_unchecked(&space) }.serialize(s)
    } else {
        bytes.serialize(s)
    }
}

fn deserialize_arr<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
    if d.is_human_readable() {
        let s = <&str>::deserialize(d)?;
        if s.len() != 64 {
            return Err(de::Error::custom("invalid length"));
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(s, &mut bytes).unwrap();
        Ok(bytes)
    } else {
        <[u8; 32]>::deserialize(d)
    }
}

#[test]
fn ristretto_to_edwards() {
    use rand::Rng;

    let sk = Scalar::from_bytes_mod_order(rand_core::OsRng.gen::<[u8; 32]>());
    let pk = RISTRETTO_BASEPOINT_POINT * sk;
    let ek = WrappedEdwards::from(WrappedRistretto(pk));
    assert!(ek.0.is_torsion_free());
}

#[cfg(feature = "std")]
#[test]
fn serde_scalar() {
    let rng = rand::rngs::OsRng::default();
    let ws1 = WrappedScalar::random(rng);
    // serialize
    let res = serde_bare::to_vec(&ws1);
    assert!(res.is_ok());
    let wsvec = res.unwrap();
    // deserialize
    let res = serde_bare::from_slice(&wsvec);
    assert!(res.is_ok());
    let ws2: WrappedScalar = res.unwrap();
    assert_eq!(ws1, ws2);
}

#[cfg(feature = "std")]
#[test]
fn serde_edwards() {
    let rng = rand::rngs::OsRng::default();
    let ed1 = WrappedEdwards::random(rng);
    // serialize
    let res = serde_bare::to_vec(&ed1);
    assert!(res.is_ok());
    let edvec = res.unwrap();
    // deserialize
    let res = serde_bare::from_slice(&edvec);
    assert!(res.is_ok());
    let ed2: WrappedEdwards = res.unwrap();
    assert_eq!(ed1, ed2);
}
