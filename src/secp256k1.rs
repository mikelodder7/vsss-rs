/*
    Copyright. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! These are convenience wrappers for the k256::Scalar and
//! k256::ProjectivePoint types.
//! The intent is the consumer will not have to use these directly since
//! the wrappers implement the [`From`] and [`Into`] traits.
use core::{
    borrow::Borrow,
    fmt,
    iter::Sum,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use elliptic_curve::{
    bigint::{ArrayEncoding, U512},
    generic_array::GenericArray,
    ops::Reduce,
    sec1::{FromEncodedPoint, ToEncodedPoint},
};
use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};
use k256::{AffinePoint, CompressedPoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar};
use rand_core::RngCore;
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

/// Wrapper around secp256k1 ProjectivePoint that handles serialization
#[derive(Copy, Clone, Debug, Eq)]
pub struct WrappedProjectivePoint(pub ProjectivePoint);

impl WrappedProjectivePoint {
    /// Serialize this value as a SEC1 EncodedPoint, optionally applying
    /// point compression.
    pub fn to_encoded_point(&self, compress: bool) -> EncodedPoint {
        self.0.to_encoded_point(compress)
    }

    /// Return the affine representation of this point, or None if it is the identity
    pub fn to_affine(&self) -> AffinePoint {
        self.0.to_affine()
    }
}

impl Group for WrappedProjectivePoint {
    type Scalar = WrappedScalar;

    fn random(rng: impl RngCore) -> Self {
        Self(ProjectivePoint::random(rng))
    }

    fn identity() -> Self {
        Self(ProjectivePoint::IDENTITY)
    }

    fn generator() -> Self {
        Self(ProjectivePoint::GENERATOR)
    }

    fn is_identity(&self) -> Choice {
        self.0.is_identity()
    }

    fn double(&self) -> Self {
        Self(self.0.double())
    }
}

impl<T> Sum<T> for WrappedProjectivePoint
where
    T: Borrow<WrappedProjectivePoint>,
{
    fn sum<I: Iterator<Item = T>>(iter: I) -> Self {
        iter.fold(Self::identity(), |acc, item| acc + item.borrow())
    }
}

impl<'a> Neg for &'a WrappedProjectivePoint {
    type Output = WrappedProjectivePoint;

    #[inline]
    fn neg(self) -> Self::Output {
        WrappedProjectivePoint(self.0.neg())
    }
}

impl Neg for WrappedProjectivePoint {
    type Output = WrappedProjectivePoint;

    #[inline]
    fn neg(self) -> Self::Output {
        -&self
    }
}

impl PartialEq for WrappedProjectivePoint {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<'a, 'b> Add<&'b WrappedProjectivePoint> for &'a WrappedProjectivePoint {
    type Output = WrappedProjectivePoint;

    #[inline]
    fn add(self, rhs: &'b WrappedProjectivePoint) -> Self::Output {
        *self + *rhs
    }
}

impl<'b> Add<&'b WrappedProjectivePoint> for WrappedProjectivePoint {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &'b WrappedProjectivePoint) -> Self::Output {
        self + *rhs
    }
}

impl<'a> Add<WrappedProjectivePoint> for &'a WrappedProjectivePoint {
    type Output = WrappedProjectivePoint;

    #[inline]
    fn add(self, rhs: WrappedProjectivePoint) -> Self::Output {
        *self + rhs
    }
}

impl Add for WrappedProjectivePoint {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        WrappedProjectivePoint(self.0 + rhs.0)
    }
}

impl AddAssign for WrappedProjectivePoint {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<'b> AddAssign<&'b WrappedProjectivePoint> for WrappedProjectivePoint {
    #[inline]
    fn add_assign(&mut self, rhs: &'b WrappedProjectivePoint) {
        *self = *self + *rhs;
    }
}

impl<'a, 'b> Sub<&'b WrappedProjectivePoint> for &'a WrappedProjectivePoint {
    type Output = WrappedProjectivePoint;

    #[inline]
    fn sub(self, rhs: &'b WrappedProjectivePoint) -> Self::Output {
        *self - *rhs
    }
}

impl<'b> Sub<&'b WrappedProjectivePoint> for WrappedProjectivePoint {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &'b WrappedProjectivePoint) -> Self::Output {
        self - *rhs
    }
}

impl<'a> Sub<WrappedProjectivePoint> for &'a WrappedProjectivePoint {
    type Output = WrappedProjectivePoint;

    #[inline]
    fn sub(self, rhs: WrappedProjectivePoint) -> Self::Output {
        *self - rhs
    }
}

impl Sub for WrappedProjectivePoint {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        WrappedProjectivePoint(self.0 - rhs.0)
    }
}

impl SubAssign for WrappedProjectivePoint {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<'b> SubAssign<&'b WrappedProjectivePoint> for WrappedProjectivePoint {
    #[inline]
    fn sub_assign(&mut self, rhs: &'b WrappedProjectivePoint) {
        *self = *self - *rhs;
    }
}

impl<'a, 'b> Mul<&'b WrappedScalar> for &'a WrappedProjectivePoint {
    type Output = WrappedProjectivePoint;

    #[inline]
    fn mul(self, rhs: &'b WrappedScalar) -> Self::Output {
        *self * *rhs
    }
}

impl<'b> Mul<&'b WrappedScalar> for WrappedProjectivePoint {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &'b WrappedScalar) -> Self::Output {
        self * *rhs
    }
}

impl<'a> Mul<WrappedScalar> for &'a WrappedProjectivePoint {
    type Output = WrappedProjectivePoint;

    #[inline]
    fn mul(self, rhs: WrappedScalar) -> Self::Output {
        *self * rhs
    }
}

impl Mul<WrappedScalar> for WrappedProjectivePoint {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: WrappedScalar) -> Self::Output {
        WrappedProjectivePoint(self.0 * rhs.0)
    }
}

impl MulAssign<WrappedScalar> for WrappedProjectivePoint {
    #[inline]
    fn mul_assign(&mut self, rhs: WrappedScalar) {
        *self = *self * rhs;
    }
}

impl<'b> MulAssign<&'b WrappedScalar> for WrappedProjectivePoint {
    #[inline]
    fn mul_assign(&mut self, rhs: &'b WrappedScalar) {
        *self = *self * *rhs;
    }
}

impl GroupEncoding for WrappedProjectivePoint {
    type Repr = CompressedPoint;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        <ProjectivePoint as GroupEncoding>::from_bytes(bytes).map(|point| point.into())
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Self::Repr {
        CompressedPoint::clone_from_slice(self.0.to_affine().to_encoded_point(true).as_bytes())
    }
}

impl Default for WrappedProjectivePoint {
    fn default() -> Self {
        Self(ProjectivePoint::IDENTITY)
    }
}

impl From<WrappedProjectivePoint> for ProjectivePoint {
    fn from(v: WrappedProjectivePoint) -> Self {
        v.0
    }
}

impl From<ProjectivePoint> for WrappedProjectivePoint {
    fn from(v: ProjectivePoint) -> Self {
        WrappedProjectivePoint(v)
    }
}

impl Serialize for WrappedProjectivePoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let ep = self.0.to_encoded_point(false);
        serializer.serialize_bytes(ep.as_bytes())
    }
}

struct WrappedProjectivePointVisitor;

impl<'de> Visitor<'de> for WrappedProjectivePointVisitor {
    type Value = WrappedProjectivePoint;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "an array of bytes")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if let Ok(ep) = EncodedPoint::from_bytes(v) {
            let pp = ProjectivePoint::from_encoded_point(&ep);
            if pp.is_some().unwrap_u8() == 1u8 {
                return Ok(WrappedProjectivePoint(pp.unwrap()));
            }
        }
        Err(de::Error::custom(
            "failed to deserialize K256 ProjectivePoint",
        ))
    }
}

impl<'de> Deserialize<'de> for WrappedProjectivePoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(WrappedProjectivePointVisitor)
    }
}

/// Wrapper around secp256k1 Scalar that handles serialization
#[derive(Copy, Clone, Debug, Eq, Default)]
pub struct WrappedScalar(pub Scalar);

impl WrappedScalar {
    /// Parses the given byte array as a scalar.
    /// Subtracts the modulus when the byte array is larger than the modulus.
    pub fn from_be_bytes_reduced(bytes: &[u8; 64]) -> Self {
        let input = U512::from_be_byte_array(*GenericArray::from_slice(bytes));
        Self(Scalar::from_uint_reduced(input))
    }

    /// Parses the given byte array as a scalar.
    /// Subtracts the modulus when the byte array is larger than the modulus.
    pub fn from_le_bytes_reduced(bytes: &[u8; 64]) -> Self {
        let input = U512::from_le_byte_array(*GenericArray::from_slice(bytes));
        Self(Scalar::from_uint_reduced(input))
    }
}

impl Field for WrappedScalar {
    fn random(rng: impl RngCore) -> Self {
        Self(Scalar::random(rng))
    }

    fn zero() -> Self {
        Self(Scalar::zero())
    }

    fn one() -> Self {
        Self(Scalar::one())
    }

    fn is_zero(&self) -> Choice {
        self.0.is_zero()
    }

    fn square(&self) -> Self {
        Self(self.0 * self.0)
    }

    fn double(&self) -> Self {
        Self(self.0 + self.0)
    }

    fn invert(&self) -> CtOption<Self> {
        CtOption::new(Self(self.0.invert().unwrap()), Choice::from(1u8))
    }

    fn sqrt(&self) -> CtOption<Self> {
        // Not used for secret sharing
        unimplemented!()
    }
}

impl PrimeField for WrappedScalar {
    type Repr = FieldBytes;

    fn from_repr(bytes: Self::Repr) -> CtOption<Self> {
        let res = Scalar::from_repr(bytes);
        if res.is_some().unwrap_u8() == 1u8 {
            CtOption::new(Self(res.unwrap()), Choice::from(1u8))
        } else {
            CtOption::new(Self::default(), Choice::from(0u8))
        }
    }

    fn to_repr(&self) -> Self::Repr {
        self.0.to_repr()
    }

    fn is_odd(&self) -> Choice {
        self.0.is_odd()
    }

    const NUM_BITS: u32 = Scalar::NUM_BITS;
    const CAPACITY: u32 = Scalar::CAPACITY;

    fn multiplicative_generator() -> Self {
        unimplemented!();
    }

    const S: u32 = Scalar::S;

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
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for WrappedScalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let scalar = Scalar::deserialize(deserializer)?;
        Ok(WrappedScalar(scalar))
    }
}

#[test]
fn serde_scalar() {
    use ff::Field;

    let rng = rand::rngs::OsRng::default();
    let ws1 = WrappedScalar::from(Scalar::random(rng));
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

#[test]
fn serde_projective_point() {
    use group::Group;

    let rng = rand::rngs::OsRng::default();
    let wpp1 = WrappedProjectivePoint::from(ProjectivePoint::random(rng));
    // serialize
    let res = serde_bare::to_vec(&wpp1);
    assert!(res.is_ok());
    let wppvec = res.unwrap();
    // deserialize
    let res = serde_bare::from_slice(&wppvec);
    assert!(res.is_ok());
    let wpp2: WrappedProjectivePoint = res.unwrap();
    assert_eq!(wpp1, wpp2);
}
