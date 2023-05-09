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
use core::{
    borrow::Borrow,
    fmt,
    iter::{Iterator, Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use core::fmt::Formatter;
use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT, RISTRETTO_BASEPOINT_POINT},
    edwards::{CompressedEdwardsY, EdwardsPoint},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, IsIdentity},
};
use elliptic_curve::{
    ff::{helpers, Field, PrimeField},
    group::{Group, GroupEncoding},
};
use rand::Rng;
use rand_core::RngCore;
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

const BASE64_SIZE: usize = 44;

struct Base64Visitor;

impl<'de> Visitor<'de> for Base64Visitor {
    type Value = [u8; 32];

    fn expecting(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "a base64 encoded string")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where E: de::Error {
        let mut s = [0u8; 32];
        let mut bytes = [0u8; 33];
        let decoded = data_encoding::BASE64.decode_mut(v.as_bytes(), &mut bytes).map_err(|_| de::Error::custom("invalid base64"))?;
        if decoded != 32 {
            return Err(de::Error::custom("invalid base64 length"));
        }
        s.copy_from_slice(&bytes[..32]);
        Ok(s)
    }
}

fn serde_base64<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
    use serde::ser::Error;

    let mut space = [0u8; BASE64_SIZE];
    data_encoding::BASE64.encode_mut(bytes, &mut space);
    s.serialize_str(unsafe { core::str::from_utf8_unchecked(&space) })
}

/// Wraps a ristretto25519 point
#[derive(Copy, Clone, Debug, Eq)]
pub struct WrappedRistretto(pub RistrettoPoint);

impl Group for WrappedRistretto {
    type Scalar = WrappedScalar;

    fn random(mut rng: impl RngCore) -> Self {
        let mut seed = [0u8; 64];
        rng.fill_bytes(&mut seed);
        Self(RistrettoPoint::from_uniform_bytes(&seed))
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

impl Default for WrappedRistretto {
    fn default() -> Self {
        Self(RistrettoPoint::identity())
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
        if serializer.is_human_readable() {
            serde_base64(self.0.compress().as_bytes(), serializer)
        } else {
            // serialize as compressed ristretto
            let t = self.0.compress().to_bytes();
            t.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for WrappedRistretto {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut bytes = [0u8; 32];
        if deserializer.is_human_readable() {
            bytes = deserializer.deserialize_str(Base64Visitor)?;
        } else {
            bytes = <[u8; 32]>::deserialize(deserializer)?;
        }
        // deserialize compressed ristretto, then decompress
        if let Some(ep) = CompressedRistretto::from_slice(&bytes).decompress() {
            return Ok(WrappedRistretto(ep));
        }
        Err(de::Error::custom(
            "failed to deserialize CompressedRistretto",
        ))
    }
}

/// Wraps an ed25519 point
#[derive(Copy, Clone, Debug, Eq)]
pub struct WrappedEdwards(pub EdwardsPoint);

impl Group for WrappedEdwards {
    type Scalar = WrappedScalar;

    fn random(mut rng: impl RngCore) -> Self {
        Self(EdwardsPoint::hash_from_bytes::<sha2_9::Sha512>(
            &rng.gen::<[u8; 32]>(),
        ))
    }

    fn identity() -> Self {
        Self(EdwardsPoint::identity())
    }

    fn generator() -> Self {
        Self(ED25519_BASEPOINT_POINT)
    }

    fn is_identity(&self) -> Choice {
        Choice::from(u8::from(self.0.is_identity()))
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
            None => CtOption::new(Self(EdwardsPoint::identity()), Choice::from(0u8)),
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

impl Default for WrappedEdwards {
    fn default() -> Self {
        Self(EdwardsPoint::identity())
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
        if serializer.is_human_readable() {
            serde_base64(self.0.compress().as_bytes(), serializer)
        } else {
            // serialize as compressed ristretto
            let t = self.0.compress().to_bytes();
            t.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for WrappedEdwards {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut bytes = [0u8; 32];
        if d.is_human_readable() {
            bytes = d.deserialize_str(Base64Visitor)?;
        } else {
            bytes = <[u8; 32]>::deserialize(d)?;
        }
        // deserialize compressed edwards y, then decompress
        if let Some(ep) = CompressedEdwardsY::from_slice(&bytes).decompress() {
            return Ok(WrappedEdwards(ep));
        }
        Err(de::Error::custom(
            "failed to deserialize CompressedEdwardsY",
        ))
    }
}

/// Wraps a curve25519 scalar
#[derive(Copy, Clone, Debug, Eq, Default)]
pub struct WrappedScalar(pub Scalar);

impl Field for WrappedScalar {
    const ZERO: Self = Self(Scalar::from_bits([0u8; 32]));
    const ONE: Self = Self(Scalar::from_bits([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]));

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
    type Repr = [u8; 32];

    fn from_repr(bytes: Self::Repr) -> CtOption<Self> {
        CtOption::new(Self(Scalar::from_bits(bytes)), Choice::from(1u8))
    }

    fn to_repr(&self) -> Self::Repr {
        self.0.to_bytes()
    }

    fn is_odd(&self) -> Choice {
        Choice::from(self.0[0] & 1)
    }

    const MODULUS: &'static str =
        "0000100000000000000000000014def9000dea2f79cd65810002631a5cf5d3ed";

    const NUM_BITS: u32 = 255;
    const CAPACITY: u32 = Self::NUM_BITS - 1;
    const TWO_INV: Self = Self(Scalar::from_bits([
        0xf7, 0xe9, 0x7a, 0x2e, 0x8d, 0x31, 0x09, 0x2c, 0x6b, 0xce, 0x7b, 0x51, 0xef, 0x7c, 0x6f,
        0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x08,
    ]));
    const MULTIPLICATIVE_GENERATOR: Self = Self(Scalar::from_bits([
        0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ]));

    const S: u32 = 16;
    const ROOT_OF_UNITY: Self = Self(Scalar::from_bits([
        0x13, 0xec, 0x5b, 0xd7, 0x37, 0xca, 0x0f, 0xa2, 0xf3, 0xf8, 0xb2, 0x1c, 0x58, 0xfb, 0xd7,
        0x24, 0x06, 0x30, 0x4c, 0x86, 0x38, 0x8a, 0x6a, 0x40, 0xdb, 0x53, 0xbd, 0x45, 0x20, 0x05,
        0x00, 0x00,
    ]));
    const ROOT_OF_UNITY_INV: Self = Self(Scalar::from_bits([
        0x09, 0x91, 0xe8, 0xf4, 0x91, 0xbb, 0xc8, 0xca, 0x08, 0xed, 0xfb, 0xe5, 0xde, 0x4a, 0x8e,
        0xdb, 0xea, 0x46, 0x8f, 0x60, 0x55, 0xfd, 0xbd, 0x30, 0x37, 0xae, 0xc1, 0x09, 0x0a, 0x07,
        0x00, 0x00,
    ]));
    const DELTA: Self = Self(Scalar::from_bits([
        0x89, 0xf6, 0x30, 0x4e, 0x68, 0x88, 0x5f, 0x18, 0xae, 0xa2, 0xee, 0x41, 0x54, 0xce, 0x9b,
        0x4d, 0x17, 0xda, 0xad, 0xd4, 0x92, 0x69, 0x49, 0x1c, 0xfa, 0x5c, 0xa3, 0xd3, 0x99, 0x00,
        0x00, 0x00,
    ]));
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
        if serializer.is_human_readable() {
            serde_base64(self.0.as_bytes(), serializer)
        } else {
            self.0.to_bytes().serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for WrappedScalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut bytes = [0u8; 32];
        if deserializer.is_human_readable() {
            bytes = deserializer.deserialize_str(Base64Visitor)?;
        } else {
            bytes = <[u8; 32]>::deserialize(deserializer)?;
        }
        Ok(WrappedScalar(Scalar::from_bits(bytes)))
    }
}

impl Sum for WrappedScalar {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut acc = Scalar::zero();
        for s in iter {
            acc += s.0;
        }
        Self(acc)
    }
}

impl<'a> Sum<&'a WrappedScalar> for WrappedScalar {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        let mut acc = Scalar::zero();
        for s in iter {
            acc += s.0;
        }
        Self(acc)
    }
}

impl Product for WrappedScalar {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut acc = Scalar::one();
        for s in iter {
            acc *= s.0;
        }
        Self(acc)
    }
}

impl<'a> Product<&'a WrappedScalar> for WrappedScalar {
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        let mut acc = Scalar::one();
        for s in iter {
            acc *= s.0;
        }
        Self(acc)
    }
}

#[test]
fn ristretto_to_edwards() {
    let sk = Scalar::from_bits(rand_core::OsRng.gen::<[u8; 32]>());
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
