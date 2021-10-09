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
    constants::{ED25519_BASEPOINT_POINT, RISTRETTO_BASEPOINT_POINT},
    edwards::{CompressedEdwardsY, EdwardsPoint},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, IsIdentity},
};
use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};
use rand_chacha::ChaChaRng;
use rand_core::{RngCore, SeedableRng};
use subtle::{Choice, ConditionallySelectable, CtOption};

/// Wraps a ristretto25519 point
#[derive(Copy, Clone, Debug, Eq)]
pub struct WrappedRistretto(pub RistrettoPoint);

impl Group for WrappedRistretto {
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

/// Wraps an ed25519 point
#[derive(Copy, Clone, Debug, Eq)]
pub struct WrappedEdwards(pub EdwardsPoint);

impl Group for WrappedEdwards {
    type Scalar = WrappedScalar;

    fn random(mut rng: impl RngCore) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self(EdwardsPoint::hash_from_bytes::<sha2::Sha512>(&seed))
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

/// Wraps a curve25519 scalar
#[derive(Copy, Clone, Debug, Eq)]
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

#[test]
fn ristretto_to_edwards() {
    let mut osrng = rand::rngs::OsRng::default();
    let sk = Scalar::random(&mut osrng);
    let pk = RISTRETTO_BASEPOINT_POINT * sk;
    let ek = WrappedEdwards::from(WrappedRistretto(pk));
    assert!(ek.0.is_torsion_free());
}
