//! Represents Galois Field of 2^8 elements. This uses constant time operations
//! for all operations as related to shamir secret sharing. Too many implementations
//! use lookup tables which help for speed but leak secret information.
//! No lookup tables are used in this implementation because Cryptographic operations should
//!
//! 1. Ensure runtime is independent of secret data
//! 2. Ensure code access patterns are independent of secret data
//! 3. Ensure data access patterns are independent of secret data

use crate::util::CtIsNotZero;
use core::borrow::Borrow;
use core::{
    fmt::{self, Binary, Display, Formatter, LowerHex, UpperHex},
    iter::{Product, Sum},
    ops::{
        Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div,
        DivAssign, Mul, MulAssign, Neg, Sub, SubAssign,
    },
};
use elliptic_curve::ff::{Field, PrimeField};
use rand_core::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

#[cfg(any(feature = "alloc", feature = "std"))]
use rand_core::CryptoRng;

/// Represents the finite field GF(2^8) with 256 elements.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Gf256(pub u8);

impl Display for Gf256 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl LowerHex for Gf256 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}", self.0)
    }
}

impl UpperHex for Gf256 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:02X}", self.0)
    }
}

impl Binary for Gf256 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:08b}", self.0)
    }
}

impl ConditionallySelectable for Gf256 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Gf256(u8::conditional_select(&a.0, &b.0, choice))
    }
}

impl ConstantTimeEq for Gf256 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl Add for Gf256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Gf256(self.0 ^ rhs.0)
    }
}

impl Add<&Gf256> for Gf256 {
    type Output = Gf256;

    fn add(self, rhs: &Gf256) -> Gf256 {
        self + *rhs
    }
}

impl Add<Gf256> for &Gf256 {
    type Output = Gf256;

    fn add(self, rhs: Gf256) -> Gf256 {
        *self + rhs
    }
}

impl Add<&Gf256> for &Gf256 {
    type Output = Gf256;

    fn add(self, rhs: &Gf256) -> Gf256 {
        *self + *rhs
    }
}

impl AddAssign for Gf256 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl AddAssign<&Gf256> for Gf256 {
    fn add_assign(&mut self, rhs: &Gf256) {
        *self = *self + *rhs;
    }
}

impl Sub for Gf256 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Gf256(self.0 ^ rhs.0)
    }
}

impl Sub<&Gf256> for Gf256 {
    type Output = Gf256;

    fn sub(self, rhs: &Gf256) -> Gf256 {
        Gf256(self.0 ^ rhs.0)
    }
}

impl Sub<Gf256> for &Gf256 {
    type Output = Gf256;

    fn sub(self, rhs: Gf256) -> Gf256 {
        Gf256(self.0 ^ rhs.0)
    }
}

impl Sub<&Gf256> for &Gf256 {
    type Output = Gf256;

    fn sub(self, rhs: &Gf256) -> Gf256 {
        Gf256(self.0 ^ rhs.0)
    }
}

impl SubAssign for Gf256 {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl SubAssign<&Gf256> for Gf256 {
    fn sub_assign(&mut self, rhs: &Gf256) {
        self.0 ^= rhs.0;
    }
}

impl Mul for Gf256 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self(gf256_mul(self.0, rhs.0))
    }
}

impl Mul<&Gf256> for Gf256 {
    type Output = Gf256;

    fn mul(self, rhs: &Gf256) -> Gf256 {
        self * *rhs
    }
}

impl Mul<Gf256> for &Gf256 {
    type Output = Gf256;

    fn mul(self, rhs: Gf256) -> Gf256 {
        *self * rhs
    }
}

impl Mul<&Gf256> for &Gf256 {
    type Output = Gf256;

    fn mul(self, rhs: &Gf256) -> Gf256 {
        *self * *rhs
    }
}

impl MulAssign for Gf256 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl MulAssign<&Gf256> for Gf256 {
    fn mul_assign(&mut self, rhs: &Gf256) {
        *self = *self * *rhs;
    }
}

impl Div for Gf256 {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.invert().expect("no division by zero")
    }
}

impl Div<&Gf256> for Gf256 {
    type Output = Gf256;

    fn div(self, rhs: &Gf256) -> Gf256 {
        self / *rhs
    }
}

impl Div<Gf256> for &Gf256 {
    type Output = Gf256;

    fn div(self, rhs: Gf256) -> Gf256 {
        *self / rhs
    }
}

impl Div<&Gf256> for &Gf256 {
    type Output = Gf256;

    fn div(self, rhs: &Gf256) -> Gf256 {
        *self / *rhs
    }
}

impl DivAssign for Gf256 {
    fn div_assign(&mut self, rhs: Self) {
        *self *= rhs.invert().expect("no division by zero");
    }
}

impl DivAssign<&Gf256> for Gf256 {
    fn div_assign(&mut self, rhs: &Gf256) {
        *self *= rhs.invert().expect("no division by zero");
    }
}

impl Neg for Gf256 {
    type Output = Self;

    fn neg(self) -> Self {
        self
    }
}

impl BitAnd for Gf256 {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl BitAnd<&Gf256> for Gf256 {
    type Output = Gf256;

    fn bitand(self, rhs: &Gf256) -> Gf256 {
        self & *rhs
    }
}

impl BitAnd<Gf256> for &Gf256 {
    type Output = Gf256;

    fn bitand(self, rhs: Gf256) -> Gf256 {
        *self & rhs
    }
}

impl BitAnd<&Gf256> for &Gf256 {
    type Output = Gf256;

    fn bitand(self, rhs: &Gf256) -> Gf256 {
        *self & *rhs
    }
}

impl BitAndAssign for Gf256 {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl BitAndAssign<&Gf256> for Gf256 {
    fn bitand_assign(&mut self, rhs: &Gf256) {
        self.0 &= rhs.0;
    }
}

impl BitOr for Gf256 {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOr<&Gf256> for Gf256 {
    type Output = Gf256;

    fn bitor(self, rhs: &Gf256) -> Gf256 {
        self | *rhs
    }
}

impl BitOr<Gf256> for &Gf256 {
    type Output = Gf256;

    fn bitor(self, rhs: Gf256) -> Gf256 {
        *self | rhs
    }
}

impl BitOr<&Gf256> for &Gf256 {
    type Output = Gf256;

    fn bitor(self, rhs: &Gf256) -> Gf256 {
        *self | *rhs
    }
}

impl BitOrAssign for Gf256 {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitOrAssign<&Gf256> for Gf256 {
    fn bitor_assign(&mut self, rhs: &Gf256) {
        self.0 |= rhs.0;
    }
}

impl BitXor for Gf256 {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl BitXor<&Gf256> for Gf256 {
    type Output = Gf256;

    fn bitxor(self, rhs: &Gf256) -> Gf256 {
        self ^ *rhs
    }
}

impl BitXor<Gf256> for &Gf256 {
    type Output = Gf256;

    fn bitxor(self, rhs: Gf256) -> Gf256 {
        *self ^ rhs
    }
}

impl BitXor<&Gf256> for &Gf256 {
    type Output = Gf256;

    fn bitxor(self, rhs: &Gf256) -> Gf256 {
        *self ^ *rhs
    }
}

impl BitXorAssign for Gf256 {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl BitXorAssign<&Gf256> for Gf256 {
    fn bitxor_assign(&mut self, rhs: &Gf256) {
        self.0 ^= rhs.0;
    }
}

impl<T: Borrow<Gf256>> Sum<T> for Gf256 {
    fn sum<I: Iterator<Item = T>>(iter: I) -> Self {
        iter.fold(Self(0), |acc, x| acc + x.borrow())
    }
}

impl<T: Borrow<Gf256>> Product<T> for Gf256 {
    fn product<I: Iterator<Item = T>>(iter: I) -> Self {
        iter.fold(Self(1), |acc, x| acc * x.borrow())
    }
}

impl Field for Gf256 {
    const ZERO: Self = Self(0);
    const ONE: Self = Self(1);

    fn random(mut rng: impl RngCore) -> Self {
        let b = rng.next_u32() as u8;
        Self((b & 0xFE) + 1)
    }

    fn square(&self) -> Self {
        self * self
    }

    fn double(&self) -> Self {
        self + self
    }

    fn invert(&self) -> CtOption<Self> {
        let mut z = self.0;
        for _ in 0..6 {
            z = gf256_mul(z, z);
            z = gf256_mul(z, self.0);
        }
        CtOption::new(Self(gf256_mul(z, z)), self.0.ct_is_not_zero())
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        let p = 0x1bu8; // Prime field characteristic for GF(256)
        let pm1d2 = (p - 1) >> 1;
        let pp2d4 = (p + 2) >> 2;
        let z = (2..=p).find(|z| gf256_pow(*z, pm1d2) != 1).unwrap(); // Find a non-quadratic residue

        let a = gf256_mul(num.0, div.0);
        let mut c = gf256_pow(a, pp2d4);
        let mut t = gf256_pow(a, pm1d2);
        let mut r = gf256_pow(z, pm1d2);

        let mut m = t;

        let mut i = 1;
        while m != 1 {
            let mut temp = m;
            for _ in 1..i {
                temp = gf256_mul(temp, temp);
                temp %= p;
            }
            let mut j = 0;
            while temp != 1 {
                temp = gf256_mul(temp, temp);
                temp %= p;
                j += 1;
            }
            let b = gf256_pow(r, 1 << (i - j - 1));
            c = gf256_mul(c, b);
            r = gf256_mul(b, b);
            t = gf256_mul(t, r);
            m = t;
            i = j;
        }
        let is_square = gf256_pow(c, 2).ct_eq(&c);
        (is_square, Self(c))
    }
}

impl From<u8> for Gf256 {
    fn from(val: u8) -> Self {
        Gf256(val)
    }
}

impl From<Gf256> for u8 {
    fn from(val: Gf256) -> u8 {
        val.0
    }
}

impl From<u16> for Gf256 {
    fn from(val: u16) -> Self {
        Gf256(val as u8)
    }
}

impl From<Gf256> for u16 {
    fn from(val: Gf256) -> u16 {
        val.0 as u16
    }
}

impl From<u32> for Gf256 {
    fn from(val: u32) -> Self {
        Gf256(val as u8)
    }
}

impl From<Gf256> for u32 {
    fn from(val: Gf256) -> u32 {
        val.0 as u32
    }
}

impl From<u64> for Gf256 {
    fn from(val: u64) -> Self {
        Gf256(val as u8)
    }
}

impl From<Gf256> for u64 {
    fn from(val: Gf256) -> u64 {
        val.0 as u64
    }
}

impl From<u128> for Gf256 {
    fn from(val: u128) -> Self {
        Gf256(val as u8)
    }
}

impl From<Gf256> for u128 {
    fn from(val: Gf256) -> u128 {
        val.0 as u128
    }
}

impl PrimeField for Gf256 {
    type Repr = [u8; 1];

    fn from_repr(repr: Self::Repr) -> CtOption<Self> {
        CtOption::new(Self(repr[0]), Choice::from(1u8))
    }

    fn to_repr(&self) -> Self::Repr {
        [self.0]
    }

    fn is_odd(&self) -> Choice {
        (self.0 & 1).ct_eq(&1)
    }

    const MODULUS: &'static str = "";
    const NUM_BITS: u32 = 8;
    const CAPACITY: u32 = 7;
    const TWO_INV: Self = Self(141);
    const MULTIPLICATIVE_GENERATOR: Self = Self(2);
    const S: u32 = 3;
    const ROOT_OF_UNITY: Self = Self(8);
    const ROOT_OF_UNITY_INV: Self = Self(114);
    const DELTA: Self = Self(67);
}

impl Gf256 {
    /// Raise the element to the power of `exp`.
    pub fn pow(&self, exp: u8) -> Self {
        Self(gf256_pow(self.0, exp))
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Split a byte array into shares.
    pub fn split_array<B: AsRef<[u8]>>(
        threshold: usize,
        limit: usize,
        secret: B,
        mut rng: impl RngCore + CryptoRng,
    ) -> crate::VsssResult<crate::Vec<crate::Vec<u8>>> {
        if limit > 255 {
            return Err(crate::Error::InvalidSizeRequest);
        }
        let secret = secret.as_ref();
        if secret.is_empty() {
            return Err(crate::Error::InvalidSecret);
        }
        let mut shares = crate::Vec::with_capacity(limit);
        for i in 1..=limit {
            let mut inner = crate::Vec::with_capacity(limit + 1);
            inner.push(u8::try_from(i).map_err(|_| crate::Error::SharingInvalidIdentifier)?);
            shares.push(inner);
        }
        for b in secret {
            let inner_shares = crate::shamir::split_secret::<Self, u8, [u8; 2]>(
                threshold,
                limit,
                Self(*b),
                &mut rng,
            )?;
            for (share, inner_share) in shares.iter_mut().zip(inner_shares.iter()) {
                share.push(inner_share[1]);
            }
        }
        Ok(shares)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Split a byte array into shares using the participant number generator.
    pub fn split_array_with_participant_generator<
        P: crate::ParticipantNumberGenerator<Self>,
        B: AsRef<[u8]>,
    >(
        threshold: usize,
        limit: usize,
        secret: B,
        mut rng: impl RngCore + CryptoRng,
        participant_generator: P,
    ) -> crate::VsssResult<crate::Vec<crate::Vec<u8>>> {
        if limit > 255 {
            return Err(crate::Error::InvalidSizeRequest);
        }
        let secret = secret.as_ref();
        if secret.is_empty() {
            return Err(crate::Error::InvalidSecret);
        }
        let mut shares = crate::Vec::with_capacity(limit);
        for i in 0..limit {
            let mut inner = crate::Vec::with_capacity(limit + 1);
            inner.push(participant_generator.get_participant_id(i).0);
            shares.push(inner);
        }
        for b in secret {
            let inner_shares =
                crate::shamir::split_secret_with_participant_generator::<Self, u8, [u8; 2], P>(
                    threshold,
                    limit,
                    Self(*b),
                    &mut rng,
                    participant_generator.clone(),
                )?;
            for (share, inner_share) in shares.iter_mut().zip(inner_shares.iter()) {
                share.push(inner_share[1]);
            }
        }
        Ok(shares)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Combine shares into a byte array.
    pub fn combine_array<B: AsRef<[crate::Vec<u8>]>>(
        shares: B,
    ) -> crate::VsssResult<crate::Vec<u8>> {
        let shares = shares.as_ref();

        Self::are_shares_valid(shares)?;

        let mut secret = crate::Vec::with_capacity(shares[0].len() - 1);
        let mut inner_shares = crate::Vec::with_capacity(shares[0].len() - 1);

        for share in shares {
            inner_shares.push([share[0], 0u8]);
        }
        for i in 1..shares[0].len() {
            for (inner_share, share) in inner_shares.iter_mut().zip(shares.iter()) {
                inner_share[1] = share[i];
            }
            secret.push(crate::combine_shares::<Self, u8, [u8; 2]>(&inner_shares)?.0);
        }
        Ok(secret)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn are_shares_valid(shares: &[crate::Vec<u8>]) -> crate::VsssResult<()> {
        if shares.len() < 2 {
            return Err(crate::Error::SharingMinThreshold);
        }
        if shares[0].len() < 2 {
            return Err(crate::Error::InvalidShare);
        }
        if shares[1..].iter().any(|s| s.len() != shares[0].len()) {
            return Err(crate::Error::InvalidShare);
        }
        Ok(())
    }
}

fn gf256_pow(base: u8, exp: u8) -> u8 {
    let mut result = 1;
    for i in 0..8 {
        result *= result;
        let mut tmp = result;
        tmp *= base;
        let allow = ((exp >> i) & 1).ct_eq(&1);
        result.conditional_assign(&tmp, allow);
    }
    result.conditional_assign(&1, exp.ct_eq(&0));
    result
}

fn gf256_mul(a: u8, b: u8) -> u8 {
    let mut a = a as i8;
    let mut b = b as i8;
    let mut r = 0i8;
    for _ in 0..8 {
        r ^= a & -(b & 1);
        b >>= 1;
        let t = a >> 7;
        a <<= 1;
        a ^= 0x1b & t;
    }
    r as u8
}

#[cfg(test)]
#[cfg(any(feature = "alloc", feature = "std"))]
mod tests {
    use super::gf256_cmp;
    use super::*;
    use crate::{combine_shares, shamir, SequentialParticipantNumberGenerator};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;
    use std::prelude::v1::Vec;

    #[test]
    fn compatibility() {
        let mut rng = ChaCha8Rng::from_seed([57u8; 32]);
        for _ in 0..1000 {
            let a = rng.gen::<u8>();
            let b = rng.gen::<u8>();
            let y = Gf256(a);
            let z = Gf256(b);

            assert_eq!((y * z).0, gf256_cmp::gf256_mul(a, b));
        }
        rng = ChaCha8Rng::from_entropy();
        for _ in 0..1000 {
            let a = rng.gen::<u8>();
            let b = rng.gen::<u8>();
            let y = Gf256(a);
            let z = Gf256(b);

            assert_eq!((y * z).0, gf256_cmp::gf256_mul(a, b));
        }

        let mut rng = ChaCha8Rng::from_seed([57u8; 32]);
        for _ in 0..1000 {
            let mut a = rng.gen::<u8>();
            while a == 0 {
                a = rng.gen::<u8>();
            }
            let y = Gf256(a);

            assert_eq!(y.invert().unwrap().0, gf256_cmp::gf256_div(1, a));
        }
    }

    #[test]
    fn shamir() {
        let mut rng = ChaCha8Rng::from_seed([57u8; 32]);
        for i in 1..=255 {
            let secret = Gf256(i);
            let shares =
                shamir::split_secret::<Gf256, u8, [u8; 2]>(3, 5, secret, &mut rng).unwrap();
            assert_eq!(shares[0][0], 1);
            assert_eq!(shares[1][0], 2);
            assert_eq!(shares[2][0], 3);
            assert_eq!(shares[3][0], 4);
            assert_eq!(shares[4][0], 5);
            let res = combine_shares::<Gf256, u8, [u8; 2]>(&shares[0..3]);
            assert!(
                res.is_ok(),
                "Failed at iteration {}, secret: {}",
                i,
                secret.0
            );
            assert_eq!(
                res.unwrap(),
                secret,
                "Failed at iteration {}, secret: {}",
                i,
                secret.0
            );
        }
        rng = ChaCha8Rng::from_entropy();
        for i in 1..=255 {
            let secret = Gf256(i);
            let shares =
                shamir::split_secret::<Gf256, u8, [u8; 2]>(3, 5, secret, &mut rng).unwrap();
            assert_eq!(shares[0][0], 1);
            assert_eq!(shares[1][0], 2);
            assert_eq!(shares[2][0], 3);
            assert_eq!(shares[3][0], 4);
            assert_eq!(shares[4][0], 5);
            let res = combine_shares::<Gf256, u8, [u8; 2]>(&shares[2..]);
            assert_eq!(res.unwrap(), secret);
        }
    }

    #[test]
    fn split_array() {
        let mut rng = ChaCha8Rng::from_seed([57u8; 32]);
        let secret = b"Hello World!";
        let shares = Gf256::split_array(3, 5, secret, &mut rng).unwrap();
        assert_eq!(shares.len(), 5);

        let res = Gf256::combine_array(&shares[..3]);
        assert_eq!(res.unwrap(), secret);

        let p = SequentialParticipantNumberGenerator::new(
            Some(std::num::NonZeroU64::new(10).unwrap()),
            None,
            std::num::NonZeroUsize::new(5).unwrap(),
        );
        let shares =
            Gf256::split_array_with_participant_generator(3, 5, secret, &mut rng, p).unwrap();
        assert_eq!(shares.len(), 5);

        let res = Gf256::combine_array(&shares[..3]);
        let secret2 = res.unwrap();
        assert_eq!(secret2, secret);

        let res = Gf256::combine_array(&[shares[4].clone(), shares[1].clone(), shares[3].clone()]);
        let secret2 = res.unwrap();
        assert_eq!(secret2, secret);
    }

    #[test]
    fn combine_fuzz() {
        let res = Gf256::combine_array(&[vec![], vec![]]);
        assert!(res.is_err());
        let res = Gf256::combine_array(&[vec![1u8, 8u8], vec![2u8]]);
        assert!(res.is_err());

        let mut rng = ChaCha8Rng::from_entropy();
        for _ in 0..25 {
            let threshold = rng.gen::<u8>() + 1;

            let mut shares = Vec::with_capacity(threshold as usize);
            for i in 0..threshold {
                let share = vec![i; (rng.gen::<usize>() % 64) + 1];
                shares.push(share);
            }
            assert!(Gf256::combine_array(shares).is_err());
        }
    }
}

#[cfg(test)]
#[cfg(any(feature = "alloc", feature = "std"))]
mod gf256_cmp {
    // Ref https://github.com/veracruz-project/veracruz/blob/main/sdk/data-generators/shamir-secret-sharing/src/main.rs

    #[rustfmt::skip]
    const GF256_LOG: [u8; 256] = [
        0xff, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1a, 0xc6,
        0x4b, 0xc7, 0x1b, 0x68, 0x33, 0xee, 0xdf, 0x03,
        0x64, 0x04, 0xe0, 0x0e, 0x34, 0x8d, 0x81, 0xef,
        0x4c, 0x71, 0x08, 0xc8, 0xf8, 0x69, 0x1c, 0xc1,
        0x7d, 0xc2, 0x1d, 0xb5, 0xf9, 0xb9, 0x27, 0x6a,
        0x4d, 0xe4, 0xa6, 0x72, 0x9a, 0xc9, 0x09, 0x78,
        0x65, 0x2f, 0x8a, 0x05, 0x21, 0x0f, 0xe1, 0x24,
        0x12, 0xf0, 0x82, 0x45, 0x35, 0x93, 0xda, 0x8e,
        0x96, 0x8f, 0xdb, 0xbd, 0x36, 0xd0, 0xce, 0x94,
        0x13, 0x5c, 0xd2, 0xf1, 0x40, 0x46, 0x83, 0x38,
        0x66, 0xdd, 0xfd, 0x30, 0xbf, 0x06, 0x8b, 0x62,
        0xb3, 0x25, 0xe2, 0x98, 0x22, 0x88, 0x91, 0x10,
        0x7e, 0x6e, 0x48, 0xc3, 0xa3, 0xb6, 0x1e, 0x42,
        0x3a, 0x6b, 0x28, 0x54, 0xfa, 0x85, 0x3d, 0xba,
        0x2b, 0x79, 0x0a, 0x15, 0x9b, 0x9f, 0x5e, 0xca,
        0x4e, 0xd4, 0xac, 0xe5, 0xf3, 0x73, 0xa7, 0x57,
        0xaf, 0x58, 0xa8, 0x50, 0xf4, 0xea, 0xd6, 0x74,
        0x4f, 0xae, 0xe9, 0xd5, 0xe7, 0xe6, 0xad, 0xe8,
        0x2c, 0xd7, 0x75, 0x7a, 0xeb, 0x16, 0x0b, 0xf5,
        0x59, 0xcb, 0x5f, 0xb0, 0x9c, 0xa9, 0x51, 0xa0,
        0x7f, 0x0c, 0xf6, 0x6f, 0x17, 0xc4, 0x49, 0xec,
        0xd8, 0x43, 0x1f, 0x2d, 0xa4, 0x76, 0x7b, 0xb7,
        0xcc, 0xbb, 0x3e, 0x5a, 0xfb, 0x60, 0xb1, 0x86,
        0x3b, 0x52, 0xa1, 0x6c, 0xaa, 0x55, 0x29, 0x9d,
        0x97, 0xb2, 0x87, 0x90, 0x61, 0xbe, 0xdc, 0xfc,
        0xbc, 0x95, 0xcf, 0xcd, 0x37, 0x3f, 0x5b, 0xd1,
        0x53, 0x39, 0x84, 0x3c, 0x41, 0xa2, 0x6d, 0x47,
        0x14, 0x2a, 0x9e, 0x5d, 0x56, 0xf2, 0xd3, 0xab,
        0x44, 0x11, 0x92, 0xd9, 0x23, 0x20, 0x2e, 0x89,
        0xb4, 0x7c, 0xb8, 0x26, 0x77, 0x99, 0xe3, 0xa5,
        0x67, 0x4a, 0xed, 0xde, 0xc5, 0x31, 0xfe, 0x18,
        0x0d, 0x63, 0x8c, 0x80, 0xc0, 0xf7, 0x70, 0x07,
    ];

    #[rustfmt::skip]
    const GF256_EXP: [u8; 2*255] = [
        0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff,
        0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35,
        0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4,
        0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa,
        0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26,
        0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31,
        0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc,
        0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd,
        0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7,
        0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88,
        0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f,
        0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a,
        0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0,
        0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3,
        0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec,
        0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0,
        0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2,
        0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41,
        0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0,
        0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75,
        0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e,
        0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80,
        0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf,
        0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54,
        0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09,
        0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca,
        0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91,
        0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e,
        0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c,
        0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17,
        0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd,
        0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6,

        0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff,
        0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35,
        0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4,
        0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa,
        0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26,
        0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31,
        0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc,
        0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd,
        0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7,
        0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88,
        0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f,
        0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a,
        0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0,
        0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3,
        0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec,
        0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0,
        0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2,
        0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41,
        0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0,
        0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75,
        0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e,
        0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80,
        0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf,
        0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54,
        0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09,
        0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca,
        0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91,
        0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e,
        0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c,
        0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17,
        0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd,
        0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6,
    ];

    /// Multiply in GF(256).
    pub fn gf256_mul(a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            GF256_EXP
                [usize::from(GF256_LOG[usize::from(a)]) + usize::from(GF256_LOG[usize::from(b)])]
        }
    }

    /// Divide in GF(256)/
    pub fn gf256_div(a: u8, b: u8) -> u8 {
        // multiply a against inverse b
        gf256_mul(a, GF256_EXP[usize::from(255 - GF256_LOG[usize::from(b)])])
    }
}
