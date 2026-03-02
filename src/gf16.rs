//! Represents Galois Field of 2^4 elements. This uses constant time operations
//! for all operations as related to shamir secret sharing. Too many implementations
//! use lookup tables which help for speed but leak secret information.
//! No lookup tables are used in this implementation because Cryptographic operations should
//!
//! 1. Ensure runtime is independent of secret data
//! 2. Ensure code access patterns are independent of secret data
//! 3. Ensure data access patterns are independent of secret data

use crate::util::CtIsNotZero;
use crate::*;
use core::borrow::Borrow;
use core::{
    fmt::{self, Binary, Display, Formatter, LowerHex, UpperHex},
    iter::{Product, Sum},
    ops::{
        Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Deref,
        DerefMut, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign,
    },
};
use elliptic_curve::ff::{Field, PrimeField};
use rand_core::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

#[cfg(any(feature = "alloc", feature = "std"))]
use crate::ParticipantIdGeneratorType;
use rand_core::CryptoRng;
#[cfg(feature = "zeroize")]
use zeroize::DefaultIsZeroes;

#[cfg(any(feature = "alloc", feature = "std"))]
type GfShare = DefaultShare<IdentifierGf16, IdentifierGf16>;

/// Represents the finite field GF(2^4) with 16 elements.
/// Elements are stored in the lower nibble of a u8 (values 0x00..=0x0F).
/// Uses the irreducible polynomial x^4 + x + 1 for multiplication.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct Gf16(pub u8);

#[cfg(feature = "zeroize")]
impl DefaultIsZeroes for Gf16 {}

impl Display for Gf16 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl LowerHex for Gf16 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:01x}", self.0)
    }
}

impl UpperHex for Gf16 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:01X}", self.0)
    }
}

impl Binary for Gf16 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:04b}", self.0)
    }
}

impl ConditionallySelectable for Gf16 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Gf16(u8::conditional_select(&a.0, &b.0, choice))
    }
}

impl ConstantTimeEq for Gf16 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl Add for Gf16 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Gf16(self.0 ^ rhs.0)
    }
}

impl Add<&Gf16> for Gf16 {
    type Output = Gf16;

    fn add(self, rhs: &Gf16) -> Gf16 {
        self + *rhs
    }
}

impl Add<Gf16> for &Gf16 {
    type Output = Gf16;

    fn add(self, rhs: Gf16) -> Gf16 {
        *self + rhs
    }
}

impl Add<&Gf16> for &Gf16 {
    type Output = Gf16;

    fn add(self, rhs: &Gf16) -> Gf16 {
        *self + *rhs
    }
}

impl AddAssign for Gf16 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl AddAssign<&Gf16> for Gf16 {
    fn add_assign(&mut self, rhs: &Gf16) {
        *self = *self + *rhs;
    }
}

impl Sub for Gf16 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Gf16(self.0 ^ rhs.0)
    }
}

impl Sub<&Gf16> for Gf16 {
    type Output = Gf16;

    fn sub(self, rhs: &Gf16) -> Gf16 {
        Gf16(self.0 ^ rhs.0)
    }
}

impl Sub<Gf16> for &Gf16 {
    type Output = Gf16;

    fn sub(self, rhs: Gf16) -> Gf16 {
        Gf16(self.0 ^ rhs.0)
    }
}

impl Sub<&Gf16> for &Gf16 {
    type Output = Gf16;

    fn sub(self, rhs: &Gf16) -> Gf16 {
        Gf16(self.0 ^ rhs.0)
    }
}

impl SubAssign for Gf16 {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl SubAssign<&Gf16> for Gf16 {
    fn sub_assign(&mut self, rhs: &Gf16) {
        self.0 ^= rhs.0;
    }
}

impl Mul for Gf16 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self(gf16_mul(self.0, rhs.0))
    }
}

impl Mul<&Gf16> for Gf16 {
    type Output = Gf16;

    fn mul(self, rhs: &Gf16) -> Gf16 {
        self * *rhs
    }
}

impl Mul<Gf16> for &Gf16 {
    type Output = Gf16;

    fn mul(self, rhs: Gf16) -> Gf16 {
        *self * rhs
    }
}

impl Mul<&Gf16> for &Gf16 {
    type Output = Gf16;

    fn mul(self, rhs: &Gf16) -> Gf16 {
        *self * *rhs
    }
}

impl MulAssign for Gf16 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl MulAssign<&Gf16> for Gf16 {
    fn mul_assign(&mut self, rhs: &Gf16) {
        *self = *self * *rhs;
    }
}

impl Div for Gf16 {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.invert().expect("no division by zero")
    }
}

impl Div<&Gf16> for Gf16 {
    type Output = Gf16;

    fn div(self, rhs: &Gf16) -> Gf16 {
        self / *rhs
    }
}

impl Div<Gf16> for &Gf16 {
    type Output = Gf16;

    fn div(self, rhs: Gf16) -> Gf16 {
        *self / rhs
    }
}

impl Div<&Gf16> for &Gf16 {
    type Output = Gf16;

    fn div(self, rhs: &Gf16) -> Gf16 {
        *self / *rhs
    }
}

impl DivAssign for Gf16 {
    fn div_assign(&mut self, rhs: Self) {
        *self *= rhs.invert().expect("no division by zero");
    }
}

impl DivAssign<&Gf16> for Gf16 {
    fn div_assign(&mut self, rhs: &Gf16) {
        *self *= rhs.invert().expect("no division by zero");
    }
}

impl Neg for Gf16 {
    type Output = Self;

    fn neg(self) -> Self {
        self
    }
}

impl BitAnd for Gf16 {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl BitAnd<&Gf16> for Gf16 {
    type Output = Gf16;

    fn bitand(self, rhs: &Gf16) -> Gf16 {
        self & *rhs
    }
}

impl BitAnd<Gf16> for &Gf16 {
    type Output = Gf16;

    fn bitand(self, rhs: Gf16) -> Gf16 {
        *self & rhs
    }
}

impl BitAnd<&Gf16> for &Gf16 {
    type Output = Gf16;

    fn bitand(self, rhs: &Gf16) -> Gf16 {
        *self & *rhs
    }
}

impl BitAndAssign for Gf16 {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl BitAndAssign<&Gf16> for Gf16 {
    fn bitand_assign(&mut self, rhs: &Gf16) {
        self.0 &= rhs.0;
    }
}

impl BitOr for Gf16 {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOr<&Gf16> for Gf16 {
    type Output = Gf16;

    fn bitor(self, rhs: &Gf16) -> Gf16 {
        self | *rhs
    }
}

impl BitOr<Gf16> for &Gf16 {
    type Output = Gf16;

    fn bitor(self, rhs: Gf16) -> Gf16 {
        *self | rhs
    }
}

impl BitOr<&Gf16> for &Gf16 {
    type Output = Gf16;

    fn bitor(self, rhs: &Gf16) -> Gf16 {
        *self | *rhs
    }
}

impl BitOrAssign for Gf16 {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitOrAssign<&Gf16> for Gf16 {
    fn bitor_assign(&mut self, rhs: &Gf16) {
        self.0 |= rhs.0;
    }
}

impl BitXor for Gf16 {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl BitXor<&Gf16> for Gf16 {
    type Output = Gf16;

    fn bitxor(self, rhs: &Gf16) -> Gf16 {
        self ^ *rhs
    }
}

impl BitXor<Gf16> for &Gf16 {
    type Output = Gf16;

    fn bitxor(self, rhs: Gf16) -> Gf16 {
        *self ^ rhs
    }
}

impl BitXor<&Gf16> for &Gf16 {
    type Output = Gf16;

    fn bitxor(self, rhs: &Gf16) -> Gf16 {
        *self ^ *rhs
    }
}

impl BitXorAssign for Gf16 {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl BitXorAssign<&Gf16> for Gf16 {
    fn bitxor_assign(&mut self, rhs: &Gf16) {
        self.0 ^= rhs.0;
    }
}

impl<T: Borrow<Gf16>> Sum<T> for Gf16 {
    fn sum<I: Iterator<Item = T>>(iter: I) -> Self {
        iter.fold(Self(0), |acc, x| acc + x.borrow())
    }
}

impl<T: Borrow<Gf16>> Product<T> for Gf16 {
    fn product<I: Iterator<Item = T>>(iter: I) -> Self {
        iter.fold(Self(1), |acc, x| acc * x.borrow())
    }
}

impl Field for Gf16 {
    const ZERO: Self = Self(0);
    const ONE: Self = Self(1);

    fn random(mut rng: impl RngCore) -> Self {
        let b = rng.next_u32() as u8;
        // (b & 0x0E) clears bit 0 and the upper nibble, giving even values 0,2,4,...,14.
        // Adding 1 gives odd values 1,3,5,...,15 — always non-zero.
        Self((b & 0x0E) + 1)
    }

    fn square(&self) -> Self {
        self * self
    }

    fn double(&self) -> Self {
        self + self
    }

    fn invert(&self) -> CtOption<Self> {
        // Compute a^(2^4 - 2) = a^14 = a^(-1) in GF(2^4).
        // Loop pattern: after k iterations, z = a^(2^(k+1) - 1).
        // After 2 iterations: z = a^7. Final square: a^14.
        let mut z = self.0;
        for _ in 0..2 {
            z = gf16_mul(z, z);
            z = gf16_mul(z, self.0);
        }
        CtOption::new(Self(gf16_mul(z, z)), self.0.ct_is_not_zero())
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        let p = 0xfu8; // |GF(16)*| = 15
        let pm1d2 = (p - 1) >> 1; // 7
        let pp2d4 = (p + 2) >> 2; // 4

        // z = 2 (x) is a primitive root: gf16_pow(2, 7) = 11 != 1
        let z = (2..=p).find(|z| gf16_pow(*z, pm1d2) != 1).unwrap();

        let a = gf16_mul(num.0, div.0);
        let mut c = gf16_pow(a, pp2d4);
        let mut t = gf16_pow(a, pm1d2);
        let mut r = gf16_pow(z, pm1d2);

        let mut m = t;
        let mut i = 1usize;
        while m != 1 && m != 0 {
            let mut temp = m;
            for _ in 1..i {
                temp = gf16_mul(temp, temp);
            }
            let mut j = 0usize;
            while temp != 1 && temp != 0 && j < 4 {
                temp = gf16_mul(temp, temp);
                j += 1;
            }
            if i <= j {
                break;
            }
            let b = gf16_pow(r, 1u8 << (i - j - 1));
            c = gf16_mul(c, b);
            r = gf16_mul(b, b);
            t = gf16_mul(t, r);
            m = t;
            i = j;
        }
        let is_square = gf16_pow(c, 2).ct_eq(&c);
        (is_square, Self(c))
    }
}

impl From<u8> for Gf16 {
    fn from(val: u8) -> Self {
        Gf16(val)
    }
}

impl From<Gf16> for u8 {
    fn from(val: Gf16) -> u8 {
        val.0
    }
}

impl From<u16> for Gf16 {
    fn from(val: u16) -> Self {
        Gf16(val as u8)
    }
}

impl From<Gf16> for u16 {
    fn from(val: Gf16) -> u16 {
        val.0 as u16
    }
}

impl From<u32> for Gf16 {
    fn from(val: u32) -> Self {
        Gf16(val as u8)
    }
}

impl From<Gf16> for u32 {
    fn from(val: Gf16) -> u32 {
        val.0 as u32
    }
}

impl From<u64> for Gf16 {
    fn from(val: u64) -> Self {
        Gf16(val as u8)
    }
}

impl From<Gf16> for u64 {
    fn from(val: Gf16) -> u64 {
        val.0 as u64
    }
}

impl From<u128> for Gf16 {
    fn from(val: u128) -> Self {
        Gf16(val as u8)
    }
}

impl From<Gf16> for u128 {
    fn from(val: Gf16) -> u128 {
        val.0 as u128
    }
}

impl PrimeField for Gf16 {
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
    const NUM_BITS: u32 = 4;
    const CAPACITY: u32 = 3;
    /// TWO_INV = 2^(-1) in GF(2^4): 2 * 9 = 1, so TWO_INV = 9.
    const TWO_INV: Self = Self(9);
    /// x = 2 is a primitive root of GF(2^4): powers of 2 generate all 15 non-zero elements.
    const MULTIPLICATIVE_GENERATOR: Self = Self(2);
    /// S = 0 since |GF(16)*| = 15 is odd (2-adic valuation of 15 is 0).
    const S: u32 = 0;
    /// The 2^S = 1-st root of unity is 1 (trivially).
    const ROOT_OF_UNITY: Self = Self(1);
    const ROOT_OF_UNITY_INV: Self = Self(1);
    /// DELTA = MULTIPLICATIVE_GENERATOR^(2^S) = 2^1 = 2.
    const DELTA: Self = Self(2);
}

impl Gf16 {
    /// Raise the element to the power of `exp` in GF(2^4).
    pub fn pow(&self, exp: u8) -> Self {
        Self(gf16_pow(self.0, exp))
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Split a byte array into shares using GF(2^4) arithmetic.
    ///
    /// Each input byte is treated as two 4-bit nibbles (low = bits 0-3, high = bits 4-7).
    /// Both nibbles are independently shared as GF(16) elements and packed back into
    /// a single share byte, preserving the 1:1 byte ratio between secret and share data.
    /// Maximum of 15 shares (the field has 15 non-zero elements).
    pub fn split_array<B: AsRef<[u8]>>(
        threshold: usize,
        limit: usize,
        secret: B,
        rng: impl RngCore + CryptoRng,
    ) -> VsssResult<Vec<Vec<u8>>> {
        Self::split_array_with_participant_generators(
            threshold,
            limit,
            secret,
            rng,
            &[ParticipantIdGeneratorType::default()],
        )
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Split a byte array into shares using the participant number generator.
    pub fn split_array_with_participant_generators<B: AsRef<[u8]>>(
        threshold: usize,
        limit: usize,
        secret: B,
        mut rng: impl RngCore + CryptoRng,
        participant_generators: &[ParticipantIdGeneratorType<IdentifierGf16>],
    ) -> VsssResult<Vec<Vec<u8>>> {
        if limit > 15 {
            return Err(Error::InvalidSizeRequest);
        }
        let secret = secret.as_ref();
        if secret.is_empty() {
            return Err(Error::InvalidSecret);
        }
        let mut shares = Vec::with_capacity(limit);

        let collection = ParticipantIdGeneratorCollection::from(participant_generators);
        let mut participant_id_iter = collection.iter();

        for _ in 0..limit {
            let id = participant_id_iter
                .next()
                .ok_or(Error::NotEnoughShareIdentifiers)?;
            let mut inner = Vec::with_capacity(limit + 1);
            inner.push(id.0 .0);
            shares.push(inner);
        }
        for b in secret {
            // Each byte is split into two nibbles and shared independently.
            // The low nibble and high nibble are each a GF(16) element (0..=15).
            let lo = IdentifierGf16(Gf16(*b & 0x0f));
            let hi = IdentifierGf16(Gf16((*b >> 4) & 0x0f));

            let lo_shares = shamir::split_secret_with_participant_generator::<GfShare>(
                threshold,
                limit,
                &lo,
                &mut rng,
                participant_generators,
            )?;
            let hi_shares = shamir::split_secret_with_participant_generator::<GfShare>(
                threshold,
                limit,
                &hi,
                &mut rng,
                participant_generators,
            )?;
            // Pack both nibble-shares into a single byte per participant.
            for (share, (lo_s, hi_s)) in shares
                .iter_mut()
                .zip(lo_shares.iter().zip(hi_shares.iter()))
            {
                share.push((hi_s.value.0 .0 << 4) | lo_s.value.0 .0);
            }
        }
        Ok(shares)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Combine shares into a byte array.
    pub fn combine_array<B: AsRef<[Vec<u8>]>>(shares: B) -> VsssResult<Vec<u8>> {
        let shares = shares.as_ref();

        Self::are_shares_valid(shares)?;

        let mut secret = Vec::with_capacity(shares[0].len() - 1);
        let mut lo_inner = Vec::<GfShare>::with_capacity(shares.len());
        let mut hi_inner = Vec::<GfShare>::with_capacity(shares.len());

        for share in shares {
            lo_inner.push(DefaultShare {
                identifier: IdentifierGf16(Gf16(share[0])),
                value: IdentifierGf16(Gf16(0u8)),
            });
            hi_inner.push(DefaultShare {
                identifier: IdentifierGf16(Gf16(share[0])),
                value: IdentifierGf16(Gf16(0u8)),
            });
        }
        for i in 1..shares[0].len() {
            for ((lo_s, hi_s), share) in lo_inner
                .iter_mut()
                .zip(hi_inner.iter_mut())
                .zip(shares.iter())
            {
                lo_s.value = IdentifierGf16(Gf16(share[i] & 0x0f));
                hi_s.value = IdentifierGf16(Gf16((share[i] >> 4) & 0x0f));
            }
            let lo = lo_inner.combine()?.0 .0 & 0x0f;
            let hi = hi_inner.combine()?.0 .0 & 0x0f;
            secret.push((hi << 4) | lo);
        }
        Ok(secret)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn are_shares_valid(shares: &[Vec<u8>]) -> VsssResult<()> {
        if shares.len() < 2 {
            return Err(Error::SharingMinThreshold);
        }
        if shares[0].len() < 2 {
            return Err(Error::InvalidShare);
        }
        if shares[1..].iter().any(|s| s.len() != shares[0].len()) {
            return Err(Error::InvalidShare);
        }
        Ok(())
    }
}

/// Constant-time multiplication in GF(2^4) modulo x^4 + x + 1.
///
/// Uses the i8 arithmetic trick for constant-time operation:
/// `-(b & 1)` in signed arithmetic gives 0 (b even) or -1/0xFF (b odd),
/// serving as a branchless conditional mask.
/// Reduction: when bit 3 overflows on left-shift, XOR with 0x03 (= x + 1,
/// the non-leading terms of the irreducible polynomial x^4 + x + 1).
fn gf16_mul(a: u8, b: u8) -> u8 {
    let mut a = (a & 0x0f) as i8;
    let mut b = (b & 0x0f) as i8;
    let mut r = 0i8;
    for _ in 0..4 {
        // If the LSB of b is 1, XOR a into the accumulator (constant-time via -(b&1)).
        r ^= a & -(b & 1);
        b >>= 1;
        // Extract bit 3 of a (the overflow bit after a left-shift).
        let hi = (a as u8 >> 3) as i8 & 1;
        // Create an all-ones mask if bit 3 was set, zero otherwise.
        let t = -hi;
        // Shift a left by 1, masking to 4 bits.
        a = (a << 1) & 0x0f;
        // If bit 3 was set, reduce by XOR with x+1 = 0x03 (the non-leading
        // terms of the irreducible polynomial x^4 + x + 1).
        a ^= 0x03i8 & t;
    }
    (r & 0x0f) as u8
}

/// Constant-time exponentiation in GF(2^4).
///
/// Computes `base^exp` using the left-to-right binary (MSB-first) square-and-multiply
/// method, processing the 4 significant bits of the exponent.
fn gf16_pow(base: u8, exp: u8) -> u8 {
    let mut result = 1u8;
    let base = base & 0x0f;
    // Process bits from MSB (bit 3) down to LSB (bit 0).
    for i in (0..4).rev() {
        result = gf16_mul(result, result);
        let tmp = gf16_mul(result, base);
        let allow = ((exp >> i) & 1).ct_eq(&1);
        result.conditional_assign(&tmp, allow);
    }
    result.conditional_assign(&1u8, exp.ct_eq(&0));
    result
}

#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
/// Represents an identifier in the Galois Field GF(2^4).
///
/// Used solely for Sequential Participant ID generation,
/// since GF16 addition = xor i.e. identifiers just oscillate between
/// the start number and the incremented number instead of adding.
pub struct IdentifierGf16(pub Gf16);

impl Display for IdentifierGf16 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "zeroize")]
impl DefaultIsZeroes for IdentifierGf16 {}

impl Deref for IdentifierGf16 {
    type Target = Gf16;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for IdentifierGf16 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<Gf16> for IdentifierGf16 {
    fn as_ref(&self) -> &Gf16 {
        &self.0
    }
}

impl AsMut<Gf16> for IdentifierGf16 {
    fn as_mut(&mut self) -> &mut Gf16 {
        &mut self.0
    }
}

impl From<Gf16> for IdentifierGf16 {
    fn from(val: Gf16) -> Self {
        IdentifierGf16(val)
    }
}

impl From<&IdentifierGf16> for IdentifierGf16 {
    fn from(val: &IdentifierGf16) -> Self {
        IdentifierGf16(val.0)
    }
}

impl Mul<&IdentifierGf16> for IdentifierGf16 {
    type Output = IdentifierGf16;

    fn mul(self, rhs: &IdentifierGf16) -> IdentifierGf16 {
        IdentifierGf16(self.0 * rhs.0)
    }
}

impl ShareElement for IdentifierGf16 {
    type Serialization = [u8; 1];

    type Inner = Gf16;

    fn random(rng: impl RngCore + CryptoRng) -> Self {
        Self(Gf16::random(rng))
    }

    fn zero() -> Self {
        Self(Gf16::ZERO)
    }

    fn one() -> Self {
        Self(Gf16::ONE)
    }

    fn is_zero(&self) -> Choice {
        self.0.is_zero()
    }

    fn serialize(&self) -> Self::Serialization {
        [self.0 .0]
    }

    fn deserialize(serialized: &Self::Serialization) -> VsssResult<Self> {
        Ok(Self(Gf16(serialized[0])))
    }

    fn from_slice(slice: &[u8]) -> VsssResult<Self> {
        if slice.len() != 1 {
            return Err(Error::InvalidShareElement);
        }
        Ok(Self(Gf16(slice[0])))
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        vec![self.0 .0]
    }
}

impl ShareIdentifier for IdentifierGf16 {
    fn inc(&mut self, increment: &Self) {
        self.0 .0 = self.0 .0.saturating_add(increment.0 .0);
    }

    fn invert(&self) -> VsssResult<Self> {
        Option::from(self.0.invert())
            .map(Self)
            .ok_or(Error::InvalidShareElement)
    }
}

impl IdentifierGf16 {
    /// Returns additive identity.
    pub const ZERO: Self = Self(Gf16(0));
    /// Returns multiplicative identity.
    pub const ONE: Self = Self(Gf16(1));
}

#[cfg(test)]
#[cfg(any(feature = "alloc", feature = "std"))]
mod tests {
    use super::gf16_cmp;
    use super::*;
    use crate::shamir;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;
    use std::prelude::v1::Vec;

    #[test]
    fn compatibility() {
        let mut rng = ChaCha8Rng::from_seed([57u8; 32]);
        for _ in 0..1000 {
            let a = rng.gen::<u8>() & 0x0f;
            let b = rng.gen::<u8>() & 0x0f;
            let y = Gf16(a);
            let z = Gf16(b);

            assert_eq!((y * z).0, gf16_cmp::gf16_mul(a, b));
        }
        rng = ChaCha8Rng::from_entropy();
        for _ in 0..1000 {
            let a = rng.gen::<u8>() & 0x0f;
            let b = rng.gen::<u8>() & 0x0f;
            let y = Gf16(a);
            let z = Gf16(b);

            assert_eq!((y * z).0, gf16_cmp::gf16_mul(a, b));
        }

        // Verify all 15*15 = 225 non-zero products exhaustively
        for a in 1u8..=15 {
            for b in 1u8..=15 {
                assert_eq!(
                    gf16_mul(a, b),
                    gf16_cmp::gf16_mul(a, b),
                    "gf16_mul({a}, {b}) mismatch"
                );
            }
        }

        let mut rng = ChaCha8Rng::from_seed([57u8; 32]);
        for _ in 0..15 {
            let mut a = rng.gen::<u8>() & 0x0f;
            while a == 0 {
                a = rng.gen::<u8>() & 0x0f;
            }
            let y = Gf16(a);

            assert_eq!(y.invert().unwrap().0, gf16_cmp::gf16_inv(a));
        }
    }

    #[test]
    fn known_values() {
        // Powers of 2 (= x) in GF(2^4) with poly x^4+x+1:
        // x^1=2, x^2=4, x^3=8, x^4=3, x^5=6, x^6=12, x^7=11,
        // x^8=5, x^9=10, x^10=7, x^11=14, x^12=15, x^13=13, x^14=9, x^15=1
        let powers: [u8; 15] = [2, 4, 8, 3, 6, 12, 11, 5, 10, 7, 14, 15, 13, 9, 1];
        let mut val = Gf16(1);
        let gen = Gf16(2);
        for &expected in &powers {
            val = val * gen;
            assert_eq!(val.0, expected);
        }

        // 2^(-1) = 9
        assert_eq!(Gf16(2).invert().unwrap().0, 9);
        // 3^(-1): 3 = x^4, so 3^(-1) = 2^(-4) = 2^11 = 14
        assert_eq!(Gf16(3).invert().unwrap().0, 14);
        // 1^(-1) = 1
        assert_eq!(Gf16(1).invert().unwrap().0, 1);
        // 0 has no inverse
        assert!(bool::from(Gf16(0).invert().is_none()));
    }

    #[test]
    fn shamir() {
        let mut rng = ChaCha8Rng::from_seed([57u8; 32]);
        for i in 1u8..=15 {
            let secret = IdentifierGf16(Gf16(i));
            let shares = shamir::split_secret::<GfShare>(3, 5, &secret, &mut rng).unwrap();
            assert_eq!(shares[0].identifier.0 .0, 1);
            assert_eq!(shares[1].identifier.0 .0, 2);
            assert_eq!(shares[2].identifier.0 .0, 3);
            assert_eq!(shares[3].identifier.0 .0, 4);
            assert_eq!(shares[4].identifier.0 .0, 5);
            let res = &shares[0..3].to_vec().combine();
            assert!(
                res.is_ok(),
                "Failed at iteration {}, secret: {}",
                i,
                secret.0 .0
            );
            assert_eq!(
                res.unwrap(),
                secret,
                "Failed at iteration {}, secret: {}",
                i,
                secret.0 .0
            );
        }
        rng = ChaCha8Rng::from_entropy();
        for i in 1u8..=15 {
            let secret = IdentifierGf16(Gf16(i));
            let shares = shamir::split_secret::<GfShare>(3, 5, &secret, &mut rng).unwrap();
            assert_eq!(shares[0].identifier.0 .0, 1);
            assert_eq!(shares[1].identifier.0 .0, 2);
            assert_eq!(shares[2].identifier.0 .0, 3);
            assert_eq!(shares[3].identifier.0 .0, 4);
            assert_eq!(shares[4].identifier.0 .0, 5);
            let res = &shares[2..].to_vec().combine();
            assert_eq!(res.unwrap(), secret);
        }
    }

    #[test]
    fn split_array() {
        let mut rng = ChaCha8Rng::from_seed([57u8; 32]);
        let secret = b"Hello World!";
        let shares = Gf16::split_array(3, 5, secret, &mut rng).unwrap();
        assert_eq!(shares.len(), 5);

        let res = Gf16::combine_array(&shares[..3]);
        assert_eq!(res.unwrap(), secret);

        let p = ParticipantIdGeneratorType::Sequential {
            start: IdentifierGf16(Gf16(1)),
            increment: IdentifierGf16(Gf16(1)),
            count: 5,
        };
        let shares =
            Gf16::split_array_with_participant_generators(3, 5, secret, &mut rng, &[p]).unwrap();
        assert_eq!(shares.len(), 5);

        let res = Gf16::combine_array(&shares[..3]);
        let secret2 = res.unwrap();
        assert_eq!(secret2, secret);

        let res = Gf16::combine_array(&[shares[4].clone(), shares[1].clone(), shares[3].clone()]);
        let secret2 = res.unwrap();
        assert_eq!(secret2, secret);
    }

    #[test]
    fn combine_fuzz() {
        let res = Gf16::combine_array(&[vec![], vec![]]);
        assert!(res.is_err());
        let res = Gf16::combine_array(&[vec![1u8, 8u8], vec![2u8]]);
        assert!(res.is_err());

        let mut rng = ChaCha8Rng::from_entropy();
        for _ in 0..25 {
            let threshold = (rng.gen::<u8>() & 0x0f).saturating_add(1);

            let mut shares = Vec::with_capacity(threshold as usize);
            for i in 0..threshold {
                let share = vec![i; (rng.gen::<usize>() % 16) + 1];
                shares.push(share);
            }
            assert!(Gf16::combine_array(shares).is_err());
        }
    }
}

#[cfg(test)]
#[cfg(any(feature = "alloc", feature = "std"))]
mod gf16_cmp {
    // Reference implementation using carryless multiplication with explicit reduction.
    // Based on: https://github.com/mikelodder7/mayo/blob/main/src/gf16.rs
    // Irreducible polynomial: x^4 + x + 1.
    // Reduction rule: x^4 = x + 1, x^5 = x^2 + x, x^6 = x^3 + x^2.
    // For the degree-6 product of two degree-3 polynomials, high nibble bits 4-6
    // each reduce to two lower-bit contributions:
    //   bit 4 -> bits 0,1 (x^4 = x+1)
    //   bit 5 -> bits 1,2 (x^5 = x^2+x)
    //   bit 6 -> bits 2,3 (x^6 = x^3+x^2)
    // So: result = (low nibble) ^ (high_nibble >> 4) ^ (high_nibble >> 3).

    /// Multiply two GF(16) elements mod x^4 + x + 1.
    pub fn gf16_mul(a: u8, b: u8) -> u8 {
        let mut p: u8 = 0;
        p ^= (a & 1).wrapping_mul(b);
        p ^= (a & 2).wrapping_mul(b);
        p ^= (a & 4).wrapping_mul(b);
        p ^= (a & 8).wrapping_mul(b);
        let top_p = p & 0xf0;
        (p ^ (top_p >> 4) ^ (top_p >> 3)) & 0x0f
    }

    /// Compute a^(-1) in GF(16) via a^14 = a^8 * a^4 * a^2.
    pub fn gf16_inv(a: u8) -> u8 {
        let a2 = gf16_mul(a, a);
        let a4 = gf16_mul(a2, a2);
        let a8 = gf16_mul(a4, a4);
        let a6 = gf16_mul(a2, a4);
        gf16_mul(a8, a6)
    }
}
