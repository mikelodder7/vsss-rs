/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

/// Uniform non-zero sample in `1..=modulus` from a 32-bit RNG word.
///
/// Used by small-field share-identifier samplers (GF(256) with
/// `modulus = 255`, GF(16) with `modulus = 15`) where the zero element
/// is reserved for the secret and must never be produced. Modulo bias
/// is `(2^32 mod modulus) / 2^32` — at most ~2^-32, cryptographically
/// negligible for public identifiers.
#[inline]
pub(crate) fn uniform_nonzero_u8(bits: u32, modulus: u32) -> u8 {
    (bits % modulus + 1) as u8
}

/// Branch-free field-bounded add: returns `a + b` if the sum is in
/// `0..field_size`, otherwise `0`.
///
/// The zero return is a halt marker: `ParticipantIdGeneratorCollection::iter`
/// detects a zero identifier via `is_zero()` and ends the current
/// generator. Used by small-field `ShareIdentifier::inc` implementations
/// to terminate the sequential x-identifier stream at field exhaustion
/// instead of silently emitting duplicates (audit finding #3).
///
/// `field_size` is `u16` to cover the full `1..=256` range needed for
/// GF(256); the GF(16) caller passes `16`.
#[inline]
pub(crate) fn field_bounded_add(a: u8, b: u8, field_size: u16) -> u8 {
    let sum = a as u16 + b as u16;
    let in_range = ((sum < field_size) as u8).wrapping_neg();
    (sum as u8) & in_range
}

/// A trait for constant time indicating if a value is zero.
pub trait CtIsZero {
    /// Returns a `subtle::Choice` indicating if the value is zero.
    /// Returns 1 if the value is zero, otherwise 0.
    fn ct_is_zero(&self) -> subtle::Choice;
}

/// A trait for constant time indicating if a value is not zero.
pub trait CtIsNotZero {
    /// Returns a `subtle::Choice` indicating if the value is not zero.
    /// Returns 1 if the value is not zero, otherwise 0.
    fn ct_is_not_zero(&self) -> subtle::Choice;
}

impl CtIsZero for &[u8] {
    fn ct_is_zero(&self) -> subtle::Choice {
        let mut t = 0i8;
        for b in *self {
            t |= *b as i8;
        }
        t.ct_is_zero()
    }
}

impl CtIsZero for [u8] {
    fn ct_is_zero(&self) -> subtle::Choice {
        let mut t = 0i8;
        for b in self {
            t |= *b as i8;
        }
        t.ct_is_zero()
    }
}

impl CtIsZero for u8 {
    fn ct_is_zero(&self) -> subtle::Choice {
        let t = *self as i8;
        let a = ((t | t.wrapping_neg()) >> 7) + 1;
        subtle::Choice::from(a as u8)
    }
}

impl CtIsZero for i8 {
    fn ct_is_zero(&self) -> subtle::Choice {
        let t = *self;
        let a = ((t | t.wrapping_neg()) >> 7) + 1;
        subtle::Choice::from(a as u8)
    }
}

impl CtIsZero for u16 {
    fn ct_is_zero(&self) -> subtle::Choice {
        let t = *self as i16;
        let a = ((t | t.wrapping_neg()) >> 15) + 1;
        subtle::Choice::from(a as u8)
    }
}

impl CtIsZero for i16 {
    fn ct_is_zero(&self) -> subtle::Choice {
        let t = *self;
        let a = ((t | t.wrapping_neg()) >> 15) + 1;
        subtle::Choice::from(a as u8)
    }
}

impl CtIsZero for u32 {
    fn ct_is_zero(&self) -> subtle::Choice {
        let t = *self as i32;
        let a = ((t | t.wrapping_neg()) >> 31) + 1;
        subtle::Choice::from(a as u8)
    }
}

impl CtIsZero for i32 {
    fn ct_is_zero(&self) -> subtle::Choice {
        let t = *self;
        let a = ((t | t.wrapping_neg()) >> 31) + 1;
        subtle::Choice::from(a as u8)
    }
}

impl CtIsZero for u64 {
    fn ct_is_zero(&self) -> subtle::Choice {
        let t = *self as i64;
        let a = ((t | t.wrapping_neg()) >> 63) + 1;
        subtle::Choice::from(a as u8)
    }
}

impl CtIsZero for i64 {
    fn ct_is_zero(&self) -> subtle::Choice {
        let t = *self;
        let a = ((t | t.wrapping_neg()) >> 63) + 1;
        subtle::Choice::from(a as u8)
    }
}

#[cfg(target_pointer_width = "64")]
impl CtIsZero for u128 {
    fn ct_is_zero(&self) -> subtle::Choice {
        let t = *self as i128;
        let a = ((t | t.wrapping_neg()) >> 127) + 1;
        subtle::Choice::from(a as u8)
    }
}

#[cfg(target_pointer_width = "64")]
impl CtIsZero for i128 {
    fn ct_is_zero(&self) -> subtle::Choice {
        let t = *self;
        let a = ((t | t.wrapping_neg()) >> 127) + 1;
        subtle::Choice::from(a as u8)
    }
}

impl CtIsZero for usize {
    fn ct_is_zero(&self) -> subtle::Choice {
        let t = *self as isize;
        let a = ((t | t.wrapping_neg()) >> (usize::BITS - 1)) + 1;
        subtle::Choice::from(a as u8)
    }
}

impl CtIsNotZero for &[u8] {
    fn ct_is_not_zero(&self) -> subtle::Choice {
        let mut t = 0i8;
        for b in *self {
            t |= *b as i8;
        }
        t.ct_is_not_zero()
    }
}

impl CtIsNotZero for [u8] {
    fn ct_is_not_zero(&self) -> subtle::Choice {
        let mut t = 0i8;
        for b in self {
            t |= *b as i8;
        }
        t.ct_is_not_zero()
    }
}

impl CtIsNotZero for u8 {
    fn ct_is_not_zero(&self) -> subtle::Choice {
        let t = *self as i8;
        let a = ((t | t.wrapping_neg()) >> 7).wrapping_neg();
        subtle::Choice::from(a as u8)
    }
}

impl CtIsNotZero for i8 {
    fn ct_is_not_zero(&self) -> subtle::Choice {
        let t = *self;
        let a = ((t | t.wrapping_neg()) >> 7).wrapping_neg();
        subtle::Choice::from(a as u8)
    }
}

impl CtIsNotZero for u16 {
    fn ct_is_not_zero(&self) -> subtle::Choice {
        let t = *self as i16;
        let a = ((t | t.wrapping_neg()) >> 15).wrapping_neg();
        subtle::Choice::from(a as u8)
    }
}

impl CtIsNotZero for i16 {
    fn ct_is_not_zero(&self) -> subtle::Choice {
        let t = *self;
        let a = ((t | t.wrapping_neg()) >> 15).wrapping_neg();
        subtle::Choice::from(a as u8)
    }
}

impl CtIsNotZero for u32 {
    fn ct_is_not_zero(&self) -> subtle::Choice {
        let t = *self as i32;
        let a = ((t | t.wrapping_neg()) >> 31).wrapping_neg();
        subtle::Choice::from(a as u8)
    }
}

impl CtIsNotZero for i32 {
    fn ct_is_not_zero(&self) -> subtle::Choice {
        let t = *self;
        let a = ((t | t.wrapping_neg()) >> 31).wrapping_neg();
        subtle::Choice::from(a as u8)
    }
}

impl CtIsNotZero for u64 {
    fn ct_is_not_zero(&self) -> subtle::Choice {
        let t = *self as i64;
        let a = ((t | t.wrapping_neg()) >> 63).wrapping_neg();
        subtle::Choice::from(a as u8)
    }
}

impl CtIsNotZero for i64 {
    fn ct_is_not_zero(&self) -> subtle::Choice {
        let t = *self;
        let a = ((t | t.wrapping_neg()) >> 63).wrapping_neg();
        subtle::Choice::from(a as u8)
    }
}

#[cfg(target_pointer_width = "64")]
impl CtIsNotZero for u128 {
    fn ct_is_not_zero(&self) -> subtle::Choice {
        let t = *self as i128;
        let a = ((t | t.wrapping_neg()) >> 127).wrapping_neg();
        subtle::Choice::from(a as u8)
    }
}

#[cfg(target_pointer_width = "64")]
impl CtIsNotZero for i128 {
    fn ct_is_not_zero(&self) -> subtle::Choice {
        let t = *self;
        let a = ((t | t.wrapping_neg()) >> 127).wrapping_neg();
        subtle::Choice::from(a as u8)
    }
}

impl CtIsNotZero for usize {
    fn ct_is_not_zero(&self) -> subtle::Choice {
        let t = *self as isize;
        let a = ((t | t.wrapping_neg()) >> (usize::BITS - 1)).wrapping_neg();
        subtle::Choice::from(a as u8)
    }
}
