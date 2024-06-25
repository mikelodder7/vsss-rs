/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use crate::{Error, VsssResult};
use core::mem::size_of;
use crypto_bigint::Uint;

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

pub(crate) fn be_byte_array_to_uint<const LIMBS: usize>(buffer: &[u8]) -> VsssResult<Uint<LIMBS>> {
    let mut value = Uint::<LIMBS>::ZERO;
    let chunks = size_of::<crypto_bigint::Word>();
    let mut word_index = 0;
    for (b, limb) in buffer.chunks_exact(chunks).rev().zip(value.as_words_mut()) {
        *limb = crypto_bigint::Word::from_be_bytes(
            b.try_into().map_err(|_| Error::InvalidShareConversion)?,
        );
        word_index += 1;
    }
    let rem = buffer.len() % chunks;
    if rem > 0 {
        let mut last_limb = 0;
        for b in &buffer[chunks * word_index..] {
            last_limb <<= 8;
            last_limb |= *b as crypto_bigint::Word;
        }
        value.as_words_mut()[word_index] = last_limb;
    }
    Ok(value)
}

pub(crate) fn uint_to_be_byte_array<const LIMBS: usize>(
    u: &Uint<LIMBS>,
    buffer: &mut [u8],
) -> VsssResult<()> {
    let bytes = size_of::<crypto_bigint::Word>();
    let mut word_index = 0;
    for (slice, limb) in buffer.chunks_exact_mut(bytes).rev().zip(u.as_words()) {
        slice.copy_from_slice(&(*limb).to_be_bytes());
        word_index += 1;
    }
    let rem = buffer.len() % bytes;
    if rem > 0 {
        let mut last_limb = u.as_words()[word_index];
        for b in &mut buffer[bytes * word_index..] {
            *b = (last_limb & 0xff) as u8;
            last_limb >>= 8;
        }
    }
    Ok(())
}
