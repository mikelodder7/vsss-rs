/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use crate::{Error, VsssResult};
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

pub(crate) fn uint_to_be_byte_array<const LIMBS: usize>(
    u: &Uint<LIMBS>,
    buffer: &mut [u8],
) -> VsssResult<()> {
    let mut i = buffer.iter_mut();
    for limb in u.as_words() {
        let bytes = (*limb).to_be_bytes();
        for byte in bytes.iter() {
            if let Some(b) = i.next() {
                *b = *byte;
            } else {
                return Err(Error::InvalidShareConversion);
            }
        }
    }
    Ok(())
}
