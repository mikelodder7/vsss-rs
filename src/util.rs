/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

pub trait CtIsZero {
    fn ct_is_zero(&self) -> subtle::Choice;
}

pub trait CtIsNotZero {
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
        subtle::Choice::from((((t | -t) >> 7) + 1) as u8)
    }
}

impl CtIsZero for i8 {
    fn ct_is_zero(&self) -> subtle::Choice {
        let t = *self;
        subtle::Choice::from((((t | -t) >> 7) + 1) as u8)
    }
}

impl CtIsZero for u16 {
    fn ct_is_zero(&self) -> subtle::Choice {
        let t = *self as i16;
        subtle::Choice::from((((t | -t) >> 15) + 1) as u8)
    }
}

impl CtIsZero for i16 {
    fn ct_is_zero(&self) -> subtle::Choice {
        let t = *self;
        subtle::Choice::from((((t | -t) >> 15) + 1) as u8)
    }
}

impl CtIsZero for u32 {
    fn ct_is_zero(&self) -> subtle::Choice {
        let t = *self as i32;
        subtle::Choice::from((((t | -t) >> 31) + 1) as u8)
    }
}

impl CtIsZero for i32 {
    fn ct_is_zero(&self) -> subtle::Choice {
        let t = *self;
        subtle::Choice::from((((t | -t) >> 31) + 1) as u8)
    }
}

impl CtIsZero for u64 {
    fn ct_is_zero(&self) -> subtle::Choice {
        let t = *self as i64;
        subtle::Choice::from((((t | -t) >> 63) + 1) as u8)
    }
}

impl CtIsZero for i64 {
    fn ct_is_zero(&self) -> subtle::Choice {
        let t = *self;
        subtle::Choice::from((((t | -t) >> 63) + 1) as u8)
    }
}

#[cfg(target_pointer_width = "64")]
impl CtIsZero for u128 {
    fn ct_is_zero(&self) -> subtle::Choice {
        let t = *self as i128;
        subtle::Choice::from((((t | -t) >> 127) + 1) as u8)
    }
}

#[cfg(target_pointer_width = "64")]
impl CtIsZero for i128 {
    fn ct_is_zero(&self) -> subtle::Choice {
        let t = *self;
        subtle::Choice::from((((t | -t) >> 127) + 1) as u8)
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
        subtle::Choice::from(-((t | -t) >> 7) as u8)
    }
}

impl CtIsNotZero for i8 {
    fn ct_is_not_zero(&self) -> subtle::Choice {
        let t = *self;
        subtle::Choice::from(-((t | -t) >> 7) as u8)
    }
}

impl CtIsNotZero for u16 {
    fn ct_is_not_zero(&self) -> subtle::Choice {
        let t = *self as i16;
        subtle::Choice::from(-((t | -t) >> 15) as u8)
    }
}

impl CtIsNotZero for i16 {
    fn ct_is_not_zero(&self) -> subtle::Choice {
        let t = *self;
        subtle::Choice::from(-((t | -t) >> 15) as u8)
    }
}

impl CtIsNotZero for u32 {
    fn ct_is_not_zero(&self) -> subtle::Choice {
        let t = *self as i32;
        subtle::Choice::from(-((t | -t) >> 31) as u8)
    }
}

impl CtIsNotZero for i32 {
    fn ct_is_not_zero(&self) -> subtle::Choice {
        let t = *self;
        subtle::Choice::from(-((t | -t) >> 31) as u8)
    }
}

impl CtIsNotZero for u64 {
    fn ct_is_not_zero(&self) -> subtle::Choice {
        let t = *self as i64;
        subtle::Choice::from(-((t | -t) >> 63) as u8)
    }
}

impl CtIsNotZero for i64 {
    fn ct_is_not_zero(&self) -> subtle::Choice {
        let t = *self;
        subtle::Choice::from(-((t | -t) >> 63) as u8)
    }
}

#[cfg(target_pointer_width = "64")]
impl CtIsNotZero for u128 {
    fn ct_is_not_zero(&self) -> subtle::Choice {
        let t = *self as i128;
        subtle::Choice::from(-((t | -t) >> 127) as u8)
    }
}

#[cfg(target_pointer_width = "64")]
impl CtIsNotZero for i128 {
    fn ct_is_not_zero(&self) -> subtle::Choice {
        let t = *self;
        subtle::Choice::from(-((t | -t) >> 127) as u8)
    }
}
