/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

pub fn ct_is_zero(bytes: &[u8]) -> subtle::Choice {
    let mut t = 0i8;
    for b in bytes {
        t |= *b as i8;
    }
    subtle::Choice::from((((t | t.saturating_neg()) >> 7) + 1) as u8)
}
