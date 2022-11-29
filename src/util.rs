// Copyright Michael Lodder. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use ff::PrimeField;
use group::{Group, GroupEncoding};

pub fn bytes_to_field<F: PrimeField>(bytes: &[u8]) -> Option<F> {
    let mut s_repr = F::Repr::default();
    s_repr.as_mut()[..bytes.len()].copy_from_slice(bytes);

    let res = F::from_repr(s_repr);
    if res.is_some().unwrap_u8() == 1u8 {
        Some(res.unwrap())
    } else {
        None
    }
}

pub fn bytes_to_group<G: Group + GroupEncoding>(bytes: &[u8]) -> Option<G> {
    let mut y_repr = <G as GroupEncoding>::Repr::default();
    y_repr.as_mut().copy_from_slice(bytes);

    let y = G::from_bytes(&y_repr);
    if y.is_some().unwrap_u8() == 1 {
        Some(y.unwrap())
    } else {
        None
    }
}

#[cfg(all(not(feature = "alloc"), not(feature = "std")))]
pub fn get_group_size<G: GroupEncoding>() -> usize {
    let g = G::Repr::default();
    g.as_ref().len()
}
