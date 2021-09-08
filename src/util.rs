/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use ff::PrimeField;
use group::{Group, GroupEncoding};
use subtle::CtOption;

pub fn bytes_to_field<F: PrimeField>(bytes: &[u8]) -> CtOption<F> {
    let mut s_repr = F::Repr::default();
    s_repr.as_mut()[..bytes.len()].copy_from_slice(bytes);

    F::from_repr(s_repr)
}

pub fn bytes_to_group<G: Group + GroupEncoding>(bytes: &[u8]) -> CtOption<G> {
    let mut y_repr = <G as GroupEncoding>::Repr::default();
    y_repr.as_mut().copy_from_slice(bytes);

    G::from_bytes(&y_repr)
}

pub fn get_group_size<G: GroupEncoding>() -> usize {
    let g = G::Repr::default();
    g.as_ref().len()
}
