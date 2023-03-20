/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::super::{combine_shares, feldman, pedersen, shamir, Share};
use super::SHARE_SIZE;
use crate::tests::utils::MockRng;
use elliptic_curve::{
    ff::PrimeField,
    group::{Group, GroupEncoding, ScalarMul},
};
use heapless::Vec;
use zeroize::Zeroize;

pub fn split_invalid_args<
    F: PrimeField + Zeroize,
    G: Group + GroupEncoding + Default + ScalarMul<F>,
>() {
    let secret = F::ONE;
    let mut rng = MockRng::default();
    assert!(shamir::split_secret::<F, _, 0, 0, SHARE_SIZE>(secret, &mut rng).is_err());
    assert!(shamir::split_secret::<F, _, 3, 2, SHARE_SIZE>(secret, &mut rng).is_err());
    assert!(shamir::split_secret::<F, _, 1, 8, SHARE_SIZE>(secret, &mut rng).is_err());

    assert!(feldman::split_secret::<F, G, _, 0, 0, SHARE_SIZE>(secret, None, &mut rng).is_err());
    assert!(feldman::split_secret::<F, G, _, 3, 2, SHARE_SIZE>(secret, None, &mut rng).is_err());
    assert!(feldman::split_secret::<F, G, _, 1, 8, SHARE_SIZE>(secret, None, &mut rng).is_err());

    assert!(pedersen::split_secret::<F, G, _, 0, 0, SHARE_SIZE>(
        secret, None, None, None, &mut rng
    )
    .is_err());
    assert!(pedersen::split_secret::<F, G, _, 3, 2, SHARE_SIZE>(
        secret, None, None, None, &mut rng
    )
    .is_err());
    assert!(pedersen::split_secret::<F, G, _, 1, 8, SHARE_SIZE>(
        secret, None, None, None, &mut rng
    )
    .is_err());
}

pub fn combine_invalid<F: PrimeField, const S: usize>() {
    // No shares
    assert!(combine_shares::<F, S>(&[]).is_err());
    // One share
    assert!(combine_shares::<F, S>(&[Share::<S>(Vec::from_slice(&[1u8; S]).unwrap())]).is_err());
    // No secret
    let mut share = Share::<S>(Vec::from_slice(&[0u8; S]).unwrap());
    share.0[0] = 1u8;
    assert!(combine_shares::<F, S>(&[share, Share(Vec::from_slice(&[2u8; S]).unwrap())]).is_err());
    // Invalid identifier
    assert!(combine_shares::<F, S>(&[
        Share::<S>(Vec::from_slice(&[0u8; S]).unwrap()),
        Share::<S>(Vec::from_slice(&[2u8; S]).unwrap())
    ])
    .is_err());
    // Duplicate shares
    assert!(combine_shares::<F, S>(&[
        Share::<S>(Vec::from_slice(&[1u8; S]).unwrap()),
        Share::<S>(Vec::from_slice(&[1u8; S]).unwrap())
    ])
    .is_err());
}
