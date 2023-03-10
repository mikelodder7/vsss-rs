/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::super::utils::MockRng;
use crate::*;
use elliptic_curve::{
    ff::PrimeField,
    group::{Group, GroupEncoding, ScalarMul},
};
use zeroize::Zeroize;

pub fn split_invalid_args<
    F: PrimeField + Zeroize,
    G: Group + GroupEncoding + Default + ScalarMul<F>,
>() {
    let secret = F::one();
    let mut rng = MockRng::default();
    assert!(split_secret::<F, _>(0, 0, secret, &mut rng).is_err());
    assert!(split_secret::<F, _>(3, 2, secret, &mut rng).is_err());
    assert!(split_secret::<F, _>(1, 8, secret, &mut rng).is_err());

    assert!(feldman::split_secret::<F, G, _>(0, 0, secret, None, &mut rng).is_err());
    assert!(feldman::split_secret::<F, G, _>(3, 2, secret, None, &mut rng).is_err());
    assert!(feldman::split_secret::<F, G, _>(1, 8, secret, None, &mut rng).is_err());

    assert!(pedersen::split_secret::<F, G, _>(0, 0, secret, None, None, None, &mut rng).is_err());
    assert!(pedersen::split_secret::<F, G, _>(3, 2, secret, None, None, None, &mut rng).is_err());
    assert!(pedersen::split_secret::<F, G, _>(1, 8, secret, None, None, None, &mut rng).is_err());
}

pub fn combine_invalid<F: PrimeField>() {
    // No shares
    assert!(combine_shares::<F>(&[]).is_err());
    // One share
    assert!(combine_shares::<F>(&[Share(vec![1u8; 32])]).is_err());
    // No secret
    let mut share = Share(vec![0u8; 32]);
    share.0[0] = 1u8;
    assert!(combine_shares::<F>(&[share, Share(vec![2u8; 32])]).is_err());
    // Invalid identifier
    assert!(combine_shares::<F>(&[Share(vec![0u8; 32]), Share(vec![2u8; 32])]).is_err());
    // Duplicate shares
    assert!(combine_shares::<F>(&[Share(vec![1u8; 32]), Share(vec![1u8; 32])]).is_err());
}
