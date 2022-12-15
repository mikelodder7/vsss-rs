/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::super::utils::MockRng;
use crate::{Feldman, Pedersen, Shamir, Share};
use elliptic_curve::{
    ff::PrimeField,
    group::{Group, GroupEncoding, ScalarMul},
};
use zeroize::Zeroize;

pub fn split_invalid_args<
    F: PrimeField + Zeroize,
    G: Group + GroupEncoding + Default + ScalarMul<F>,
    const S: usize,
>() {
    let secret = F::one();
    let mut rng = MockRng::default();
    assert!(Shamir::<0, 0>::split_secret::<F, MockRng, S>(secret, &mut rng).is_err());
    assert!(Shamir::<3, 2>::split_secret::<F, MockRng, S>(secret, &mut rng).is_err());
    assert!(Shamir::<1, 8>::split_secret::<F, MockRng, S>(secret, &mut rng).is_err());

    assert!(Feldman::<0, 0>::split_secret::<F, G, MockRng, S>(secret, None, &mut rng).is_err());
    assert!(Feldman::<3, 2>::split_secret::<F, G, MockRng, S>(secret, None, &mut rng).is_err());
    assert!(Feldman::<1, 8>::split_secret::<F, G, MockRng, S>(secret, None, &mut rng).is_err());

    assert!(
        Pedersen::<0, 0>::split_secret::<F, G, MockRng, S>(secret, None, None, None, &mut rng)
            .is_err()
    );
    assert!(
        Pedersen::<3, 2>::split_secret::<F, G, MockRng, S>(secret, None, None, None, &mut rng)
            .is_err()
    );
    assert!(
        Pedersen::<1, 8>::split_secret::<F, G, MockRng, S>(secret, None, None, None, &mut rng)
            .is_err()
    );

    let secret = F::zero();
    assert!(Shamir::<2, 3>::split_secret::<F, MockRng, S>(secret, &mut rng).is_err());
    assert!(Feldman::<2, 3>::split_secret::<F, G, MockRng, S>(secret, None, &mut rng).is_err());
    assert!(
        Pedersen::<2, 3>::split_secret::<F, G, MockRng, S>(secret, None, None, None, &mut rng)
            .is_err()
    );
}

pub fn combine_invalid<F: PrimeField, const S: usize>() {
    // No shares
    assert!(Shamir::<2, 3>::combine_shares::<F, S>(&[]).is_err());
    // One share
    assert!(Shamir::<2, 3>::combine_shares::<F, S>(&[Share([1u8; S])]).is_err());
    // No secret
    let mut share = Share([0u8; S]);
    share.0[0] = 1u8;
    assert!(Shamir::<2, 3>::combine_shares::<F, S>(&[share, Share([2u8; S])]).is_err());
    // Invalid identifier
    assert!(Shamir::<2, 3>::combine_shares::<F, S>(&[Share([0u8; S]), Share([2u8; S])]).is_err());
    // Duplicate shares
    assert!(Shamir::<2, 3>::combine_shares::<F, S>(&[Share([1u8; S]), Share([1u8; S])]).is_err());
}
