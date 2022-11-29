// Copyright Michael Lodder. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use ff::PrimeField;
use group::{Group, GroupEncoding, ScalarMul};
use zeroize::Zeroize;

use super::super::utils::MockRng;
use crate::{Feldman, Pedersen, Shamir, Share};

pub fn split_invalid_args<F: PrimeField + Zeroize, G: Group + GroupEncoding + Default + ScalarMul<F>>() {
    let secret = F::one();
    let mut rng = MockRng::default();
    assert!(Shamir { t: 0, n: 0 }
        .split_secret::<F, MockRng>(secret, &mut rng)
        .is_err());
    assert!(Shamir { t: 3, n: 2 }
        .split_secret::<F, MockRng>(secret, &mut rng)
        .is_err());
    assert!(Shamir { t: 1, n: 8 }
        .split_secret::<F, MockRng>(secret, &mut rng)
        .is_err());

    assert!(Feldman { t: 0, n: 0 }
        .split_secret::<F, G, MockRng>(secret, None, &mut rng)
        .is_err());
    assert!(Feldman { t: 3, n: 2 }
        .split_secret::<F, G, MockRng>(secret, None, &mut rng)
        .is_err());
    assert!(Feldman { t: 1, n: 8 }
        .split_secret::<F, G, MockRng>(secret, None, &mut rng)
        .is_err());

    assert!(Pedersen { t: 0, n: 0 }
        .split_secret::<F, G, MockRng>(secret, None, None, None, &mut rng)
        .is_err());
    assert!(Pedersen { t: 3, n: 2 }
        .split_secret::<F, G, MockRng>(secret, None, None, None, &mut rng)
        .is_err());
    assert!(Pedersen { t: 1, n: 8 }
        .split_secret::<F, G, MockRng>(secret, None, None, None, &mut rng)
        .is_err());

    let secret = F::zero();
    assert!(Shamir { t: 2, n: 3 }
        .split_secret::<F, MockRng>(secret, &mut rng)
        .is_err());
    assert!(Feldman { t: 2, n: 3 }
        .split_secret::<F, G, MockRng>(secret, None, &mut rng)
        .is_err());
    assert!(Pedersen { t: 2, n: 3 }
        .split_secret::<F, G, MockRng>(secret, None, None, None, &mut rng)
        .is_err());
}

pub fn combine_invalid<F: PrimeField>() {
    let shamir = Shamir { t: 2, n: 3 };
    // No shares
    assert!(shamir.combine_shares::<F>(&[]).is_err());
    // One share
    assert!(shamir.combine_shares::<F>(&[Share(vec![1u8; 32])]).is_err());
    // No secret
    let mut share = Share(vec![0u8; 32]);
    share.0[0] = 1u8;
    assert!(shamir.combine_shares::<F>(&[share, Share(vec![2u8; 32])]).is_err());
    // Invalid identifier
    assert!(shamir
        .combine_shares::<F>(&[Share(vec![0u8; 32]), Share(vec![2u8; 32])])
        .is_err());
    // Duplicate shares
    assert!(shamir
        .combine_shares::<F>(&[Share(vec![1u8; 32]), Share(vec![1u8; 32])])
        .is_err());
}
