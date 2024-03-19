/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::super::utils::MockRng;
use super::*;
use elliptic_curve::{
    ff::{Field, PrimeField},
    group::{Group, GroupEncoding},
};

pub fn split_invalid_args<
    G: Group + GroupEncoding + Default,
    I: ShareIdentifier,
    S: Share<Identifier = I>,
>() {
    let secret = G::Scalar::ONE;
    let mut rng = MockRng::default();
    assert!(TesterVsss::<G, I, S>::split_secret(0, 0, secret, &mut rng).is_err());
    assert!(TesterVsss::<G, I, S>::split_secret(3, 2, secret, &mut rng).is_err());
    assert!(TesterVsss::<G, I, S>::split_secret(1, 8, secret, &mut rng).is_err());

    assert!(
        TesterVsss::<G, I, S>::split_secret_with_verifier(0, 0, secret, None, &mut rng).is_err()
    );
    assert!(
        TesterVsss::<G, I, S>::split_secret_with_verifier(3, 2, secret, None, &mut rng).is_err()
    );
    assert!(
        TesterVsss::<G, I, S>::split_secret_with_verifier(1, 8, secret, None, &mut rng).is_err()
    );

    assert!(TesterVsss::<G, I, S>::split_secret_with_blind_verifier(
        0, 0, secret, None, None, None, &mut rng
    )
    .is_err());
    assert!(TesterVsss::<G, I, S>::split_secret_with_blind_verifier(
        3, 2, secret, None, None, None, &mut rng
    )
    .is_err());
    assert!(TesterVsss::<G, I, S>::split_secret_with_blind_verifier(
        1, 8, secret, None, None, None, &mut rng
    )
    .is_err());
}

#[cfg(any(feature = "alloc", feature = "std"))]
pub fn combine_invalid_vec<F: PrimeField>() {
    let mut shares = Vec::<[u8; 33]>::new();
    assert!(shares.combine_to_field_element::<F, [(F, F); 3]>().is_err());
    shares.push([0u8; 33]);
    assert!(shares.combine_to_field_element::<F, [(F, F); 3]>().is_err());
}

pub fn combine_invalid<F: PrimeField>() {
    // No secret
    let mut share = [0u8; 33];
    // Invalid identifier
    assert!([share.clone(), [2u8; 33]]
        .combine_to_field_element::<F, [(F, F); 3]>()
        .is_err());
    share[0] = 1u8;
    // assert!([share, [2u8; 33]]
    //     .combine_to_field_element::<F, [(F, F); 3]>()
    //     .is_err());
    // Duplicate shares
    assert!([[1u8; 33], [1u8; 33],]
        .combine_to_field_element::<F, [(F, F); 3]>()
        .is_err());
}
