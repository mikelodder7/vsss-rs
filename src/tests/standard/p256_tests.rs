/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::invalid::*;
use super::valid::*;
use crate::*;
use p256::{ProjectivePoint, Scalar};

use crate::tests::standard::TestShare;

#[test]
fn invalid_tests() {
    split_invalid_args::<TestShare<Scalar>, GroupElement<ProjectivePoint>>();
    combine_invalid::<Scalar>();
}

#[test]
fn valid_tests() {
    combine_single::<ProjectivePoint>();
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn valid_std_tests() {
    combine_all::<ProjectivePoint>();
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn key_tests() {
    use crate::shamir;
    use elliptic_curve::PrimeField;
    use p256::{NonZeroScalar, SecretKey};
    use rand::rngs::OsRng;

    let mut osrng = OsRng::default();
    let sk = SecretKey::random(&mut osrng);
    let nzs = sk.to_nonzero_scalar();
    let secret = IdentifierPrimeField(*nzs.as_ref());
    let res = shamir::split_secret::<TestShare<Scalar>>(2, 3, &secret, &mut osrng);
    assert!(res.is_ok());
    let shares = res.unwrap();
    let res = shares.combine();
    assert!(res.is_ok());
    let scalar = res.unwrap();
    let nzs_dup = NonZeroScalar::from_repr(scalar.0.to_repr()).unwrap();
    let sk_dup = SecretKey::from(nzs_dup);
    assert_eq!(sk_dup.to_bytes(), sk.to_bytes());
}
