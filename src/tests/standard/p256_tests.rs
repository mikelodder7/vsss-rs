/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::invalid::*;
use super::valid::*;
use generic_array::{typenum, GenericArray};
use p256::{ProjectivePoint, Scalar};

#[cfg(all(test, any(feature = "alloc"), feature = "std"))]
use crate::*;
#[cfg(all(test, any(feature = "alloc"), feature = "std"))]
use elliptic_curve::ff::PrimeField;
#[cfg(all(test, any(feature = "alloc"), feature = "std"))]
use p256::{NonZeroScalar, SecretKey};

#[test]
fn invalid_tests() {
    split_invalid_args::<ProjectivePoint, u8, GenericArray<u8, typenum::U33>>();
    combine_invalid::<Scalar>();
}

#[test]
fn valid_tests() {
    combine_single::<ProjectivePoint, u8, [u8; 33]>();
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn valid_std_tests() {
    use crate::Vec;
    combine_all::<ProjectivePoint, u8, Vec<u8>>();
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn std_tests() {
    use crate::{combine_shares, shamir, Vec};
    use elliptic_curve::ff::PrimeField;
    use p256::{NonZeroScalar, Scalar, SecretKey};
    use rand::rngs::OsRng;

    let mut osrng = OsRng::default();
    let sk = SecretKey::random(&mut osrng);
    let nzs = sk.to_nonzero_scalar();
    let res = shamir::split_secret::<Scalar, u8, Vec<u8>>(2, 3, *nzs.as_ref(), &mut osrng);
    assert!(res.is_ok());
    let shares = res.unwrap();
    let res = combine_shares(&shares);
    assert!(res.is_ok());
    let scalar: Scalar = res.unwrap();
    let nzs_dup = NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
    let sk_dup = SecretKey::from(nzs_dup);
    assert_eq!(sk_dup.to_bytes(), sk.to_bytes());
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn key_tests() {
    use crate::{combine_shares, shamir};
    use elliptic_curve::PrimeField;
    use p256::{NonZeroScalar, SecretKey};
    use rand::rngs::OsRng;

    let mut osrng = OsRng::default();
    let sk = SecretKey::random(&mut osrng);
    let nzs = sk.to_nonzero_scalar();
    let res = shamir::split_secret::<Scalar, u8, [u8; 33]>(2, 3, *nzs.as_ref(), &mut osrng);
    assert!(res.is_ok());
    let shares = res.unwrap();
    let res = combine_shares(&shares);
    assert!(res.is_ok());
    let scalar: Scalar = res.unwrap();
    let nzs_dup = NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
    let sk_dup = SecretKey::from(nzs_dup);
    assert_eq!(sk_dup.to_bytes(), sk.to_bytes());
}
