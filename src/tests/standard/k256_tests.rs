/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::invalid::*;
use super::valid::*;
#[cfg(all(test, any(feature = "alloc", feature = "std")))]
use crate::*;
#[cfg(all(test, any(feature = "alloc", feature = "std")))]
use elliptic_curve::ff::{Field, PrimeField};
#[cfg(all(test, any(feature = "alloc", feature = "std")))]
use k256::{NonZeroScalar, SecretKey};
use k256::{ProjectivePoint, Scalar};
#[cfg(all(test, any(feature = "alloc", feature = "std")))]
use rand::rngs::OsRng;

#[test]
fn invalid_tests() {
    split_invalid_args::<ProjectivePoint, u8, [u8; 33]>();
    combine_invalid::<Scalar>();
}

#[test]
fn valid_tests() {
    combine_single::<ProjectivePoint, u8, [u8; 33]>();
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn valid_std_tests() {
    combine_all::<ProjectivePoint, u8, Vec<u8>>();
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn key_tests() {
    let mut osrng = OsRng::default();
    let sk = SecretKey::random(&mut osrng);
    let secret = *sk.to_nonzero_scalar();
    let res = shamir::split_secret::<Scalar, u8, [u8; 33]>(2, 3, secret, &mut osrng);
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
fn share_tuples() {
    use crate::combine_shares;

    let mut osrng = OsRng::default();
    let sk = Scalar::random(&mut osrng);

    let res = shamir::split_secret::<Scalar, u8, (u8, [u8; 32])>(2, 3, sk, &mut osrng);
    assert!(res.is_ok());
    let shares = res.unwrap();
    let res = combine_shares::<Scalar, u8, (u8, [u8; 32])>(&shares);
    assert!(res.is_ok());

    let res = shamir::split_secret::<Scalar, u16, (u16, [u8; 32])>(2, 3, sk, &mut osrng);
    assert!(res.is_ok());
    let shares = res.unwrap();
    let res = combine_shares::<Scalar, u16, (u16, [u8; 32])>(&shares);
    assert!(res.is_ok());

    let res = shamir::split_secret::<Scalar, u32, (u32, [u8; 32])>(2, 3, sk, &mut osrng);
    assert!(res.is_ok());
    let shares = res.unwrap();
    let res = combine_shares::<Scalar, u32, (u32, [u8; 32])>(&shares);
    assert!(res.is_ok());

    let res = shamir::split_secret::<Scalar, u64, (u64, [u8; 32])>(2, 3, sk, &mut osrng);
    assert!(res.is_ok());
    let shares = res.unwrap();
    let res = combine_shares::<Scalar, u64, (u64, [u8; 32])>(&shares);
    assert!(res.is_ok());

    let res = shamir::split_secret::<Scalar, usize, (usize, [u8; 32])>(2, 3, sk, &mut osrng);
    assert!(res.is_ok());
    let shares = res.unwrap();
    let res = combine_shares::<Scalar, usize, (usize, [u8; 32])>(&shares);
    assert!(res.is_ok());
}
