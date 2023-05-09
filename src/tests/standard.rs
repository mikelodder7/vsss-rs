use crate::*;
use elliptic_curve::generic_array::{typenum, GenericArray};
type ScalarShare = GenericArray<u8, typenum::U33>;

vsss_arr_impl!(TesterVsss, TesterPedersenResult, 8, 15);

pub mod bls12_381_tests;
// #[cfg(feature = "curve25519")]
// pub mod curve25519_tests;
pub mod invalid;
// pub mod k256_tests;
// pub mod p256_tests;
pub mod valid;
