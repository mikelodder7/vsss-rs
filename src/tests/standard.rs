use crate::*;

vsss_fixed_array_impl!(FixedArrayVsss8Of15, FixedArrayPedersenResult8Of15, 8, 15);
type TestShare<F> = (IdentifierPrimeField<F>, IdentifierPrimeField<F>);
type FixedArrayVsss8Of15ShareSet<S, V> = <FixedArrayVsss8Of15<S, V> as Shamir<S>>::ShareSet;
type FixedArrayVsss8Of15FeldmanVerifierSet<S, V> =
    <FixedArrayVsss8Of15<S, V> as Feldman<S, V>>::VerifierSet;

pub mod bls12_381_tests;
#[cfg(feature = "curve25519")]
pub mod curve25519_tests;
pub mod ed448_tests;
pub mod invalid;
pub mod k256_tests;
pub mod p256_tests;
pub mod valid;
