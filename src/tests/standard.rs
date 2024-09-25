use crate::*;
use elliptic_curve::PrimeField;
use generic_array::{typenum::Add1, ArrayLength, GenericArray};

vsss_fixed_array_impl!(FixedArrayVsss8Of15, FixedArrayPedersenResult8Of15, 8, 15);
type TestShare<F: PrimeField> = (IdentifierPrimeField<F>, IdentifierPrimeField<F>);
type FixedArrayVsss8Of15ShareSet<S: Share, V: ShareVerifier<S>> =
    <FixedArrayVsss8Of15<S, V> as Shamir<S>>::ShareSet;
type FixedArrayVsss8Of15FeldmanVerifierSet<S: Share, V: ShareVerifier<S>> =
    <FixedArrayVsss8Of15<S, V> as Feldman<S, V>>::VerifierSet;
type FixedArrayVsss8Of15PedersenVerifierSet<S: Share, V: ShareVerifier<S>> =
    <FixedArrayVsss8Of15<S, V> as Pedersen<S, V>>::PedersenVerifierSet;

type PrimeField8Of15ShareSet<G: Group + GroupEncoding + Default> =
    FixedArrayVsss8Of15ShareSet<TestShare<G::Scalar>, GroupElement<G>>;
type PrimeField8Of15FeldmanVerifierSet<G: Group + GroupEncoding + Default> =
    FixedArrayVsss8Of15FeldmanVerifierSet<TestShare<G::Scalar>, GroupElement<G>>;
type PrimeField8Of15PedersenResult<G: Group + GroupEncoding + Default> =
    FixedArrayPedersenResult8Of15<TestShare<G::Scalar>, GroupElement<G>>;

pub mod bls12_381_tests;
#[cfg(feature = "curve25519")]
pub mod curve25519_tests;
pub mod ed448_tests;
pub mod invalid;
pub mod k256_tests;
pub mod p256_tests;
pub mod valid;
