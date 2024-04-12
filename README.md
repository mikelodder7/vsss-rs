# Verifiable Secret Sharing Schemes

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache 2.0][license-image]

This crate provides various cryptography verifiable secret sharing schemes when the rust standard library is available.

* **This implementation is currently under audit and results will be published when completed. Until then use at your own risk.**
* This implementation does not require the Rust standard library.
* All operations are constant time unless explicitly noted.

## NOTE if upgrading from Version 2

The interfaces have been redesigned to be compatible with each other as well as serialization.

Version 3 defines a set of traits for implementing secret sharing schemes. While the standard mode provides quick
and easy methods to split and combine secrets, the traits allow for more flexibility and customization especially in
no-std mode. Previous versions tried to keep the two modes aligned but in doing so resulted in a lot of code duplication
and stack overflow issues. The new traits allow for a single implementation to be used in both modes and allow
no-std consumers to use exactly what they need while minimizing code duplication and stack overflows.

## NOte if upgrading from Version 3

The `ShareIdentifier` trait has been modified as follows:

- fn to_buffer which receives a byte buffer and fills the contents with the byte representation of the identifier
- fn from_buffer which receives a byte buffer and creates the identifier from the byte representation
- to_vec which returns the byte representation as a Vec<u8> if features=alloc or std is enabled.

### Why this change?

The previous method was not flexible enough to handle different types of identifiers such as u16, u32, u64, etc. 
because as_bytes returned &[u8] and there was no safe method to convert the byte representation from the identifier
when using u16, u32, etc. So the option was to either continue as is but use unsafe code with Statics (not good), 
or implement a wrapper struct that would handle the conversion but needed to implement the same methods and traits
as the primitives would (also not good and results in a lot of boilerplate).

The `Share` trait has been modified as follows:

- value and value_mut now mirror to_buffer and from_buffer in ShareIdentifier
- value_vec mirrors to_vec in ShareIdentifier

### Other changes

Before the `Share` trait was implemented for fixed sizes of 33, 49, and 97. Now all array sizes are supported. 

In addition, GenericArray of any size is supported.
`crypto-bigint` Uint types are supported as well.

Now tuples with the identifier as `.0` and the share as `.1` are supported.

Gf256 has been added as a field for secret sharing schemes with just byte sequences. All operations are constant time.
Most implementations comparatively are not constant time due to: runtime is dependent on the value of the secret such as
using if statements and looping with break statements, or using lookup tables that allow an attacker to monitor code or
data access patterns. While great for performance, they are not constant time which is desirable for cryptographic operations.
This implementation has been cross-checked for compatibility with other libraries and also implements the necessary
traits to function with this library.

### Numbering

Share numbering methods have been added. The default method has been to use incrementing numbers starting at 1. While
simple enough, again it's not flexible enough for all use cases. The following numbering methods are available:

- SequentialParticipantNumberGenerator: index for the share identifiers starts at a specified number and incrementing by a specified value until a limit is reached. The default is starting at 1 and incrementing by 1 until 255 is reached
- RandomParticipantNumberGenerator: index for the share identifiers is random. The random number generator is based on the desired index, a domain separator which are hashed using [Shake256](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf).
- ListParticipantNumberGenerator: index for the share identifiers is based on a list. The provided list must be at least as long as the number of shares to be generated. This is useful when the share identifiers are known ahead of time like in the case of [proactive secret sharing](https://eprint.iacr.org/2017/719).
- ListAndRandomParticipantNumberGenerator: a combination of the above two methods. The list is used first and then random numbers are used after the list is exhausted.
- ListAndSequentialParticipantNumberGenerator: a combination of the above two methods. The list is used first and then sequential numbers are used after the list is exhausted.

The new method `split_secret_with_participant_generator` enables the use of the above methods. If you don't need
the new flexible methods, the old method `split_secret` is still available which uses SequentialParticipantNumberGenerator starting at 1 and incrementing by 1.

### Shares and Identifiers

There was lots of requests to enable share identifiers to be more than just integer values. This is now possible
by implementing the `ShareIdentifier` trait. The `ShareIdentifier` trait is a simple trait that provides the necessary
methods for splitting and combining shares. The `ShareIdentifier` trait is implemented for 
primitive integer values by default. Other values can be used by implementing the trait for the desired type 
but keep in might endianness. By default, primitive types represented as big-endian byte sequences. As explained
earlier, `Share` is implemented for [u8; N], GenericArray<u8, N>, Uint<LIMBS>, Vec<u8>, and ShareIdentifier for all unsigned integer types.
Tuples such as {primitive integer type, [u8; N]} are also supported.
Both traits can be implemented however consumers need them to be.

The following tuples also implement `Share`:

- ({primitive integer type}, \[u8; N\])
- ({primitive integer type}, GenericArray<u8, N>) 
- ({primitive integer type}, Vec<u8>) when used with the `std` or `alloc` feature

If the share identifier is `u8` then the additional implementations exist.

- \[u8; N+1\] where N is the share size and the first byte is the identifier
- GenericArray<u8, N+1> where N is the share size and the first byte is the identifier
- Vec<u8> where the first byte is the identifier

### Polynomials
`Polynomial` holds the coefficients of the polynomial and provides methods to evaluate the polynomial at a given point.
Polymomials are only used when splitting secrets.

### Share Sets
A share set is a collection of shares that belong to the same secret. The share set provides methods to combine into
the original secret or another group. These are offered as `ReadableShareSet` and `WriteableShareSet`. In no-std mode,
combines require a `ShareSetCombiner`.

`ShareSetCombiner` is the data store used during a secret reconstruct operation.

### Secret Sharing Schemes

Secret sharing schemes are implemented as traits. The traits provide methods to split secrets and if applicable return the 
verifier set. `Shamir` only splits secrets. `Feldman` returns a verifier set. `Pedersen` returns multiple verifier sets:
one for itself and one for `Feldman`.

`FeldmanVerifierSet` and `PedersenVerifierSet` are the verifier sets returned by the schemes. They provide methods to
validate the shares. 

Since `Pedersen` returns a large amount of information after a split the `PedersenResult` trait is used to encapsulate
the data. `StdPedersenResult` is provided when an allocator is available by default.

### Other noteworthy items

When operating in standard mode, no traits should be necessary to be implemented and there are default functions
to accomplish what you want just like in previous versions.

`StdVsss` provides the majority of methods needed to accomplish splitting and reconstructing secrets but requires
specifying lots of generic parameters. If you need to use a specific field, `DefaultStdVsss` is provided to make
the process easier. `DefaultStdVsss` assumes the identifier is `u8` and the share is a `Vec<u8>`.

If you need custom structs in no-std mode the `vsss_arr_impl` macro will create the necessary implementations for you.

## [Documentation](https://docs.rs/vsss-rs)

Verifiable Secret Sharing Schemes are using to split secrets into
multiple shares and distribute them among different entities,
with the ability to verify if the shares are correct and belong
to a specific set. This crate includes Shamir's secret sharing
scheme which does not support verification but is more of a
building block for the other schemes.

This crate supports Feldman and Pedersen verifiable secret sharing
schemes.

Feldman and Pedersen are similar in many ways. It's hard to describe when to use
one over the other. Indeed, both are used in [distributed key generation](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.134.6445&rep=rep1&type=pdf).

Feldman reveals the public value of the verifier whereas Pedersen's hides it.

Feldman and Pedersen are different from Shamir when splitting the secret.
Combining shares back into the original secret is identical across all methods
and is available for each scheme for convenience.

This crate is no-std compliant and uses const generics to specify sizes.

Shares are represented as byte arrays by default but can be changed by implementing the provided traits.
When specifying share sizes, use the field size in bytes + 1 for the identifier.
Shares can represent finite fields or groups
depending on the use case. The first byte is reserved for the share identifier (x-coordinate)
and everything else is the actual value of the share (y-coordinate).

## Default methods

The default methods for splitting and combining secrets are:

- shamir::split_secret
- feldman::split_secret
- pedersen::split_secret
- combine_shares
- combine_shares_group

### P-256

To split a p256 secret using Shamir

```rust
use vsss_rs::{*, shamir};
use elliptic_curve::ff::PrimeField;
use p256::{NonZeroScalar, Scalar, SecretKey};

let mut osrng = rand_core::OsRng::default();
let sk = SecretKey::random(&mut osrng);
let nzs = sk.to_nonzero_scalar();
let res = shamir::split_secret::<Scalar, u8, Vec<u8>>(2, 3, *nzs.as_ref(), &mut osrng);
assert!(res.is_ok());
let shares = res.unwrap();
let res = combine_shares(&shares);
assert!(res.is_ok());
let scalar: Scalar = res.unwrap();
let nzs_dup =  NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
let sk_dup = SecretKey::from(nzs_dup);
assert_eq!(sk_dup.to_bytes(), sk.to_bytes());
```

Or using the `DefaultStdVsss` struct

```rust
 use elliptic_curve::ff::Field;

let mut osrng = rand_core::OsRng::default();
let secret = p256::Scalar::random(&mut osrng);
let res = DefaultStdVsss::<p256::ProjectivePoint>::split_secret(2, 3, secret, &mut osrng);
assert!(res.is_ok());
let shares = res.unwrap();
let res = combine_shares(&shares);
assert!(res.is_ok());
let scalar: p256::Scalar = res.unwrap();
assert_eq!(secret, scalar);
```

### Secp256k1

To split a k256 secret using Shamir

```rust
use vsss_rs::{*, shamir};
use elliptic_curve::ff::PrimeField;
use k256::{NonZeroScalar, Scalar, ProjectivePoint, SecretKey};

let mut osrng = rand_core::OsRng::default();
let sk = SecretKey::random(&mut osrng);
let secret = *sk.to_nonzero_scalar();
let res = shamir::split_secret::<Scalar, [u8; 1], u8, Vec<u8>>(2, 3, secret, &mut osrng);
assert!(res.is_ok());
let shares = res.unwrap();
let res = combine_shares(&shares);
assert!(res.is_ok());
let scalar: Scalar = res.unwrap();
let nzs_dup = NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
let sk_dup = SecretKey::from(nzs_dup);
assert_eq!(sk_dup.to_bytes(), sk.to_bytes());
```
or to use feldman
```rust
use vsss_rs::{*, feldman};
use bls12_381_plus::{Scalar, G1Projective};
use elliptic_curve::ff::Field;

let mut rng = rand_core::OsRng::default();
let secret = Scalar::random(&mut rng);
let res = feldman::split_secret::<G1Projective, [u8; 1], u8, Vec<u8>>(2, 3, secret, None, &mut rng);
assert!(res.is_ok());
let (shares, verifier) = res.unwrap();
for s in &shares {
    assert!(verifier.verify_share(s).is_ok());
}
let res = combine_shares(&shares);
assert!(res.is_ok());
let secret_1: Scalar = res.unwrap();
assert_eq!(secret, secret_1);
```

### Curve25519

Curve25519 is not a prime field but this crate does support it using
`features=["curve25519"]` which is enabled by default. This feature
wraps curve25519-dalek libraries so they can be used with Shamir, Feldman, and Pedersen.

Here's an example of using Ed25519 and x25519

```rust
use curve25519_dalek::scalar::Scalar;
use rand::Rng;
use ed25519_dalek::SecretKey;
use vsss_rs::{curve25519::WrappedScalar, *};
use x25519_dalek::StaticSecret;

let mut osrng = rand::rngs::OsRng::default();
let sc = Scalar::hash_from_bytes::<sha2::Sha512>(&osrng.gen::<[u8; 32]>());
let sk1 = StaticSecret::from(sc.to_bytes());
let ske1 = SecretKey::from_bytes(&sc.to_bytes()).unwrap();
let res = shamir::split_secret::<WrappedScalar, [u8; 1], u8, Vec<u8>>(2, 3, sc.into(), &mut osrng);
assert!(res.is_ok());
let shares = res.unwrap();
let res = combine_shares(&shares);
assert!(res.is_ok());
let scalar: WrappedScalar = res.unwrap();
assert_eq!(scalar.0, sc);
let sk2 = StaticSecret::from(scalar.0.to_bytes());
let ske2 = SecretKey::from_bytes(&scalar.0.to_bytes()).unwrap();
assert_eq!(sk2.to_bytes(), sk1.to_bytes());
assert_eq!(ske1.to_bytes(), ske2.to_bytes());
```

Either `RistrettoPoint` or `EdwardsPoint` may be used when using Feldman and Pedersen VSSS.

# License

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

# Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be licensed as above, without any additional terms or
conditions.

# References

1. [How to share a secret, Shamir, A. Nov, 1979](https://dl.acm.org/doi/pdf/10.1145/359168.359176)
1. [A Practical Scheme for Non-interactive Verifiable Secret Sharing, Feldman, P. 1987](https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf)
1. [Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing, Pedersen, T. 1991](https://link.springer.com/content/pdf/10.1007%2F3-540-46766-1_9.pdf)

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/vsss-rs.svg
[crate-link]: https://crates.io/crates/vsss-rs
[docs-image]: https://docs.rs/vsss-rs/badge.svg
[docs-link]: https://docs.rs/vsss-rs/
[license-image]: https://img.shields.io/badge/license-Apache2.0-blue.svg
