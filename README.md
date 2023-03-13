# Verifiable Secret Sharing Schemes

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache 2.0][license-image]
[![Build status](https://ci.appveyor.com/api/projects/status/cxxv4bng7ss5f09d?svg=true)](https://ci.appveyor.com/project/mikelodder7/vsss-rs-std)

This crate provides various cryptography verifiable secret sharing schemes when the rust standard library is available.

* **This implementation has not been reviewed or audited. Use at your own risk.**
* This implementation targets Rust `1.51` or later.
* This implementation does not require the Rust standard library.
* All operations are constant time unless explicitly noted.

## NOTE if upgrading from Version 2

The standard mode has been split out into [vsss-rs-std](https://docs.rs/vsss-rs-std) to enable both in the same project.
In addition, the interfaces have been redesigned to be compatible with each other as well as serialization.

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
one over the other. Indeed both are used in [distributed key generation](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.134.6445&rep=rep1&type=pdf).

Feldman reveals the public value of the verifier whereas Pedersen's hides it.

Feldman and Pedersen are different from Shamir when splitting the secret.
Combining shares back into the original secret is identical across all methods
and is available for each scheme for convenience.

This crate is no-std compliant and uses const generics to specify sizes.

This crate supports 255 as the maximum number of shares to be requested.
Anything higher is pretty ridiculous but if such a use case exists please let me know.

Shares are represented as byte arrays. Shares can represent finite fields or groups
depending on the use case. The first byte is reserved for the share identifier (x-coordinate)
and everything else is the actual value of the share (y-coordinate).

When specifying share sizes, use the field size in bytes + 1 for the identifier.

### P-256

To split a p256 secret using Shamir

```rust
use vsss_rs::Shamir;
use ff::PrimeField;
use p256::{NonZeroScalar, Scalar, SecretKey};
use rand::rngs::OsRng;

fn main() {
    let mut osrng = OsRng::default();
    let sk = SecretKey::random(&mut osrng);
    let nzs = sk.to_secret_scalar();
    // 32 for field size, 1 for identifier = 33
    let res = Shamir::<2, 3>::split_secret::<Scalar, OsRng, 33>(*nzs.as_ref(), &mut osrng);
    assert!(res.is_ok());
    let shares = res.unwrap();
    let res = Shamir::<2, 3>::combine_shares::<Scalar, 33>(&shares);
    assert!(res.is_ok());
    let scalar = res.unwrap();
    let nzs_dup =  NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
    let sk_dup = SecretKey::from(nzs_dup);
    assert_eq!(sk_dup.to_bytes(), sk.to_bytes());
}
```

### Secp256k1

To split a k256 secret using Shamir

```rust
use vsss_rs::Shamir;
use ff::PrimeField;
use k256::{NonZeroScalar, Scalar, SecretKey};
use rand::rngs::OsRng;

fn main() {
    let mut osrng = OsRng::default();
    let sk = SecretKey::random(&mut osrng);
    let nzs = sk.to_secret_scalar();
    let res = Shamir::<2, 3>::split_secret::<Scalar, OsRng, 33>(*nzs.as_ref(), &mut osrng);
    assert!(res.is_ok());
    let shares = res.unwrap();
    let res = Shamir::<2, 3>::combine_shares::<Scalar, 33>(&shares);
    assert!(res.is_ok());
    let scalar = res.unwrap();
    let nzs_dup = NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
    let sk_dup = SecretKey::from(nzs_dup);
    assert_eq!(sk_dup.to_bytes(), sk.to_bytes());
}
```

### BLS12-381

Feldman or Pedersen return extra information for verification using their respective verifiers

```rust
use vsss_rs::Feldman;
use bls12_381_plus::{Scalar, G1Projective};
use ff::Field;
use rand::rngs::OsRng;

fn main() {
    let mut rng = OsRng::default();
    let secret = Scalar::random(&mut rng);
    let res = Feldman::<2, 3>::split_secret::<Scalar, G1Projective, OsRng, 33>(secret, None, &mut rng);
    assert!(res.is_ok());
    let (shares, verifier) = res.unwrap();
    for s in &shares {
        assert!(verifier.verify(s));
    }
    let res = Feldman::<2, 3>::combine_shares::<Scalar, 33>(&shares);
    assert!(res.is_ok());
    let secret_1 = res.unwrap();
    assert_eq!(secret, secret_1);
}
```

### Curve25519

Curve25519 is not a prime field but this crate does support it using
`features=["curve25519"]` which is enabled by default. This feature
wraps curve25519-dalek libraries so they can be used with Shamir, Feldman, and Pedersen.

Here's an example of using Ed25519 and x25519

```rust
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SecretKey;
use vsss_rs::{Shamir, WrappedScalar};
use rand::rngs::OsRng;
use x25519_dalek::StaticSecret;

fn main() {
    let mut osrng = rand::rngs::OsRng::default();
    let sc = Scalar::random(&mut osrng);
    let sk1 = StaticSecret::from(sc.to_bytes());
    let ske1 = SecretKey::from_bytes(&sc.to_bytes()).unwrap();
    let res = Shamir::<2, 3>::split_secret::<WrappedScalar, OsRng, 33>(sc.into(), &mut osrng);
    assert!(res.is_ok());
    let shares = res.unwrap();
    let res = Shamir::<2, 3>::combine_shares::<WrappedScalar, 33>(&shares);
    assert!(res.is_ok());
    let scalar = res.unwrap();
    assert_eq!(scalar.0, sc);
    let sk2 = StaticSecret::from(scalar.0.to_bytes());
    let ske2 = SecretKey::from_bytes(&scalar.0.to_bytes()).unwrap();
    assert_eq!(sk2.to_bytes(), sk1.to_bytes());
    assert_eq!(ske1.to_bytes(), ske2.to_bytes());
}
```

Either `RistrettoPoint` or `EdwardsPoint` may be used when using Feldman and Pedersen VSSS.

## Testing

Due to no_std mode, this requires a larger stack than the current default.

`RUST_MIN_STACK=4964353 cargo test`

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