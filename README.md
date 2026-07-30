# Verifiable Secret Sharing Schemes

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Coverage][coverage-image]][coverage-link]
![Apache 2.0][license-image]

`vsss-rs` implements Shamir secret sharing and the Feldman and Pedersen
verifiable secret sharing schemes. It supports `no_std`, fixed-size storage,
allocator-backed storage, prime fields, groups, and byte-oriented GF(16) and
GF(256) sharing.

The library is production-ready and in production use. Thank you to
LIT Protocol and Turnkey for funding security audits of this library.

## Schemes

| Scheme | Verification | Split result |
| --- | --- | --- |
| Shamir | None | Secret shares |
| Feldman | Public commitments | Secret shares and Feldman verifiers |
| Pedersen | Hiding commitments | Secret shares, blinder shares, blinder, and verifier sets |

Combining shares is identical across the three schemes and is provided by
`ReadableShareSet::combine`.

## Quick start

Add the crate and an RNG:

```toml
[dependencies]
rand = "0.10"
vsss-rs = "6"
```

Split and combine a byte string with GF(256):

```rust
use rand::{SeedableRng, rngs::StdRng};
use vsss_rs::Gf256;

fn main() -> Result<(), vsss_rs::Error> {
    let mut rng = StdRng::from_seed([7u8; 32]);
    let shares = Gf256::split_bytes(2, 3, b"secret", &mut rng)?;
    let recovered = Gf256::combine_bytes(&shares[..2])?;

    assert_eq!(recovered, b"secret");
    Ok(())
}
```

Split and combine a prime-field element with Shamir:

```rust
use elliptic_curve::{Generate, ff::PrimeField};
use p256::{NonZeroScalar, Scalar, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use vsss_rs::{IdentifierPrimeField, PrimeFieldShare, ReadableShareSet, shamir};

fn main() -> Result<(), vsss_rs::Error> {
    let mut rng = StdRng::from_seed([1u8; 32]);
    let key = SecretKey::generate_from_rng(&mut rng);
    let secret = IdentifierPrimeField(*key.to_nonzero_scalar().as_ref());
    let shares =
        shamir::split_secret::<PrimeFieldShare<Scalar>>(2, 3, &secret, &mut rng)?;
    let recovered = shares.combine()?;
    let recovered = NonZeroScalar::from_repr(recovered.0.to_repr()).unwrap();

    assert_eq!(SecretKey::from(recovered).to_bytes(), key.to_bytes());
    Ok(())
}
```

The curve example additionally needs:

```toml
[dependencies]
elliptic-curve = "0.14"
p256 = { version = "0.14", features = ["arithmetic"] }
```

See the [crate documentation][docs-link] for Feldman, Pedersen, K256,
BLS12-381, Curve25519, Ed25519, Ed448, and X25519 examples.

## Shares and identifiers

The `Share` trait separates a share into an identifier and a value. The crate
provides:

- `(Identifier, Value)` for tuple-based shares.
- `DefaultShare<Identifier, Value>` for shares with named fields.
- `PrimeFieldShare<F>` for field-valued shares.
- `GroupShare<G>` for group-valued shares.
- `Gf16::split_bytes` and `Gf256::split_bytes` for byte strings.

Identifiers implement `ShareIdentifier`; values implement `ShareElement`.
Custom field or group representations can be integrated by implementing these
traits.

Participant identifiers default to sequential nonzero values beginning at one.
`ParticipantIdGenerator` supports:

- `Sequential { start, increment, count }`
- `List { list }`
- `Random { seed, count }` with the `random-participant-ids` feature

Use `split_secret_with_participant_generators` for generators,
`split_secret_with_participant_ids_iter` for an iterator of identifiers, or
`split_secret_with_participant_ids_stream` for an asynchronous stream.

## Combining shares

Collections implementing `ReadableShareSet` provide `combine` and
`combine_in_place`. Allocator-backed callers can also use:

- `combine_iter`
- `combine_iter_in_place`
- `combine_stream`
- `combine_stream_in_place`

Stream combination consumes exactly the requested number of shares and returns
`Error::NotEnoughShares` if the stream ends early. The selected shares are
retained until interpolation completes because every Lagrange coefficient
depends on the complete identifier set.

GF(16) and GF(256) provide equivalent `combine_bytes_iter` and
`combine_bytes_stream` methods.

## `no_std` and storage

The crate is `#![no_std]`. Without an allocator, fixed arrays,
`generic_array::GenericArray`, and `hybrid_array::Array` can hold polynomials,
shares, and verifier sets. The `vsss_fixed_array_impl!` macro can define a
complete fixed-size Shamir/Feldman/Pedersen implementation.

Enable `alloc` for `Vec`-backed APIs in a `no_std` environment. The `std`
feature implies `alloc`.

For a minimal GF(16)/GF(256 build:

```toml
[dependencies]
vsss-rs = { version = "6", default-features = false, features = ["alloc"] }
```

## Features

| Feature | Default | Adds |
| --- | --- | --- |
| `alloc` | Through `std` | `Vec`/`Box` APIs for allocator-enabled environments |
| `std` | Yes | Standard-library support in dependencies |
| `bigint` | Yes | `crypto-bigint`, `num-bigint`, and bigint share elements |
| `primitive` | Yes | Primitive integer share elements |
| `curve` | Through `curve-serde` | Prime-field and group-backed share elements |
| `curve-serde` | Yes | `curve`, Serde, and curve serialization helpers |
| `random-participant-ids` | Yes | SHAKE-based random participant identifiers |
| `serde` | Through `curve-serde` | Serialization for supported types |
| `stream` | No | Async identifier splitting and exact-count share combination; implies `alloc` |
| `zeroize` | Yes | Zeroization for supported share elements |
| `legacy-curve-tests` | No | Compatibility-only tests for older curve combinations |

## Big integer share elements

With `bigint`, the crate supports:

- `IdentifierUint<LIMBS>` and `ValueUint<LIMBS>`
- `IdentifierBoxedUint<BITS>` and `ValueBoxedUint<BITS>` with `alloc`
- `IdentifierResidue<MOD, LIMBS>` and `ValueResidue<MOD, LIMBS>`
- `IdentifierConstMontyResidue<MOD, LIMBS>` and
  `ValueConstMontyResidue<MOD, LIMBS>`
- Runtime-modulus `IdentifierMontyResidue<LIMBS>` and
  `ValueMontyResidue<LIMBS>` helpers

Runtime-modulus Montgomery values do not implement `ShareElement`, because
their zero and one values require runtime parameters.

## Security

Share counts and identifiers are public inputs. Field and group operations used
for secret material are designed to avoid secret-dependent control flow and
table lookups. Applications remain responsible for authenticating transported
shares and, when using Feldman or Pedersen, verifying shares before combining
them.

Please follow the private reporting process in [SECURITY.md](SECURITY.md)
rather than opening a public issue.

## License

Licensed under either:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.

Unless explicitly stated otherwise, contributions intentionally submitted for
inclusion are licensed under the same terms without additional conditions.

## References

1. [How to Share a Secret — Adi Shamir, 1979](https://dl.acm.org/doi/10.1145/359168.359176)
2. [A Practical Scheme for Non-interactive Verifiable Secret Sharing — Paul Feldman, 1987](https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf)
3. [Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing — Torben Pedersen, 1991](https://link.springer.com/chapter/10.1007/3-540-46766-1_9)

[crate-image]: https://img.shields.io/crates/v/vsss-rs.svg
[crate-link]: https://crates.io/crates/vsss-rs
[docs-image]: https://docs.rs/vsss-rs/badge.svg
[docs-link]: https://docs.rs/vsss-rs/
[coverage-image]: https://codecov.io/gh/mikelodder7/vsss-rs/branch/main/graph/badge.svg
[coverage-link]: https://codecov.io/gh/mikelodder7/vsss-rs
[license-image]: https://img.shields.io/badge/license-Apache2.0-blue.svg
