# Changelog

## 7.0.0 - 2026-11-23

- Added the `pi-la` feature: Π_LA hash-based verifiable secret sharing (Baghery, PKC 2025). It is post-quantum, needs no group, and works with any `digest::Digest` (SHA-2, SHA-3, BLAKE2, BLAKE3 via `traits-preview`). The only new dependency is `digest`.
- Added the `lattice-pvss` feature, **experimental and unaudited**: the post-quantum publicly verifiable secret sharing scheme of Kate, Mukherjee, Saleem, Sarkar, and Sinha (ePrint 2026/813, Sec. 5), built on an NTRU-lattice identity-based encryption (key generation, Klein/GPV extraction in Falcon's fast-Fourier form, encryption, decryption) with about 110 bits of classical security. It is not constant-time and adds no dependencies.
- `Error` now derives `thiserror::Error`, so it implements `core::error::Error`. Display messages are unchanged.
- Split polynomials are now wiped on drop under the `zeroize` feature in every split path: Shamir, Feldman, Pedersen, GF(256), and GF(16) ([#26](https://github.com/mikelodder7/vsss-rs/issues/26), [#27](https://github.com/mikelodder7/vsss-rs/pull/27)).
- **Breaking:** under the `zeroize` feature, `Share` and `ShareElement` now require `zeroize::Zeroize` (via the new `ShareZeroize` marker trait). Custom share or element types must implement `Zeroize`.
- **Breaking:** `IdentifierPrimeField<F>` and `ValueGroup<G>` now implement `Zeroize` for any `F`/`G` instead of `DefaultIsZeroes` only when the inner type does.
- `IdentifierBigUint` and `IdentifierBoxedUint` now implement `Zeroize`. The `BigUint` wipe is best-effort because `num-bigint` has no zeroize support.

## 6.0.0 - 2026-07-30

- Added iterator-based APIs alongside the existing slice-based methods for Shamir, Feldman, Pedersen, and share-set workflows.
- Added an optional `stream` feature for asynchronous participant-identifier splitting and exact-count share combination.
- Added shorter API aliases for common split, combine, polynomial, verifier, and share-set operations while keeping the older method names available.
- Added in-place helpers for polynomial evaluation and share combining to support lower-allocation `no_std` use cases.
- Added `BoxedUint` share element support when `bigint` and `alloc`/`std` are enabled.
- Split curve-backed APIs behind the `curve` and `curve-serde` features so GF(16)/GF(256)-only users can build with a much smaller normal dependency tree.
- Split random participant identifier generation behind `random-participant-ids`.
- Replaced the `num` meta-crate dependency with narrower `num-bigint` and `num-traits` dependencies.
- Updated CI coverage, documentation, and release checks for minimal feature combinations.
