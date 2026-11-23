# Changelog

## 7.0.0 - 2026-11-23

- Added the `pi-la` feature: Π_LA hash-based verifiable secret sharing (Baghery, PKC 2025). It is post-quantum, needs no group, and works with any `digest::Digest` (SHA-2, SHA-3, BLAKE2, BLAKE3 via `traits-preview`). The only new dependency is `digest`.
- Added the `hash-commitment` feature: public `HashCommitment` and `HashOpening`, a length-prefixed, domain-separated hash commitment over any `digest::Digest` with constant-time verification. Π_LA and the lattice PVSS build their commitments on it.
- Added the `lattice-pvss` feature, **experimental and unaudited**: the post-quantum publicly verifiable secret sharing scheme of Kate, Mukherjee, Saleem, Sarkar, and Sinha (ePrint 2026/813, Sec. 5), built on an NTRU-lattice identity-based encryption (key generation, Klein/GPV extraction in Falcon's fast-Fourier form, encryption, decryption) with ~110-bit classical security (below 128). It is not constant-time and adds no dependencies.
- **Breaking:** `Error` has a new `Lattice(&'static str)` variant for lattice PVSS failures. Exhaustive matches on `Error` need a new arm.
- **Breaking:** crate-owned constant-time APIs use `ctutils` (re-exported as `vsss_rs::ctutils`) instead of `subtle`: `ShareElement::is_zero`, `CtIsZero`, and `CtIsNotZero` return `ctutils::Choice`, `HashOpening` implements `ctutils::CtEq` instead of `subtle::ConstantTimeEq`, and `Saturating` implements `ctutils::CtEq`/`CtSelect` instead of `subtle::ConstantTimeEq`/`ConditionallySelectable`. `subtle` stays only at foreign-trait boundaries (`ff`, `group`) and is still re-exported. Lattice decryption now decides each key bit without branching on the secret.
- Lattice PVSS: the discrete Gaussian samplers are isochronous, following Howe–Prest–Ricosset–Rossi (the Falcon design). Key extraction's leaf sampler (`SamplerZ`, replacing `sample_z`) uses a fixed 128-bit reverse-CDT scan, a sign bit, and a fixed-point `exp` Bernoulli step whose timing is independent of the trapdoor and the center; key generation's `f, g` (`sample_poly`, now without a width argument) come from a fixed-table convolution sampler. Key generation rejects trapdoors whose sampling-tree widths leave `[σ_min, σ_max] = [2, 2.8]`. Lattice module docs now state the exact residual timing assumptions; lattice outputs for a given seed change.
- Share identifier validation checks for zero identifiers before duplicates, and finds duplicates in O(n log n) when an allocator is available. A set holding both a zero and a duplicated identifier now reports `SharingInvalidIdentifier`.
- `crypto-bigint` now requires 0.7.11 or later.
- Fixed `Gf256::pow`, which used integer instead of field multiplication, and `Gf16::pow` for exponents of 16 or more. `ff::Field::sqrt_ratio` (and so `sqrt`) for `Gf256` and `Gf16` now returns correct square roots: every element of GF(2^n) is a square, with root `x^(2^(n-1))`.
- `Gf256` and `Gf16` division no longer panics: dividing by zero yields zero. Use `Field::invert` to detect a zero divisor.
- `Error` now derives `thiserror::Error`, so it implements `core::error::Error`. Display messages are unchanged.
- Split polynomials are now wiped on drop under the `zeroize` feature in every split path: Shamir, Feldman, Pedersen, GF(256), and GF(16) ([#26](https://github.com/mikelodder7/vsss-rs/issues/26), [#27](https://github.com/mikelodder7/vsss-rs/pull/27)).
- **Breaking:** under the `zeroize` feature, `Share` and `ShareElement` now require `zeroize::Zeroize` (via the new `ShareZeroize` marker trait). Custom share or element types must implement `Zeroize`.
- `IdentifierPrimeField<F>` and `ValueGroup<G>` now implement `DefaultIsZeroes` (and so `Zeroize`) for any `F`/`G`, not only when the inner type does.
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
