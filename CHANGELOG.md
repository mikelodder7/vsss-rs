# Changelog

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
