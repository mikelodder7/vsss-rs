# Changelog

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v2.7.0 - 2023-02-27

- Allow splitting of secrets equal to zero as this is useful in threshold MPC refresh protocols

## v2.6.0 - 2023-02-24

- Better and consistent serialization for Shares and consistent with std and no_std.

## v2.5.0 - 2023-02-23

- Additional serialization and test fixes

## v2.4.0 - 2023-02-20

- Fixed some serialization and tests
- Update dependencies

## v2.3.2 - 2023-01-04
- Add serdes to all structs

## v2.3.0 - 2022-12-16
- Relax requirement for implementing zeroize


## v2.2.0 - 2022-12-15
- Update dependencies
- Error implements Display and Error traits
- Share can be converted to PrimeField and GroupEncoding


## v2.1.0 - 2022-11-23
- Fix dependencies

## v2.0.0 - 2022-08-08

- Add both standard and non-standard modes
- Update dependencies
- Add wrapper for curve25519-dalek

## v1.4.0 - 2021-10-21

- Namespace Wrappers
- Add Wrapper for k256
- Add serialization to Wrappers
- Make subtle optional

## v1.3.0 - 2021-10-14

- Add WrappedEdwards and Update WrappedPoint to WrappedRistretto

## v.1.2.0 - 2021-10-7

- Add serialization to Verifiers
- Updated LICENSE to include MIT

## v1.1.0 - 2021-08-25

- Update dependency versions
- Use `serde` without default-features for better no-std compatibility

## v1.0.0 - 2021-07-01

- Initial release.
