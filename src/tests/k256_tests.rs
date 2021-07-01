/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::invalid::*;
use super::valid::*;
use k256::{ProjectivePoint, Scalar};

#[test]
fn invalid_tests() {
    split_invalid_args::<Scalar, ProjectivePoint, 33>();
    combine_invalid::<Scalar, 33>();
}

#[test]
fn valid_tests() {
    combine_single::<Scalar, ProjectivePoint, 33>();
    combine_all::<Scalar, ProjectivePoint, 33>();
}
