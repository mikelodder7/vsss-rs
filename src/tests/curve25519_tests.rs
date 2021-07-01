/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use super::invalid::*;
use super::valid::*;
use crate::{WrappedPoint, WrappedScalar};

#[test]
fn invalid_tests() {
    split_invalid_args::<WrappedScalar, WrappedPoint, 33>();
    combine_invalid::<WrappedScalar, 33>();
}

#[test]
fn valid_tests() {
    combine_single::<WrappedScalar, WrappedPoint, 33>();
    combine_all::<WrappedScalar, WrappedPoint, 33>();
}
