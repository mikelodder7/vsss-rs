/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use crate::lib::*;
use core::{array::TryFromSliceError, convert::TryFrom};
use elliptic_curve::{
    ff::PrimeField,
    group::GroupEncoding,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
use crate::Error;

/// A Shamir simple secret share
/// provides no integrity checking
/// The first byte is the X-coordinate or identifier
/// The remaining bytes are the Y-coordinate
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Zeroize)]
pub struct Share(pub Vec<u8>);

impl Default for Share {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl AsRef<[u8]> for Share {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Share {
    type Error = TryFromSliceError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(bytes.to_vec()))
    }
}

impl From<Share> for Vec<u8> {
    fn from(share: Share) -> Self {
        share.0
    }
}

impl Share {
    /// True if all value bytes are zero in constant time
    pub fn is_zero(&self) -> bool {
        let mut v = 0u8;
        for b in &self.0[1..] {
            v |= b;
        }
        v == 0
    }

    /// The identifier for this share
    pub fn identifier(&self) -> u8 {
        self.0[0]
    }

    /// The raw byte value of the share
    pub fn value(&self) -> &[u8] {
        &self.0[1..]
    }

    /// Convert this share into a group element
    pub fn as_group_element<G: GroupEncoding>(&self) -> Result<G, Error> {
        let mut repr = G::Repr::default();
        repr.as_mut().copy_from_slice(self.value());
        let res = G::from_bytes(&repr);
        if res.is_some().unwrap_u8() == 1u8 {
            Ok(res.unwrap())
        } else {
            Err(Error::InvalidShareConversion)
        }
    }

    /// Convert this share into a prime field element
    pub fn as_field_element<F: PrimeField>(&self) -> Result<F, Error> {
        let mut repr = F::Repr::default();
        repr.as_mut().copy_from_slice(self.value());
        let res = F::from_repr(repr);
        if res.is_some().unwrap_u8() == 1u8 {
            Ok(res.unwrap())
        } else {
            Err(Error::InvalidShareConversion)
        }
    }
}
