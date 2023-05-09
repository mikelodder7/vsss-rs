/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use crate::*;
use core::hash::Hash;
use elliptic_curve::{
    ff::PrimeField,
    generic_array::{
        typenum::{U33, U49, U97},
        GenericArray,
    },
    group::GroupEncoding,
};
use zeroize::Zeroize;

/// A value used to represent the identifier for secret shares
pub trait ShareIdentifier: Sized + Eq + Hash + Ord {
    /// Convert an identifier from a field element
    fn from_field_element<F: PrimeField>(element: F) -> VsssResult<Self>;
    /// Convert this share into a field element
    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F>;
    /// True if all value bytes are zero
    fn is_zero(&self) -> Choice;
}

impl ShareIdentifier for u8 {
    fn from_field_element<F: PrimeField>(element: F) -> VsssResult<Self> {
        let repr = element.to_repr();
        // Assume little endian encoding first
        // then try big endian
        let bytes = repr.as_ref();
        if ct_is_zero(&bytes[1..]).into() {
            Ok(bytes[0])
        } else if ct_is_zero(&bytes[..bytes.len() - 2]).into() {
            Ok(*bytes.last().unwrap())
        } else {
            Err(Error::InvalidShareConversion)
        }
    }

    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
        Ok(F::from(*self as u64))
    }

    fn is_zero(&self) -> Choice {
        ct_is_zero(&[*self])
    }
}

/// The methods necessary for a secret share
pub trait Share: Sized + Default + Clone + Eq + Hash + Ord + Zeroize {
    /// The identifier type
    type Identifier: ShareIdentifier;

    /// True if all value bytes are zero
    fn is_zero(&self) -> Choice {
        ct_is_zero(self.value())
    }

    /// The identifier for this share
    fn identifier(&self) -> Self::Identifier;

    /// The mutable identifier for this share
    fn identifier_mut(&mut self) -> &mut Self::Identifier;

    /// The raw byte value of the share excluding the identifier
    fn value(&self) -> &[u8];

    /// The writeable raw byte value of the share excluding the identifier
    fn value_mut(&mut self) -> &mut [u8];

    /// Convert this share into a group element
    fn as_group_element<G: GroupEncoding>(&self) -> VsssResult<G> {
        let mut repr = G::Repr::default();
        repr.as_mut().copy_from_slice(self.value());
        Option::<G>::from(G::from_bytes(&repr)).ok_or(Error::InvalidShareConversion)
    }

    /// Convert group element into a share
    fn from_group_element<G: GroupEncoding>(
        identifier: Self::Identifier,
        group: G,
    ) -> VsssResult<Self> {
        let repr = group.to_bytes();
        let mut me = Self::default();
        *(me.identifier_mut()) = identifier;
        if me.value().len() != repr.as_ref().len() {
            return Err(Error::InvalidShareConversion);
        }
        me.value_mut().copy_from_slice(repr.as_ref());
        Ok(me)
    }

    /// Convert this share into a prime field element
    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
        let mut repr = F::Repr::default();
        repr.as_mut().copy_from_slice(self.value());
        Option::<F>::from(F::from_repr(repr)).ok_or(Error::InvalidShareConversion)
    }

    /// Convert field element into a share
    fn from_field_element<F: PrimeField>(
        identifier: Self::Identifier,
        field: F,
    ) -> VsssResult<Self> {
        let repr = field.to_repr();
        let mut me = Self::default();
        *(me.identifier_mut()) = identifier;
        if me.value().len() != repr.as_ref().len() {
            return Err(Error::InvalidShareConversion);
        }
        me.value_mut().copy_from_slice(repr.as_ref());
        Ok(me)
    }
}

macro_rules! impl_share {
    ($($size:ident),+$(,)*) => {
        $(
        impl Share for GenericArray<u8, $size> {
            type Identifier = u8;

            fn identifier(&self) -> Self::Identifier {
                self[0]
            }

            fn identifier_mut(&mut self) -> &mut Self::Identifier {
                &mut self[0]
            }

            fn value(&self) -> &[u8] {
                &self[1..]
            }

            fn value_mut(&mut self) -> &mut [u8] {
                self[1..].as_mut()
            }
        }
        )+
    };
}

impl_share!(U33, U49, U97);