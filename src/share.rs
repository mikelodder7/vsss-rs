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
    /// Return a byte sequence representing the identifier
    fn as_bytes(&self) -> &[u8];
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

    fn as_bytes(&self) -> &[u8] {
        const BYTES: [u8; 256] = [
            0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67,
            68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89,
            90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142,
            143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
            160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176,
            177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193,
            194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210,
            211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227,
            228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244,
            245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255,
        ];
        let index = *self as usize;
        &BYTES[index..index + 1]
    }
}

/// The methods necessary for a secret share
pub trait Share: Sized + Clone + Eq + Hash + Ord + Zeroize {
    /// The identifier type
    type Identifier: ShareIdentifier;

    /// Create a new share with space equal to or greater than the size hint
    fn empty_share_with_capacity(size_hint: usize) -> Self;

    /// Create a new share with the given identifier and value
    fn with_identifier_and_value(identifier: Self::Identifier, value: &[u8]) -> Self {
        let mut me = Self::empty_share_with_capacity(value.len());
        *(me.identifier_mut()) = identifier;
        me.value_mut().copy_from_slice(value);
        me
    }

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
        let mut me = Self::empty_share_with_capacity(repr.as_ref().len());
        *(me.identifier_mut()) = identifier;
        if me.value().len() < repr.as_ref().len() {
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
        let mut me = Self::empty_share_with_capacity(repr.as_ref().len());
        if me.value().len() < repr.as_ref().len() {
            return Err(Error::InvalidShareConversion);
        }
        *(me.identifier_mut()) = identifier;
        me.value_mut().copy_from_slice(repr.as_ref());
        Ok(me)
    }
}

macro_rules! impl_share {
    ($($num:expr => $size:ident),+$(,)*) => {
        $(
        impl Share for GenericArray<u8, $size> {
            type Identifier = u8;

            fn empty_share_with_capacity(_size_hint: usize) -> Self {
                Self::default()
            }

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

        impl Share for [u8; $num] {
            type Identifier = u8;

            fn empty_share_with_capacity(_size_hint: usize) -> Self {
                [0u8; $num]
            }

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

impl_share!(33 => U33, 49 => U49, 97 => U97);

#[cfg(any(feature = "alloc", feature = "std"))]
impl Share for Vec<u8> {
    type Identifier = u8;

    fn empty_share_with_capacity(size_hint: usize) -> Self {
        vec![0u8; size_hint + 1]
    }

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

#[test]
fn test_with_identifier_and_value() {
    let share = GenericArray::<u8, U33>::with_identifier_and_value(1, &[1u8; 32]);
    assert_eq!(share.identifier(), 1);
    assert_eq!(share.identifier().as_bytes(), [1u8]);
    assert_eq!(share.value(), &[1u8; 32]);

    let share = GenericArray::<u8, U49>::with_identifier_and_value(2, &[1u8; 48]);
    assert_eq!(share.identifier(), 2);
    assert_eq!(share.identifier().as_bytes(), [2u8]);
    assert_eq!(share.value(), &[1u8; 48]);
}
