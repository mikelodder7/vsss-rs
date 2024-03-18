/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use crate::*;
use crypto_bigint::{
    Encoding, U1024, U128, U16384, U192, U2048, U256, U3072, U32768, U384, U4096, U448, U512, U576,
    U64, U768, U8192, U896,
};
use elliptic_curve::{
    ff::PrimeField,
    generic_array::{ArrayLength, GenericArray},
    group::GroupEncoding,
};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
/// A value used to represent the prime field.
/// When used with ShareIdentifier, ideally the field elements should be the same
/// as the prime field used in the secret sharing scheme.
pub struct PrimeFieldImpl<F: PrimeField>(pub F);

impl<F: PrimeField> core::hash::Hash for PrimeFieldImpl<F> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.to_repr().as_ref().hash(state);
    }
}

impl<F: PrimeField> PartialOrd for PrimeFieldImpl<F> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<F: PrimeField> Ord for PrimeFieldImpl<F> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.to_repr().as_ref().cmp(other.0.to_repr().as_ref())
    }
}

impl<F: PrimeField> Zeroize for PrimeFieldImpl<F> {
    fn zeroize(&mut self) {
        self.0 = F::ZERO;
    }
}

/// The methods necessary for a secret share
pub trait Share: Sized + Clone + Eq + core::hash::Hash + Ord + Zeroize {
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
        self.value().ct_is_zero()
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

impl<const L: usize> Share for [u8; L] {
    type Identifier = u8;

    fn empty_share_with_capacity(_size_hint: usize) -> Self {
        [0u8; L]
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
        &mut self[1..]
    }
}

impl<L: ArrayLength<u8>> Share for GenericArray<u8, L> {
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

macro_rules! impl_array_share {
    ($($type:ident),+$(,)*) => {
        $(
            impl<const L: usize> Share for ($type, [u8; L]) {
                type Identifier = $type;

                fn empty_share_with_capacity(_size_hint: usize) -> Self {
                                                              (0, [0u8; L])
                                              }

                fn identifier(&self) -> Self::Identifier {
                                                           self.0
                                                           }

                fn identifier_mut(&mut self) -> &mut Self::Identifier {
                                                                    &mut self.0
                                                                    }

                fn value(&self) -> &[u8] {
                                            &self.1
                                            }

                fn value_mut(&mut self) -> &mut [u8] {
                                                    self.1.as_mut()
                                                    }
            }

            impl<L: ArrayLength<u8>> Share for ($type, GenericArray<u8, L>) {
                type Identifier = $type;

                fn empty_share_with_capacity(_size_hint: usize) -> Self {
                                                              (0, GenericArray::<u8, L>::default())
                                              }

                fn identifier(&self) -> Self::Identifier {
                                                           self.0
                                                           }

                fn identifier_mut(&mut self) -> &mut Self::Identifier {
                                                                    &mut self.0
                                                                    }

                fn value(&self) -> &[u8] {
                                            &self.1
                                            }

                fn value_mut(&mut self) -> &mut [u8] {
                                                    self.1.as_mut()
                                                    }
            }
        )+
    };
}

impl_array_share!(u8, u16, u32, u64, usize,);

#[cfg(target_pointer_width = "64")]
impl_array_share!(u128,);

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

#[cfg(any(feature = "alloc", feature = "std"))]
impl Share for (Vec<u8>, Vec<u8>) {
    type Identifier = Vec<u8>;

    fn empty_share_with_capacity(size_hint: usize) -> Self {
        (Vec::with_capacity(size_hint), vec![0u8; size_hint])
    }

    fn identifier(&self) -> Self::Identifier {
        self.0.clone()
    }

    fn identifier_mut(&mut self) -> &mut Self::Identifier {
        &mut self.0
    }

    fn value(&self) -> &[u8] {
        &self.1
    }

    fn value_mut(&mut self) -> &mut [u8] {
        self.1.as_mut()
    }
}

macro_rules! impl_int_vec_share {
    ($($type:ident),+$(,)*) => {
        $(
            impl Share for ($type, Vec<u8>) {
                type Identifier = $type;

                fn empty_share_with_capacity(size_hint: usize) -> Self {
                    (0, vec![0u8; size_hint])
                }

                fn identifier(&self) -> Self::Identifier {
                    self.0
                }

                fn identifier_mut(&mut self) -> &mut Self::Identifier {
                    &mut self.0
                }

                fn value(&self) -> &[u8] {
                    &self.1
                }

                fn value_mut(&mut self) -> &mut [u8] {
                    self.1.as_mut()
                }
            }
        )+
    };
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl_int_vec_share!(u8, u16, u32, u64, u128, usize);

macro_rules! impl_big_int_share {
    ($(TYPE = $type:ident, BI = $bigint:ident),+$(,)*) => {
        $(
            impl Share for ($type, $BI) {
                type Identifier = $type;

                fn empty_share_with_capacity(_size_hint: usize) -> Self {
                    (0, $bigint::default())
                }

                fn identifier(&self) -> Self::Identifier {
                    self.0
                }

                fn identifier_mut(&mut self) -> &mut Self::Identifier {
                    &mut self.0
                }

                fn value(&self) -> &[u8] {
                    self.1.to_be_slice()
                }

                fn value_mut(&mut self) -> &mut [u8] {
                    self.1.as_mut()
                }
            }
        )+
    };
}

#[test]
fn test_with_identifier_and_value() {
    use elliptic_curve::generic_array::typenum;

    let share = GenericArray::<u8, typenum::U33>::with_identifier_and_value(1, &[1u8; 32]);
    assert_eq!(share.identifier(), 1);
    assert_eq!(share.identifier().to_repr(), [1u8]);
    assert_eq!(share.value(), &[1u8; 32]);

    let share = GenericArray::<u8, typenum::U49>::with_identifier_and_value(2, &[1u8; 48]);
    assert_eq!(share.identifier(), 2);
    assert_eq!(share.identifier().to_repr(), [2u8]);
    assert_eq!(share.value(), &[1u8; 48]);
}

#[test]
fn test_small_vec_shares() {
    let share = (2000u16, [1u8; 32]);
    assert_eq!(share.identifier(), 2000u16);
    assert_eq!(share.identifier().to_repr(), 2000u16.to_be_bytes());
    assert_eq!(share.value(), &[1u8; 32]);

    let share = (10000u16, [1u8; 48]);
    assert_eq!(share.identifier(), 10000u16);
    assert_eq!(share.identifier().to_repr(), 10000u16.to_be_bytes());
    assert_eq!(share.value(), &[1u8; 48]);

    let share = (435123523u32, [1u8; 56]);
    assert_eq!(share.identifier(), 435123523u32);
    assert_eq!(share.identifier().to_repr(), 435123523u32.to_be_bytes());
    assert_eq!(share.value(), &[1u8; 56]);
}
