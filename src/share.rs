/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use crate::util::{uint_to_be_byte_array, CtIsZero};
use crate::*;
use crypto_bigint::{Uint, Zero};
use elliptic_curve::{group::GroupEncoding, PrimeField};
use generic_array::{ArrayLength, GenericArray};
use std::cmp;

/// The methods necessary for a secret share
pub trait Share: Sized + Clone + Eq + core::hash::Hash + Ord {
    /// The identifier type
    type Identifier: ShareIdentifier;

    /// Create a new share with space equal to or greater than the size hint
    fn empty_share_with_capacity(size_hint: usize) -> Self;

    /// Create a new share with the given identifier and value
    fn with_identifier_and_value(identifier: Self::Identifier, value: &[u8]) -> Self {
        let mut me = Self::empty_share_with_capacity(value.len());
        *(me.identifier_mut()) = identifier;
        me.value_mut(value)
            .expect("the value length should be equal to or less than the share capacity");
        me
    }

    /// True if all value bytes are zero
    fn is_zero(&self) -> Choice;

    /// The identifier for this share
    fn identifier(&self) -> Self::Identifier;

    /// The mutable identifier for this share
    fn identifier_mut(&mut self) -> &mut Self::Identifier;

    /// The raw byte value of the share excluding the identifier is written to the buffer
    fn value(&self, buffer: &mut [u8]) -> VsssResult<()>;

    /// The writeable raw byte value of the share excluding the identifier
    fn value_mut(&mut self, buffer: &[u8]) -> VsssResult<()>;

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// The byte representation value of the share excluding the identifier
    fn value_vec(&self) -> Vec<u8>;

    /// Convert this share into a group element
    fn as_group_element<G: GroupEncoding>(&self) -> VsssResult<G> {
        let mut repr = G::Repr::default();
        self.value(repr.as_mut())?;
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
        me.value_mut(repr.as_ref())?;
        Ok(me)
    }

    /// Convert this share into a prime field element
    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
        let mut repr = F::Repr::default();
        self.value(repr.as_mut())?;
        Option::<F>::from(F::from_repr(repr)).ok_or(Error::InvalidShareConversion)
    }

    /// Convert field element into a share
    fn from_field_element<F: PrimeField>(
        identifier: Self::Identifier,
        field: F,
    ) -> VsssResult<Self> {
        let repr = field.to_repr();
        let mut me = Self::empty_share_with_capacity(repr.as_ref().len());
        *(me.identifier_mut()) = identifier;
        me.value_mut(repr.as_ref())?;
        Ok(me)
    }
}

impl<const L: usize> Share for [u8; L] {
    type Identifier = u8;

    fn empty_share_with_capacity(_size_hint: usize) -> Self {
        [0u8; L]
    }

    fn is_zero(&self) -> Choice {
        self.ct_is_zero()
    }

    fn identifier(&self) -> Self::Identifier {
        self[0]
    }

    fn identifier_mut(&mut self) -> &mut Self::Identifier {
        &mut self[0]
    }

    fn value(&self, buffer: &mut [u8]) -> VsssResult<()> {
        if buffer.len() < L - 1 {
            return Err(Error::InvalidShareConversion);
        }
        buffer[..L - 1].copy_from_slice(&self[1..]);
        Ok(())
    }

    fn value_mut(&mut self, buffer: &[u8]) -> VsssResult<()> {
        if buffer.len() < L - 1 {
            return Err(Error::InvalidShareConversion);
        }
        self[1..].copy_from_slice(&buffer[..L - 1]);
        Ok(())
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn value_vec(&self) -> Vec<u8> {
        self[1..].to_vec()
    }
}

impl<L: ArrayLength> Share for GenericArray<u8, L> {
    type Identifier = u8;

    fn empty_share_with_capacity(_size_hint: usize) -> Self {
        Self::default()
    }

    fn is_zero(&self) -> Choice {
        self.ct_is_zero()
    }

    fn identifier(&self) -> Self::Identifier {
        self[0]
    }

    fn identifier_mut(&mut self) -> &mut Self::Identifier {
        &mut self[0]
    }

    fn value(&self, buffer: &mut [u8]) -> VsssResult<()> {
        if buffer.len() < L::to_usize() - 1 {
            return Err(Error::InvalidShareConversion);
        }
        let len = L::to_usize() - 1;
        buffer[..len].copy_from_slice(&self[1..]);
        Ok(())
    }

    fn value_mut(&mut self, buffer: &[u8]) -> VsssResult<()> {
        if buffer.len() < L::to_usize() - 1 {
            return Err(Error::InvalidShareConversion);
        }
        let len = L::to_usize() - 1;
        self[1..].copy_from_slice(&buffer[..len]);
        Ok(())
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn value_vec(&self) -> Vec<u8> {
        self[1..].to_vec()
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

                fn is_zero(&self) -> Choice {
                    self.1.ct_is_zero()
                }

                fn identifier(&self) -> Self::Identifier {
                                                           self.0
                                                           }

                fn identifier_mut(&mut self) -> &mut Self::Identifier {
                                                                    &mut self.0
                                                                    }

                fn value(&self, buffer: &mut [u8]) -> VsssResult<()> {
                    if buffer.len() < L {
                        return Err(Error::InvalidShareConversion);
                    }
                    buffer[..L].copy_from_slice(&self.1);
                    Ok(())
                }

                fn value_mut(&mut self, buffer: &[u8]) -> VsssResult<()> {
                    if buffer.len() < L {
                        return Err(Error::InvalidShareConversion);
                    }
                    self.1.copy_from_slice(&buffer[..L]);
                    Ok(())
                }

                #[cfg(any(feature = "alloc", feature = "std"))]
                fn value_vec(&self) -> Vec<u8> {
                    self.1.to_vec()
                }
            }

            impl<L: ArrayLength> Share for ($type, GenericArray<u8, L>) {
                type Identifier = $type;

                fn empty_share_with_capacity(_size_hint: usize) -> Self {
                    (0, GenericArray::<u8, L>::default())
                }

                fn is_zero(&self) -> Choice {
                    self.1.ct_is_zero()
                }

                fn identifier(&self) -> Self::Identifier {
                    self.0
                }

                fn identifier_mut(&mut self) -> &mut Self::Identifier {
                                                                    &mut self.0
                                                                    }

                fn value(&self, buffer: &mut [u8]) -> VsssResult<()> {
                    if buffer.len() < L::to_usize() {
                        return Err(Error::InvalidShareConversion);
                    }
                    buffer[..L::to_usize()].copy_from_slice(&self.1);
                    Ok(())
                }

                fn value_mut(&mut self, buffer: &[u8]) -> VsssResult<()> {
                    if buffer.len() < L::to_usize() {
                        return Err(Error::InvalidShareConversion);
                    }
                    self.1.copy_from_slice(&buffer[..L::to_usize()]);
                    Ok(())
                }

                #[cfg(any(feature = "alloc", feature = "std"))]
                fn value_vec(&self) -> Vec<u8> {
                    self.1.to_vec()
                }
            }

            impl<const LIMBS: usize> Share for ($type, Uint<LIMBS>) {
                type Identifier = $type;

                fn empty_share_with_capacity(_size_hint: usize) -> Self {
                    (0, Uint::<LIMBS>::ZERO)
                }

                fn is_zero(&self) -> Choice {
                    Zero::is_zero(&self.1)
                }

                fn identifier(&self) -> Self::Identifier {
                    self.0
                }

                fn identifier_mut(&mut self) -> &mut Self::Identifier {
                    &mut self.0
                }

                fn value(&self, buffer: &mut [u8]) -> VsssResult<()> {
                    if buffer.len() < Uint::<LIMBS>::BYTES {
                        return Err(Error::InvalidShareConversion);
                    }
                    uint_to_be_byte_array(&self.1, buffer)
                }

                fn value_mut(&mut self, buffer: &[u8]) -> VsssResult<()> {
                    if buffer.len() < Uint::<LIMBS>::BYTES {
                        return Err(Error::InvalidShareConversion);
                    }
                    self.1 = Uint::<LIMBS>::from_be_slice(buffer);
                    Ok(())
                }

                #[cfg(any(feature = "alloc", feature = "std"))]
                fn value_vec(&self) -> Vec<u8> {
                    let mut buffer = vec![0u8; Uint::<LIMBS>::BYTES];
                    uint_to_be_byte_array(&self.1, &mut buffer).expect("buffer is the correct size");
                    buffer
                }
            }

            #[cfg(any(feature = "alloc", feature = "std"))]
            impl Share for ($type, Vec<u8>) {
                type Identifier = $type;

                fn empty_share_with_capacity(size_hint: usize) -> Self {
                    (0, vec![0u8; size_hint])
                }

                fn is_zero(&self) -> Choice {
                    self.1.ct_is_zero()
                }

                fn identifier(&self) -> Self::Identifier {
                    self.0
                }

                fn identifier_mut(&mut self) -> &mut Self::Identifier {
                    &mut self.0
                }

                fn value(&self, buffer: &mut [u8]) -> VsssResult<()> {
                    if buffer.len() < self.1.len() {
                        return Err(Error::InvalidShareConversion);
                    }
                    buffer[..self.1.len()].copy_from_slice(&self.1);
                    Ok(())
                }

                fn value_mut(&mut self, buffer: &[u8]) -> VsssResult<()> {
                    self.1 = buffer.to_vec();
                    Ok(())
                }

                fn value_vec(&self) -> Vec<u8> {
                    self.1.clone()
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

    fn is_zero(&self) -> Choice {
        self.ct_is_zero()
    }

    fn identifier(&self) -> Self::Identifier {
        self[0]
    }

    fn identifier_mut(&mut self) -> &mut Self::Identifier {
        &mut self[0]
    }

    fn value(&self, buffer: &mut [u8]) -> VsssResult<()> {
        if buffer.len() < self.len() - 1 {
            return Err(Error::InvalidShareConversion);
        }
        buffer[..self.len() - 1].copy_from_slice(&self[1..]);
        Ok(())
    }

    fn value_mut(&mut self, buffer: &[u8]) -> VsssResult<()> {
        if buffer.len() < self.len() - 1 {
            return Err(Error::InvalidShareConversion);
        }
        let len = cmp::min(buffer.len(), self.len() - 1);
        self[1..].copy_from_slice(&buffer[..len]);
        Ok(())
    }

    fn value_vec(&self) -> Vec<u8> {
        self[1..].to_vec()
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl Share for (Vec<u8>, Vec<u8>) {
    type Identifier = Vec<u8>;

    fn empty_share_with_capacity(size_hint: usize) -> Self {
        (Vec::with_capacity(size_hint), vec![0u8; size_hint])
    }

    fn is_zero(&self) -> Choice {
        self.1.ct_is_zero()
    }

    fn identifier(&self) -> Self::Identifier {
        self.0.clone()
    }

    fn identifier_mut(&mut self) -> &mut Self::Identifier {
        &mut self.0
    }

    fn value(&self, buffer: &mut [u8]) -> VsssResult<()> {
        if buffer.len() < self.1.len() {
            return Err(Error::InvalidShareConversion);
        }
        buffer[..self.1.len()].copy_from_slice(&self.1);
        Ok(())
    }

    fn value_mut(&mut self, buffer: &[u8]) -> VsssResult<()> {
        self.1 = buffer.to_vec();
        Ok(())
    }

    fn value_vec(&self) -> Vec<u8> {
        self.1.clone()
    }
}

#[test]
fn test_with_identifier_and_value() {
    use generic_array::{typenum, GenericArray};

    let share = GenericArray::<u8, typenum::U33>::with_identifier_and_value(1, &[1u8; 32]);
    assert_eq!(share.identifier(), 1u8);
    let mut value = [0u8; 32];
    assert!(share.value(&mut value).is_ok());
    assert_eq!(value, [1u8; 32]);

    let share = GenericArray::<u8, typenum::U49>::with_identifier_and_value(2, &[1u8; 48]);
    assert_eq!(share.identifier(), 2u8);
    let mut value = [0u8; 48];
    assert!(share.value(&mut value).is_ok());
    assert_eq!(value, [1u8; 48]);
}

#[test]
fn test_small_vec_shares() {
    let share = (2000u16, [1u8; 32]);
    assert_eq!(share.identifier(), 2000u16);
    let mut value = [0u8; 32];
    assert!(share.value(&mut value).is_ok());
    assert_eq!(value, [1u8; 32]);

    let share = (10000u16, [1u8; 48]);
    assert_eq!(share.identifier(), 10000u16);
    let mut value = [0u8; 48];
    assert!(share.value(&mut value).is_ok());
    assert_eq!(value, [1u8; 48]);

    let share = (435123523u32, [1u8; 56]);
    assert_eq!(share.identifier(), 435123523u32);
    let mut value = [0u8; 56];
    assert!(share.value(&mut value).is_ok());
    assert_eq!(value, [1u8; 56]);
}
