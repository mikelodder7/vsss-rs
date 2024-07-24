/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use crate::util::CtIsZero;
use crate::*;
use crypto_bigint::{
    modular::{
        constant_mod::{Residue, ResidueParams},
        runtime_mod::{DynResidue, DynResidueParams},
    },
    Uint, Zero,
};
use elliptic_curve::{group::GroupEncoding, PrimeField};
use generic_array::{ArrayLength, GenericArray};

/// The methods necessary for a secret share
pub trait Share: Sized + Clone + Eq + PartialEq {
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

impl<L: elliptic_curve::generic_array::ArrayLength<u8>> Share
    for elliptic_curve::generic_array::GenericArray<u8, L>
{
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
                    self.1 = GenericArray::from_buffer(buffer)?;
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
                    self.1.to_buffer(buffer)
                }

                fn value_mut(&mut self, buffer: &[u8]) -> VsssResult<()> {
                    self.1 = Uint::<LIMBS>::from_buffer(buffer)?;
                    Ok(())
                }

                #[cfg(any(feature = "alloc", feature = "std"))]
                fn value_vec(&self) -> Vec<u8> {
                    self.1.to_vec()
                }
            }

            impl<const LIMBS: usize> Share for ($type, DynResidue<LIMBS>) {
                type Identifier = $type;

                fn empty_share_with_capacity(_size_hint: usize) -> Self {
                    // TODO(mikelodder7): figure out a better way to do this
                    // stubbed in but assumes the caller will correct the modulus
                    // 18,446,744,073,709,551,557
                    let params = DynResidueParams::new(&Uint::<LIMBS>::from(0xffffffffffffffc5u64));
                    (0, DynResidue::<LIMBS>::zero(params))
                }

                fn is_zero(&self) -> Choice {
                    Zero::is_zero(&self.1.retrieve())
                }

                fn identifier(&self) -> Self::Identifier {
                    self.0
                }

                fn identifier_mut(&mut self) -> &mut Self::Identifier {
                    &mut self.0
                }

                fn value(&self, buffer: &mut [u8]) -> VsssResult<()> {
                    self.1.to_buffer(buffer)
                }

                fn value_mut(&mut self, buffer: &[u8]) -> VsssResult<()> {
                    self.1 = DynResidue::from_buffer(buffer)?;
                    Ok(())
                }

                #[cfg(any(feature = "alloc", feature = "std"))]
                fn value_vec(&self) -> Vec<u8> {
                    self.1.to_vec()
                }
            }

            impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> Share for ($type, Residue<MOD, LIMBS>) {
                type Identifier = $type;

                fn empty_share_with_capacity(_size_hint: usize) -> Self {
                    (0, Residue::ZERO)
                }

                fn is_zero(&self) -> Choice {
                    Zero::is_zero(&self.1.retrieve())
                }

                fn identifier(&self) -> Self::Identifier {
                    self.0
                }

                fn identifier_mut(&mut self) -> &mut Self::Identifier {
                    &mut self.0
                }

                fn value(&self, buffer: &mut [u8]) -> VsssResult<()> {
                    self.1.to_buffer(buffer)
                }

                fn value_mut(&mut self, buffer: &[u8]) -> VsssResult<()> {
                    self.1 = Residue::from_buffer(buffer)?;
                    Ok(())
                }

                #[cfg(any(feature = "alloc", feature = "std"))]
                fn value_vec(&self) -> Vec<u8> {
                    self.1.to_vec()
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
        let len = core::cmp::min(buffer.len(), self.len() - 1);
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

#[cfg(any(
    feature = "k256",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "ed448-goldilocks-plus",
    feature = "curve25519",
    feature = "bls12_381_plus",
    feature = "blstrs_plus"
))]
macro_rules! impl_field_share {
    ($scalar_name:ty, $($type:ident),+$(,)*) => {
        $(
            impl Share for ($type, $scalar_name) {
                type Identifier = $type;

                fn empty_share_with_capacity(_size_hint: usize) -> Self {
                    (0, <$scalar_name as elliptic_curve::Field>::ZERO)
                }

                fn is_zero(&self) -> Choice {
                    self.1.is_zero()
                }

                fn identifier(&self) -> Self::Identifier {
                    self.0
                }

                fn identifier_mut(&mut self) -> &mut Self::Identifier {
                    &mut self.0
                }

                fn value(&self, buffer: &mut [u8]) -> VsssResult<()> {
                    self.1.to_buffer(buffer)
                }

                fn value_mut(&mut self, buffer: &[u8]) -> VsssResult<()> {
                    self.1 = <$scalar_name as ShareIdentifier>::from_buffer(buffer)?;
                    Ok(())
                }

                #[cfg(any(feature = "alloc", feature = "std"))]
                fn value_vec(&self) -> Vec<u8> {
                    self.1.to_repr().to_vec()
                }
            }

        )+

        impl Share for ($scalar_name, $scalar_name) {
            type Identifier = $scalar_name;

            fn empty_share_with_capacity(_size_hint: usize) -> Self {
                (<$scalar_name as elliptic_curve::Field>::ZERO, <$scalar_name as elliptic_curve::Field>::ZERO)
            }

            fn is_zero(&self) -> Choice {
                self.1.is_zero()
            }

            fn identifier(&self) -> Self::Identifier {
                self.0
            }

            fn identifier_mut(&mut self) -> &mut Self::Identifier {
                &mut self.0
            }

            fn value(&self, buffer: &mut [u8]) -> VsssResult<()> {
                self.1.to_buffer(buffer)
            }

            fn value_mut(&mut self, buffer: &[u8]) -> VsssResult<()> {
                self.1 = <$scalar_name as ShareIdentifier>::from_buffer(buffer)?;
                Ok(())
            }

            #[cfg(any(feature = "alloc", feature = "std"))]
            fn value_vec(&self) -> Vec<u8> {
                self.1.to_repr().to_vec()
            }
        }
    };
}

#[cfg(any(
    feature = "k256",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "ed448-goldilocks-plus",
    feature = "curve25519",
))]
macro_rules! impl_group_share {
    ($group_name:ty, $scalar_name:ty, $($type:ident),+$(,)*) => {
        $(
            impl Share for ($type, $group_name) {
                type Identifier = $type;

                fn empty_share_with_capacity(_size_hint: usize) -> Self {
                    (0, <$group_name as Group>::identity())
                }

                fn is_zero(&self) -> Choice {
                    self.1.is_identity()
                }

                fn identifier(&self) -> Self::Identifier {
                    self.0
                }

                fn identifier_mut(&mut self) -> &mut Self::Identifier {
                    &mut self.0
                }

                fn value(&self, buffer: &mut [u8]) -> VsssResult<()> {
                    buffer.copy_from_slice(self.1.to_bytes().as_ref());
                    Ok(())
                }

                fn value_mut(&mut self, buffer: &[u8]) -> VsssResult<()> {
                    let t = <<$group_name as GroupEncoding>::Repr as ShareIdentifier>::from_buffer(buffer)?;
                    self.1 = Option::from(<$group_name as GroupEncoding>::from_bytes(&t)).ok_or(Error::InvalidShareConversion)?;
                    Ok(())
                }

                #[cfg(any(feature = "alloc", feature = "std"))]
                fn value_vec(&self) -> Vec<u8> {
                    self.1.to_bytes().to_vec()
                }
            }
        )+

        impl Share for ($scalar_name, $group_name) {
            type Identifier = $scalar_name;

            fn empty_share_with_capacity(_size_hint: usize) -> Self {
                (<$scalar_name as elliptic_curve::Field>::ZERO, <$group_name as Group>::identity())
            }

            fn is_zero(&self) -> Choice {
                self.1.is_identity()
            }

            fn identifier(&self) -> Self::Identifier {
                self.0
            }

            fn identifier_mut(&mut self) -> &mut Self::Identifier {
                &mut self.0
            }

            fn value(&self, buffer: &mut [u8]) -> VsssResult<()> {
                buffer.copy_from_slice(self.1.to_bytes().as_ref());
                Ok(())
            }

            fn value_mut(&mut self, buffer: &[u8]) -> VsssResult<()> {
                let t = <<$group_name as GroupEncoding>::Repr as ShareIdentifier>::from_buffer(buffer)?;
                self.1 = Option::from(<$group_name as GroupEncoding>::from_bytes(&t)).ok_or(Error::InvalidShareConversion)?;
                Ok(())
            }

            #[cfg(any(feature = "alloc", feature = "std"))]
            fn value_vec(&self) -> Vec<u8> {
                self.1.to_bytes().to_vec()
            }
        }
    };
}

#[cfg(any(feature = "bls12_381_plus", feature = "blstrs_plus"))]
macro_rules! impl_pairing_share {
    ($group_name:ident, $scalar_name:ty, $($type:ident),+$(,)*) => {
        $(
            impl Share for ($type, $group_name) {
                type Identifier = $type;

                fn empty_share_with_capacity(_size_hint: usize) -> Self {
                    (0, <$group_name as Group>::identity())
                }

                fn is_zero(&self) -> Choice {
                    self.1.is_identity()
                }

                fn identifier(&self) -> Self::Identifier {
                    self.0
                }

                fn identifier_mut(&mut self) -> &mut Self::Identifier {
                    &mut self.0
                }

                fn value(&self, buffer: &mut [u8]) -> VsssResult<()> {
                    buffer.copy_from_slice(self.1.to_bytes().as_ref());
                    Ok(())
                }

                fn value_mut(&mut self, buffer: &[u8]) -> VsssResult<()> {
                    let input = buffer.try_into().map_err(|_| Error::InvalidShareConversion)?;
                    self.1 = Option::from($group_name::from_compressed(&input)).ok_or(Error::InvalidShareConversion)?;
                    Ok(())
                }

                #[cfg(any(feature = "alloc", feature = "std"))]
                fn value_vec(&self) -> Vec<u8> {
                    self.1.to_bytes().into()
                }
            }
        )+

        impl Share for ($scalar_name, $group_name) {
            type Identifier = $scalar_name;

            fn empty_share_with_capacity(_size_hint: usize) -> Self {
                (<$scalar_name as elliptic_curve::Field>::ZERO, <$group_name as Group>::identity())
            }

            fn is_zero(&self) -> Choice {
                self.1.is_identity()
            }

            fn identifier(&self) -> Self::Identifier {
                self.0
            }

            fn identifier_mut(&mut self) -> &mut Self::Identifier {
                &mut self.0
            }

            fn value(&self, buffer: &mut [u8]) -> VsssResult<()> {
                buffer.copy_from_slice(self.1.to_bytes().as_ref());
                Ok(())
            }

            fn value_mut(&mut self, buffer: &[u8]) -> VsssResult<()> {
                let input = buffer.try_into().map_err(|_| Error::InvalidShareConversion)?;
                self.1 = Option::from($group_name::from_compressed(&input)).ok_or(Error::InvalidShareConversion)?;
                Ok(())
            }

            #[cfg(any(feature = "alloc", feature = "std"))]
            fn value_vec(&self) -> Vec<u8> {
                self.1.to_bytes().into()
            }
        }
    };
}

#[cfg(feature = "k256")]
impl_field_share!(k256::Scalar, u8, u16, u32, u64, usize, u128,);
#[cfg(feature = "k256")]
impl_group_share!(
    k256::ProjectivePoint,
    k256::Scalar,
    u8,
    u16,
    u32,
    u64,
    usize,
    u128,
);
#[cfg(feature = "p256")]
impl_field_share!(p256::Scalar, u8, u16, u32, u64, usize, u128,);
#[cfg(feature = "p256")]
impl_group_share!(
    p256::ProjectivePoint,
    p256::Scalar,
    u8,
    u16,
    u32,
    u64,
    usize,
    u128,
);
#[cfg(feature = "p384")]
impl_field_share!(p384::Scalar, u8, u16, u32, u64, usize, u128,);
#[cfg(feature = "p384")]
impl_group_share!(
    p384::ProjectivePoint,
    p384::Scalar,
    u8,
    u16,
    u32,
    u64,
    usize,
    u128,
);
#[cfg(feature = "ed448-goldilocks-plus")]
impl_field_share!(
    ed448_goldilocks_plus::Scalar,
    u8,
    u16,
    u32,
    u64,
    usize,
    u128,
);
#[cfg(feature = "ed448-goldilocks-plus")]
impl_group_share!(
    ed448_goldilocks_plus::EdwardsPoint,
    ed448_goldilocks_plus::Scalar,
    u8,
    u16,
    u32,
    u64,
    usize,
    u128,
);
#[cfg(feature = "curve25519")]
impl_field_share!(curve25519::WrappedScalar, u8, u16, u32, u64, usize, u128,);
#[cfg(feature = "curve25519")]
impl_group_share!(
    curve25519::WrappedRistretto,
    curve25519::WrappedScalar,
    u8,
    u16,
    u32,
    u64,
    usize,
    u128,
);
#[cfg(feature = "curve25519")]
impl_group_share!(
    curve25519::WrappedEdwards,
    curve25519::WrappedScalar,
    u8,
    u16,
    u32,
    u64,
    usize,
    u128,
);
#[cfg(feature = "bls12_381_plus")]
impl_field_share!(bls12_381_plus::Scalar, u8, u16, u32, u64, usize, u128,);
#[cfg(feature = "bls12_381_plus")]
use bls12_381_plus::G1Projective as G1ProjectiveBls12_381;
#[cfg(feature = "bls12_381_plus")]
impl_pairing_share!(
    G1ProjectiveBls12_381,
    bls12_381_plus::Scalar,
    u8,
    u16,
    u32,
    u64,
    usize,
    u128,
);
#[cfg(feature = "bls12_381_plus")]
use bls12_381_plus::G2Projective as G2ProjectiveBls12_381;
#[cfg(feature = "bls12_381_plus")]
impl_pairing_share!(
    G2ProjectiveBls12_381,
    bls12_381_plus::Scalar,
    u8,
    u16,
    u32,
    u64,
    usize,
    u128,
);
#[cfg(feature = "blstrs_plus")]
impl_field_share!(blstrs_plus::Scalar, u8, u16, u32, u64, usize, u128,);
#[cfg(feature = "blstrs_plus")]
use blstrs_plus::G1Projective;
#[cfg(feature = "blstrs_plus")]
impl_pairing_share!(
    G1Projective,
    blstrs_plus::Scalar,
    u8,
    u16,
    u32,
    u64,
    usize,
    u128,
);
#[cfg(feature = "blstrs_plus")]
use blstrs_plus::G2Projective;
#[cfg(feature = "blstrs_plus")]
impl_pairing_share!(
    G2Projective,
    blstrs_plus::Scalar,
    u8,
    u16,
    u32,
    u64,
    usize,
    u128,
);

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

#[test]
fn uint() {
    let share = (2000u16, Uint::<1>::from(0x12345678u32));
    assert_eq!(share.identifier(), 2000u16);
    let mut value = [0u8; 8];
    assert!(share.value(&mut value).is_ok());
    assert_eq!(value, [0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78]);

    let share = (10000u16, Uint::<2>::from(0x123456789abcdef0u64));
    assert_eq!(share.identifier(), 10000u16);
    let mut value = [0u8; 16];
    assert!(share.value(&mut value).is_ok());
    assert_eq!(
        value,
        [0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]
    );
}

#[test]
fn modular() {
    let params = DynResidueParams::new(&Uint::<1>::from(2147483647u32));
    let share = (
        2000u16,
        DynResidue::new(&Uint::<1>::from(0x12345678u32), params),
    );
    assert_eq!(share.identifier(), 2000u16);
    let mut value = [0u8; 16];
    assert!(share.value(&mut value).is_ok());
    assert_eq!(
        value,
        [0, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78]
    );

    let mut share2 = share.clone();
    let res = share2.value_mut(&value);
    assert!(res.is_ok());
    assert_eq!(share.1, share2.1);
}

#[cfg(feature = "k256")]
#[test]
fn scalars_k256() {
    let share = (1u16, k256::Scalar::from(0x12345678u64));
    assert_eq!(share.identifier(), 1u16);
    let mut value = [0u8; 32];
    assert!(share.value(&mut value).is_ok());
    assert_eq!(
        value,
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0x12, 0x34, 0x56, 0x78
        ]
    );
}

#[cfg(all(feature = "k256", any(feature = "alloc", feature = "std")))]
#[test]
fn points_k256() {
    use elliptic_curve::Field;
    use rand_core::SeedableRng;

    let mut rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);
    let secret = k256::Scalar::random(&mut rng);
    let shares =
        crate::shamir::split_secret::<k256::Scalar, u8, (u8, k256::Scalar)>(2, 3, secret, &mut rng)
            .unwrap();
    let pt_shares = shares
        .into_iter()
        .map(|(i, s)| (i, k256::ProjectivePoint::GENERATOR * s))
        .collect::<Vec<_>>();
    let pub_key: k256::ProjectivePoint = combine_shares_group(&pt_shares).unwrap();
    assert_eq!(pub_key, k256::ProjectivePoint::GENERATOR * secret);
}
