use crate::util::CtIsZero;
use crate::Vec;
use crate::{Error, PrimeFieldImpl, VsssResult};
use core::cmp;
use crypto_bigint::{Encoding, Zero, U64, U128, U192, U256, U384, U448, U512, U576, U768, U896, U1024, U2048, U3072, U4096, U8192, U16384, U32768};
use elliptic_curve::{
    PrimeField, generic_array::{GenericArray, ArrayLength},
};
use subtle::Choice;

/// A value used to represent the identifier for secret shares
pub trait ShareIdentifier: Sized + Eq {
    /// The byte representation of the identifier
    type ByteRepr: AsRef<[u8]> + AsMut<[u8]>;

    /// Convert an identifier from a field element
    fn from_field_element<F: PrimeField>(element: F) -> VsssResult<Self>;
    /// Convert this share into a field element
    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F>;
    /// True if all value bytes are zero
    fn is_zero(&self) -> Choice;
    /// Return a byte sequence representing the identifier
    fn to_repr(&self) -> Self::ByteRepr;
    /// Return a byte sequence representing the identifier
    fn from_repr(repr: Self::ByteRepr) -> VsssResult<Self>;
}

impl ShareIdentifier for u8 {
    type ByteRepr = [u8; 1];

    fn from_field_element<F: PrimeField>(element: F) -> VsssResult<Self> {
        let repr = element.to_repr();
        // Assume little endian encoding first
        // then try big endian
        let bytes = repr.as_ref();
        if bytes[1..].ct_is_zero().into() {
            Ok(bytes[0])
        } else if bytes[..bytes.len() - 2].ct_is_zero().into() {
            Ok(*bytes.last().unwrap())
        } else {
            Err(Error::InvalidShareConversion)
        }
    }

    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
        Ok(F::from(*self as u64))
    }

    fn is_zero(&self) -> Choice {
        self.ct_is_zero()
    }

    fn to_repr(&self) -> Self::ByteRepr {
        [*self]
    }

    fn from_repr(repr: Self::ByteRepr) -> VsssResult<Self> {
        Ok(repr[0])
    }
}

impl ShareIdentifier for u16 {
    type ByteRepr = [u8; 2];

    fn from_field_element<F: PrimeField>(element: F) -> VsssResult<Self> {
        let repr = element.to_repr();
        // Assume little endian encoding first
        // then try big endian
        let bytes = repr.as_ref();
        let len = bytes.len();
        if bytes[2..].ct_is_zero().into() {
            Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
        } else if bytes[..len - 3].ct_is_zero().into() {
            Ok(u16::from_be_bytes([bytes[len - 2], bytes[len - 1]]))
        } else {
            Err(Error::InvalidShareConversion)
        }
    }

    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
        Ok(F::from(*self as u64))
    }

    fn is_zero(&self) -> Choice {
        self.ct_is_zero()
    }

    fn to_repr(&self) -> Self::ByteRepr {
        self.to_be_bytes()
    }

    fn from_repr(repr: Self::ByteRepr) -> VsssResult<Self> {
        Ok(u16::from_be_bytes(repr))
    }
}

impl ShareIdentifier for u32 {
    type ByteRepr = [u8; 4];

    fn from_field_element<F: PrimeField>(element: F) -> VsssResult<Self> {
        let repr = element.to_repr();
        // Assume little endian encoding first
        // then try big endian
        let bytes = repr.as_ref();
        let len = bytes.len();
        if bytes[4..].ct_is_zero().into() {
            Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        } else if bytes[..bytes.len() - 5].ct_is_zero().into() {
            Ok(u32::from_be_bytes([
                bytes[len - 4],
                bytes[len - 3],
                bytes[len - 2],
                bytes[len - 1],
            ]))
        } else {
            Err(Error::InvalidShareConversion)
        }
    }

    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
        Ok(F::from(*self as u64))
    }

    fn is_zero(&self) -> Choice {
        self.ct_is_zero()
    }

    fn to_repr(&self) -> Self::ByteRepr {
        self.to_be_bytes()
    }

    fn from_repr(repr: Self::ByteRepr) -> VsssResult<Self> {
        Ok(u32::from_be_bytes(repr))
    }
}

impl ShareIdentifier for u64 {
    type ByteRepr = [u8; 8];

    fn from_field_element<F: PrimeField>(element: F) -> VsssResult<Self> {
        let repr = element.to_repr();
        // Assume little endian encoding first
        // then try big endian
        let bytes = repr.as_ref();
        let len = bytes.len();
        if bytes[8..].ct_is_zero().into() {
            Ok(u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]))
        } else if bytes[..len - 9].ct_is_zero().into() {
            Ok(u64::from_be_bytes([
                bytes[len - 8],
                bytes[len - 7],
                bytes[len - 6],
                bytes[len - 5],
                bytes[len - 4],
                bytes[len - 3],
                bytes[len - 2],
                bytes[len - 1],
            ]))
        } else {
            Err(Error::InvalidShareConversion)
        }
    }

    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
        Ok(F::from(*self))
    }

    fn is_zero(&self) -> Choice {
        self.ct_is_zero()
    }

    fn to_repr(&self) -> Self::ByteRepr {
        self.to_be_bytes()
    }

    fn from_repr(repr: Self::ByteRepr) -> VsssResult<Self> {
        Ok(u64::from_be_bytes(repr))
    }
}

#[cfg(target_pointer_width = "64")]
impl ShareIdentifier for u128 {
    type ByteRepr = [u8; 16];

    fn from_field_element<F: PrimeField>(element: F) -> VsssResult<Self> {
        let repr = element.to_repr();
        // Assume little endian encoding first
        // then try big endian
        let bytes = repr.as_ref();
        let len = bytes.len();
        if bytes[16..].ct_is_zero().into() {
            Ok(u128::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15],
            ]))
        } else if bytes[..len - 17].ct_is_zero().into() {
            Ok(u128::from_be_bytes([
                bytes[len - 16],
                bytes[len - 15],
                bytes[len - 14],
                bytes[len - 13],
                bytes[len - 12],
                bytes[len - 11],
                bytes[len - 10],
                bytes[len - 9],
                bytes[len - 8],
                bytes[len - 7],
                bytes[len - 6],
                bytes[len - 5],
                bytes[len - 4],
                bytes[len - 3],
                bytes[len - 2],
                bytes[len - 1],
            ]))
        } else {
            Err(Error::InvalidShareConversion)
        }
    }

    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
        Ok(F::from_u128(*self))
    }

    fn is_zero(&self) -> Choice {
        self.ct_is_zero()
    }

    fn to_repr(&self) -> Self::ByteRepr {
        self.to_be_bytes()
    }

    fn from_repr(repr: Self::ByteRepr) -> VsssResult<Self> {
        Ok(u128::from_be_bytes(repr))
    }
}

impl ShareIdentifier for usize {
    #[cfg(target_pointer_width = "32")]
    type ByteRepr = [u8; 4];
    #[cfg(target_pointer_width = "64")]
    type ByteRepr = [u8; 8];

    #[cfg(target_pointer_width = "32")]
    fn from_field_element<F: PrimeField>(element: F) -> VsssResult<Self> {
        let r = u32::from_field_element::<F>(element)? as usize;
        Ok(r)
    }
    #[cfg(target_pointer_width = "64")]
    fn from_field_element<F: PrimeField>(element: F) -> VsssResult<Self> {
        let r = u64::from_field_element::<F>(element)? as usize;
        Ok(r)
    }

    #[cfg(target_pointer_width = "32")]
    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
        let r = *self as u32;
        r.as_field_element::<F>()
    }

    #[cfg(target_pointer_width = "64")]
    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
        let r = *self as u64;
        r.as_field_element::<F>()
    }

    fn is_zero(&self) -> Choice {
        self.ct_is_zero()
    }

    #[cfg(target_pointer_width = "32")]
    fn to_repr(&self) -> Self::ByteRepr {
        let r = *self as u32;
        r.to_repr()
    }
    #[cfg(target_pointer_width = "64")]
    fn to_repr(&self) -> Self::ByteRepr {
        let r = *self as u64;
        r.to_repr()
    }

    #[cfg(target_pointer_width = "32")]
    fn from_repr(repr: Self::ByteRepr) -> VsssResult<Self> {
        let r = u32::from_repr(repr)? as usize;
        Ok(r)
    }

    #[cfg(target_pointer_width = "64")]
    fn from_repr(repr: Self::ByteRepr) -> VsssResult<Self> {
        let r = u64::from_repr(repr)? as usize;
        Ok(r)
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl ShareIdentifier for Vec<u8> {
    type ByteRepr = Vec<u8>;

    fn from_field_element<F: PrimeField>(element: F) -> VsssResult<Self> {
        let repr = element.to_repr();
        let bytes = repr.as_ref();
        Ok(bytes.to_vec())
    }

    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
        let mut repr = F::Repr::default();
        if self.len() > repr.as_ref().len() {
            return Err(Error::InvalidShareConversion);
        }
        repr.as_mut().copy_from_slice(self.as_slice());
        Option::<F>::from(F::from_repr(repr)).ok_or(Error::InvalidShareConversion)
    }

    fn is_zero(&self) -> Choice {
        self.ct_is_zero()
    }

    fn to_repr(&self) -> Self::ByteRepr {
        self.clone()
    }

    fn from_repr(repr: Self::ByteRepr) -> VsssResult<Self> {
        Ok(repr)
    }
}

impl<F: PrimeField> ShareIdentifier for PrimeFieldImpl<F> {
    type ByteRepr = F::Repr;

    fn from_field_element<FF: PrimeField>(element: FF) -> VsssResult<Self> {
        let mut repr = F::Repr::default();
        repr.as_mut().copy_from_slice(element.to_repr().as_ref());
        Self::from_repr(repr)
    }

    fn as_field_element<FF: PrimeField>(&self) -> VsssResult<FF> {
        let mut repr = FF::Repr::default();
        repr.as_mut().copy_from_slice(self.0.to_repr().as_ref());
        Option::<FF>::from(FF::from_repr(repr)).ok_or(Error::InvalidShareConversion)
    }

    fn is_zero(&self) -> Choice {
        self.0.is_zero()
    }

    fn to_repr(&self) -> Self::ByteRepr {
        self.0.to_repr()
    }

    fn from_repr(repr: Self::ByteRepr) -> VsssResult<Self> {
        Ok(PrimeFieldImpl(
            Option::from(F::from_repr(repr)).ok_or(Error::InvalidShareConversion)?,
        ))
    }
}

macro_rules! impl_share_identifier_big_int {
    ($($name:ident => $bytes:expr),+$(,)*) => {
        $(
            impl ShareIdentifier for $name {
                type ByteRepr = [u8; $bytes];

                fn from_field_element<F: PrimeField>(element: F) -> VsssResult<Self> {
                    let repr = element.to_repr();
                    let bytes = repr.as_ref();
                    let mut r = [0u8; $bytes];
                    let len = cmp::min(r.len(), bytes.len());
                    r.copy_from_slice(&bytes[0..len]);
                    Ok(Self::from_be_bytes(r))
                }

                fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
                    let mut repr = F::Repr::default();
                    let bytes = self.to_be_bytes();
                    let len = cmp::min(repr.as_ref().len(), bytes.len());
                    repr.as_mut().copy_from_slice(&bytes[..len]);
                    Option::<F>::from(F::from_repr(repr)).ok_or(Error::InvalidShareConversion)
                }

                fn is_zero(&self) -> Choice {
                    <Self as Zero>::is_zero(self)
                }

                fn to_repr(&self) -> Self::ByteRepr {
                    self.to_be_bytes()
                }

                fn from_repr(repr: Self::ByteRepr) -> VsssResult<Self> {
                    Ok(Self::from_be_bytes(repr))
                }
            }
        )+
    };
}

impl_share_identifier_big_int!(
    U64 => 8,
    U128 => 16,
    U192 => 24,
    U256 => 32,
    U384 => 48,
    U448 => 56,
    U512 => 64,
    U576 => 72,
    U768 => 96,
    U896 => 112,
    U1024 => 128,
    U2048 => 256,
    U3072 => 384,
    U4096 => 512,
    U8192 => 1024,
    U16384 => 2048,
    U32768 => 4096,
);


impl<const L: usize> ShareIdentifier for [u8; L] {
    type ByteRepr = Self;

    fn from_field_element<F: PrimeField>(element: F) -> VsssResult<Self> {
        let repr = element.to_repr();
        let bytes = repr.as_ref();
        let mut r = [0u8; L];
        let len = cmp::min(L, bytes.len());
        r[..len].copy_from_slice(&bytes[0..len]);
        Ok(r)
    }

    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
        let mut repr = F::Repr::default();
        let len = cmp::min(repr.as_ref().len(), self.len());
        repr.as_mut()[..len].copy_from_slice(&self[..len]);
        Option::<F>::from(F::from_repr(repr)).ok_or(Error::InvalidShareConversion)
    }

    fn is_zero(&self) -> Choice {
        self.ct_is_zero()
    }

    fn to_repr(&self) -> Self::ByteRepr {
        *self
    }

    fn from_repr(repr: Self::ByteRepr) -> VsssResult<Self> {
        Ok(repr)
    }
}

impl<L: ArrayLength<u8>> ShareIdentifier for GenericArray<u8, L> {
    type ByteRepr = Self;

    fn from_field_element<F: PrimeField>(element: F) -> VsssResult<Self> {
        let repr = element.to_repr();
        let bytes = repr.as_ref();
        let mut r = Self::default();
        let len = cmp::min(r.len(), bytes.len());
        r[..len].copy_from_slice(&bytes[0..len]);
        Ok(r)
    }

    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
        let mut repr = F::Repr::default();
        let len = cmp::min(repr.as_ref().len(), self.len());
        repr.as_mut()[..len].copy_from_slice(&self[..len]);
        Option::<F>::from(F::from_repr(repr)).ok_or(Error::InvalidShareConversion)
    }

    fn is_zero(&self) -> Choice {
        self.ct_is_zero()
    }

    fn to_repr(&self) -> Self::ByteRepr {
        self.clone()
    }

    fn from_repr(repr: Self::ByteRepr) -> VsssResult<Self> {
        Ok(repr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arrays() {
        let a = [1u8, 2, 3, 4];
        let res = ShareIdentifier::as_field_element::<k256::Scalar>(&a);
        assert!(res.is_ok());
    }

    #[test]
    fn ga() {
        let mut a = GenericArray::<u8, typenum::U18>::default();
        a[0] = 1;
        let res = ShareIdentifier::as_field_element::<k256::Scalar>(&a);
        assert!(res.is_ok());
    }
}