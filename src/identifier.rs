use crate::util::*;
use crate::Vec;
use crate::{Error, VsssResult};
use core::cmp;
use crypto_bigint::{Uint, Zero};
use elliptic_curve::PrimeField;
use generic_array::{ArrayLength, GenericArray};
use subtle::Choice;

/// A value used to represent the identifier for secret shares
pub trait ShareIdentifier: Sized + Eq {
    /// Convert an identifier from a field element
    fn from_field_element<F: PrimeField>(element: F) -> VsssResult<Self>;
    /// Convert this share into a field element
    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F>;
    /// True if all value bytes are zero
    fn is_zero(&self) -> Choice;
    /// Write the byte representation of this identifier to a buffer
    fn to_buffer<M: AsMut<[u8]>>(&self, buffer: M) -> VsssResult<()>;
    /// Read the byte representation of an identifier from a buffer
    fn from_buffer<B: AsRef<[u8]>>(repr: B) -> VsssResult<Self>;
    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Convert this identifier to a vector of bytes
    fn to_vec(&self) -> Vec<u8>;
}

impl ShareIdentifier for u8 {
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

    fn to_buffer<M: AsMut<[u8]>>(&self, mut buffer: M) -> VsssResult<()> {
        let buffer = buffer.as_mut();
        if buffer.is_empty() {
            return Err(Error::InvalidShareConversion);
        }
        buffer[0] = *self;
        Ok(())
    }

    fn from_buffer<B: AsRef<[u8]>>(repr: B) -> VsssResult<Self> {
        let repr = repr.as_ref();
        Ok(repr[0])
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        [*self].to_vec()
    }
}

impl ShareIdentifier for u16 {
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

    fn to_buffer<M: AsMut<[u8]>>(&self, mut buffer: M) -> VsssResult<()> {
        let buffer = buffer.as_mut();
        if buffer.len() < 2 {
            return Err(Error::InvalidShareConversion);
        }
        buffer.copy_from_slice(&self.to_be_bytes()[..]);
        Ok(())
    }

    fn from_buffer<B: AsRef<[u8]>>(repr: B) -> VsssResult<Self> {
        let repr = repr.as_ref();
        let repr: [u8; 2] = repr[..2]
            .try_into()
            .map_err(|_| Error::InvalidShareConversion)?;
        Ok(u16::from_be_bytes(repr))
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl ShareIdentifier for u32 {
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

    fn to_buffer<M: AsMut<[u8]>>(&self, mut buffer: M) -> VsssResult<()> {
        let buffer = buffer.as_mut();
        if buffer.len() < 4 {
            return Err(Error::InvalidShareConversion);
        }
        buffer.copy_from_slice(&self.to_be_bytes()[..]);
        Ok(())
    }

    fn from_buffer<B: AsRef<[u8]>>(repr: B) -> VsssResult<Self> {
        let repr = repr.as_ref();
        let repr: [u8; 4] = repr[..4]
            .try_into()
            .map_err(|_| Error::InvalidShareConversion)?;
        Ok(u32::from_be_bytes(repr))
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl ShareIdentifier for u64 {
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

    fn to_buffer<M: AsMut<[u8]>>(&self, mut buffer: M) -> VsssResult<()> {
        let buffer = buffer.as_mut();
        if buffer.len() < 8 {
            return Err(Error::InvalidShareConversion);
        }
        buffer[..8].copy_from_slice(&self.to_be_bytes()[..]);
        Ok(())
    }

    fn from_buffer<B: AsRef<[u8]>>(repr: B) -> VsssResult<Self> {
        let repr = repr.as_ref();
        let repr: [u8; 8] = repr[..8]
            .try_into()
            .map_err(|_| Error::InvalidShareConversion)?;
        Ok(u64::from_be_bytes(repr))
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

#[cfg(target_pointer_width = "64")]
impl ShareIdentifier for u128 {
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

    fn to_buffer<M: AsMut<[u8]>>(&self, mut buffer: M) -> VsssResult<()> {
        let buffer = buffer.as_mut();
        if buffer.len() < 16 {
            return Err(Error::InvalidShareConversion);
        }
        buffer[..16].copy_from_slice(&self.to_be_bytes()[..]);
        Ok(())
    }

    fn from_buffer<B: AsRef<[u8]>>(repr: B) -> VsssResult<Self> {
        let repr = repr.as_ref();
        let repr: [u8; 16] = repr[..16]
            .try_into()
            .map_err(|_| Error::InvalidShareConversion)?;
        Ok(u128::from_be_bytes(repr))
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl ShareIdentifier for usize {
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
    fn to_buffer<M: AsMut<[u8]>>(&self, buffer: M) -> VsssResult<()> {
        let r = *self as u32;
        <u32 as ShareIdentifier>::to_buffer(&r, buffer)
    }
    #[cfg(target_pointer_width = "64")]
    fn to_buffer<M: AsMut<[u8]>>(&self, buffer: M) -> VsssResult<()> {
        let r = *self as u64;
        <u64 as ShareIdentifier>::to_buffer(&r, buffer)
    }

    #[cfg(target_pointer_width = "32")]
    fn from_buffer<B: AsRef<[u8]>>(repr: B) -> VsssResult<Self> {
        let r = <u32 as ShareIdentifier>::from_buffer(repr)? as usize;
        Ok(r)
    }

    #[cfg(target_pointer_width = "64")]
    fn from_buffer<B: AsRef<[u8]>>(repr: B) -> VsssResult<Self> {
        let r = <u64 as ShareIdentifier>::from_buffer(repr)? as usize;
        Ok(r)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        match core::mem::size_of::<usize>() {
            4 => {
                let r = *self as u32;
                r.to_vec()
            }
            8 => {
                let r = *self as u64;
                r.to_vec()
            }
            _ => Vec::new(),
        }
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl ShareIdentifier for Vec<u8> {
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

    fn to_buffer<M: AsMut<[u8]>>(&self, mut buffer: M) -> VsssResult<()> {
        let buffer = buffer.as_mut();
        if buffer.len() < self.len() {
            return Err(Error::InvalidShareConversion);
        }
        buffer[..self.len()].copy_from_slice(self.as_slice());
        Ok(())
    }

    fn from_buffer<B: AsRef<[u8]>>(repr: B) -> VsssResult<Self> {
        Ok(repr.as_ref().to_vec())
    }

    fn to_vec(&self) -> Vec<u8> {
        self.clone()
    }
}

impl<const LIMBS: usize> ShareIdentifier for Uint<LIMBS> {
    fn from_field_element<F: PrimeField>(element: F) -> VsssResult<Self> {
        let repr = element.to_repr();
        let bytes = repr.as_ref();
        let len = cmp::min(Uint::<LIMBS>::BYTES, bytes.len());
        Ok(Uint::<LIMBS>::from_be_slice(&bytes[0..len]))
    }

    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
        let mut repr = F::Repr::default();
        if repr.as_ref().len() < Uint::<LIMBS>::BYTES {
            return Err(Error::InvalidShareConversion);
        }
        uint_to_be_byte_array(self, repr.as_mut())?;
        Option::<F>::from(F::from_repr(repr)).ok_or(Error::InvalidShareConversion)
    }

    fn is_zero(&self) -> Choice {
        Zero::is_zero(self)
    }

    fn to_buffer<M: AsMut<[u8]>>(&self, mut buffer: M) -> VsssResult<()> {
        let buffer = buffer.as_mut();
        if buffer.len() < Uint::<LIMBS>::BYTES {
            return Err(Error::InvalidShareConversion);
        }
        uint_to_be_byte_array(self, buffer)
    }

    fn from_buffer<B: AsRef<[u8]>>(repr: B) -> VsssResult<Self> {
        let repr = repr.as_ref();
        let len = cmp::min(Uint::<LIMBS>::BYTES, repr.len());
        Ok(Uint::<LIMBS>::from_be_slice(&repr[0..len]))
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        let mut b = vec![0u8; Uint::<LIMBS>::BYTES];
        uint_to_be_byte_array(self, &mut b).expect("buffer is the correct size");
        b
    }
}

impl<const L: usize> ShareIdentifier for [u8; L] {
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

    fn to_buffer<M: AsMut<[u8]>>(&self, mut buffer: M) -> VsssResult<()> {
        let buffer = buffer.as_mut();
        if buffer.len() < self.len() {
            return Err(Error::InvalidShareConversion);
        }
        buffer[..self.len()].copy_from_slice(self);
        Ok(())
    }

    fn from_buffer<B: AsRef<[u8]>>(repr: B) -> VsssResult<Self> {
        let repr = repr.as_ref();
        let mut r = [0u8; L];
        let len = cmp::min(L, repr.len());
        r[..len].copy_from_slice(&repr[..len]);
        Ok(r)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self[..].to_vec()
    }
}

impl<L: ArrayLength> ShareIdentifier for GenericArray<u8, L> {
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

    fn to_buffer<M: AsMut<[u8]>>(&self, mut buffer: M) -> VsssResult<()> {
        let buffer = buffer.as_mut();
        if buffer.len() < self.len() {
            return Err(Error::InvalidShareConversion);
        }
        buffer[..self.len()].copy_from_slice(self);
        Ok(())
    }

    fn from_buffer<B: AsRef<[u8]>>(repr: B) -> VsssResult<Self> {
        let repr = repr.as_ref();
        let mut r = Self::default();
        let len = cmp::min(r.len(), repr.len());
        r[..len].copy_from_slice(&repr[..len]);
        Ok(r)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self[..].to_vec()
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
        use elliptic_curve::generic_array::typenum;

        let mut a = GenericArray::<u8, typenum::U18>::default();
        a[0] = 1;
        let res = ShareIdentifier::as_field_element::<k256::Scalar>(&a);
        assert!(res.is_ok());
    }
}
