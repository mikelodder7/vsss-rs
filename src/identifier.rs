use crate::util::*;
use crate::{Error, VsssResult};
use core::cmp;
use crypto_bigint::{
    modular::{
        constant_mod::{Residue, ResidueParams},
        runtime_mod::{DynResidue, DynResidueParams},
    },
    Uint, Zero,
};
use elliptic_curve::PrimeField;
use generic_array::{ArrayLength, GenericArray};
use subtle::Choice;

#[cfg(any(feature = "alloc", feature = "std"))]
use crate::Vec;

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
        match size_of::<usize>() {
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
        be_byte_array_to_uint::<LIMBS>(bytes)
    }

    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
        let mut repr = F::Repr::default();
        uint_to_be_byte_array(self, repr.as_mut())?;
        Option::<F>::from(F::from_repr(repr)).ok_or(Error::InvalidShareConversion)
    }

    fn is_zero(&self) -> Choice {
        Zero::is_zero(self)
    }

    fn to_buffer<M: AsMut<[u8]>>(&self, mut buffer: M) -> VsssResult<()> {
        uint_to_be_byte_array(self, buffer.as_mut())
    }

    fn from_buffer<B: AsRef<[u8]>>(repr: B) -> VsssResult<Self> {
        be_byte_array_to_uint(repr.as_ref())
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

impl<L: elliptic_curve::generic_array::ArrayLength<u8>> ShareIdentifier
    for elliptic_curve::generic_array::GenericArray<u8, L>
{
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

impl<const LIMBS: usize> ShareIdentifier for DynResidue<LIMBS> {
    fn from_field_element<F: PrimeField>(element: F) -> VsssResult<Self> {
        let modulus = Uint::<LIMBS>::from_be_hex(F::MODULUS);
        let value = Uint::<LIMBS>::from_field_element(element)?;
        let params = DynResidueParams::new(&modulus);
        Ok(DynResidue::new(&value, params))
    }

    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
        Uint::<LIMBS>::as_field_element(&self.retrieve())
    }

    fn is_zero(&self) -> Choice {
        <Uint<LIMBS> as Zero>::is_zero(&self.retrieve())
    }

    fn to_buffer<M: AsMut<[u8]>>(&self, mut buffer: M) -> VsssResult<()> {
        let b = buffer.as_mut();
        if b.len() < Uint::<LIMBS>::BYTES * 2 {
            return Err(Error::InvalidShareConversion);
        }
        self.params()
            .modulus()
            .to_buffer(&mut b[..Uint::<LIMBS>::BYTES])?;
        self.retrieve().to_buffer(&mut b[Uint::<LIMBS>::BYTES..])?;
        Ok(())
    }

    fn from_buffer<B: AsRef<[u8]>>(repr: B) -> VsssResult<Self> {
        let repr = repr.as_ref();
        if repr.len() < Uint::<LIMBS>::BYTES * 2 {
            return Err(Error::InvalidShareConversion);
        }
        let modulus = Uint::<LIMBS>::from_buffer(&repr[..Uint::<LIMBS>::BYTES])?;
        let value = Uint::<LIMBS>::from_buffer(&repr[Uint::<LIMBS>::BYTES..])?;
        let params = DynResidueParams::new(&modulus);
        Ok(DynResidue::new(&value, params))
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        let mut out = vec![0u8; Uint::<LIMBS>::BYTES * 2];
        self.to_buffer(&mut out)
            .expect("buffer is the correct size");
        out
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> ShareIdentifier for Residue<MOD, LIMBS> {
    fn from_field_element<F: PrimeField>(element: F) -> VsssResult<Self> {
        debug_assert_eq!(Uint::<LIMBS>::from_be_hex(F::MODULUS), MOD::MODULUS);
        let value = Uint::<LIMBS>::from_field_element(element)?;
        Ok(Residue::new(&value))
    }

    fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
        Uint::<LIMBS>::as_field_element(&self.retrieve())
    }

    fn is_zero(&self) -> Choice {
        <Uint<LIMBS> as Zero>::is_zero(&self.retrieve())
    }

    fn to_buffer<M: AsMut<[u8]>>(&self, buffer: M) -> VsssResult<()> {
        self.retrieve().to_buffer(buffer)
    }

    fn from_buffer<B: AsRef<[u8]>>(repr: B) -> VsssResult<Self> {
        let value = Uint::<LIMBS>::from_buffer(repr)?;
        Ok(Residue::new(&value))
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        let mut out = vec![0u8; Uint::<LIMBS>::BYTES];
        self.to_buffer(&mut out)
            .expect("buffer is the correct size");
        out
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
macro_rules! scalar_impl {
    ($name:path) => {
        impl ShareIdentifier for $name {
            fn from_field_element<F: PrimeField>(element: F) -> VsssResult<Self> {
                let bytes =
                    <<$name as PrimeField>::Repr as ShareIdentifier>::from_field_element(element)?;
                let ct_out = Self::from_repr(bytes);
                Option::from(ct_out).ok_or(Error::InvalidShareConversion)
            }

            fn as_field_element<F: PrimeField>(&self) -> VsssResult<F> {
                let mut repr = F::Repr::default();
                let r = self.to_repr();
                repr.as_mut().copy_from_slice(&r);
                Option::<F>::from(F::from_repr(repr)).ok_or(Error::InvalidShareConversion)
            }

            fn is_zero(&self) -> Choice {
                <$name as elliptic_curve::Field>::is_zero(self)
            }

            fn from_buffer<B: AsRef<[u8]>>(repr: B) -> VsssResult<Self> {
                let repr = repr.as_ref();
                let bytes = <<$name as PrimeField>::Repr as ShareIdentifier>::from_buffer(repr)?;
                let ct_out = Self::from_repr(bytes);
                Option::from(ct_out).ok_or(Error::InvalidShareConversion)
            }

            fn to_buffer<M: AsMut<[u8]>>(&self, mut buffer: M) -> VsssResult<()> {
                let buffer = buffer.as_mut();
                if buffer.len() < 32 {
                    return Err(Error::InvalidShareConversion);
                }
                buffer.copy_from_slice(&self.to_repr());
                Ok(())
            }

            #[cfg(any(feature = "alloc", feature = "std"))]
            fn to_vec(&self) -> Vec<u8> {
                self.to_repr().to_vec()
            }
        }
    };
}
#[cfg(feature = "k256")]
scalar_impl!(k256::Scalar);
#[cfg(feature = "p256")]
scalar_impl!(p256::Scalar);
#[cfg(feature = "p384")]
scalar_impl!(p384::Scalar);
#[cfg(feature = "p521")]
scalar_impl!(p521::Scalar);
#[cfg(feature = "ed448-goldilocks-plus")]
scalar_impl!(ed448_goldilocks_plus::Scalar);
#[cfg(feature = "curve25519")]
scalar_impl!(crate::curve25519::WrappedScalar);
#[cfg(feature = "bls12_381_plus")]
scalar_impl!(bls12_381_plus::Scalar);
#[cfg(feature = "blstrs_plus")]
scalar_impl!(blstrs_plus::Scalar);

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::{U1024, U128, U256, U64};
    use elliptic_curve::Field;
    use rand_core::SeedableRng;

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

    #[test]
    fn uint() {
        let res = U1024::from_field_element(k256::Scalar::MULTIPLICATIVE_GENERATOR);
        assert!(res.is_ok());
        let v = res.unwrap();
        let res = ShareIdentifier::as_field_element::<k256::Scalar>(&v);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), k256::Scalar::MULTIPLICATIVE_GENERATOR);

        let res = U256::from_field_element(k256::Scalar::ONE);
        assert!(res.is_ok());
        let v = res.unwrap();
        let res = ShareIdentifier::as_field_element::<k256::Scalar>(&v);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), k256::Scalar::ONE);

        let res = U128::from_field_element(k256::Scalar::ONE);
        assert!(res.is_ok());
        let v = res.unwrap();
        let res = ShareIdentifier::as_field_element::<k256::Scalar>(&v);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), k256::Scalar::ONE);

        let res = U64::from_field_element(k256::Scalar::MULTIPLICATIVE_GENERATOR);
        assert!(res.is_ok());
        let v = res.unwrap();
        let res = ShareIdentifier::as_field_element::<k256::Scalar>(&v);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), k256::Scalar::MULTIPLICATIVE_GENERATOR);
    }

    #[test]
    fn uint_random() {
        let mut rng = rand_chacha::ChaCha8Rng::from_entropy();
        for _ in 0..20 {
            let s = k256::Scalar::random(&mut rng);

            let res = U1024::from_field_element(s);
            assert!(res.is_ok());
            let v = res.unwrap();
            let res = ShareIdentifier::as_field_element::<k256::Scalar>(&v);
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), s);

            let res = U256::from_field_element(s);
            assert!(res.is_ok());
            let v = res.unwrap();
            let res = ShareIdentifier::as_field_element::<k256::Scalar>(&v);
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), s);
        }
    }

    #[test]
    fn modular() {
        let res = DynResidue::<4>::from_field_element(k256::Scalar::MULTIPLICATIVE_GENERATOR);
        assert!(res.is_ok());
        let v = res.unwrap();
        let res = ShareIdentifier::as_field_element::<k256::Scalar>(&v);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), k256::Scalar::MULTIPLICATIVE_GENERATOR);

        let mut buffer = [0u8; 64];
        let res = v.to_buffer(&mut buffer);
        assert!(res.is_ok());
        let res = DynResidue::<4>::from_buffer(&buffer);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), v);
    }
}
