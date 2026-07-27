use super::*;
use crate::*;
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::{boxed::Box, vec::Vec};
use core::{
    fmt::{self, Display, Formatter},
    ops::{Deref, DerefMut},
};
use num::CheckedDiv;
use num::bigint::BigUint;
use num::traits::{One, Zero};
use rand_core::CryptoRng;
#[cfg(feature = "std")]
use std::{boxed::Box, vec::Vec};
use subtle::Choice;

/// A share identifier represented as a big unsigned number
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
#[repr(transparent)]
pub struct IdentifierBigUint(pub BigUint);

impl Display for IdentifierBigUint {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Deref for IdentifierBigUint {
    type Target = BigUint;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for IdentifierBigUint {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<BigUint> for IdentifierBigUint {
    fn as_ref(&self) -> &BigUint {
        &self.0
    }
}

impl AsMut<BigUint> for IdentifierBigUint {
    fn as_mut(&mut self) -> &mut BigUint {
        &mut self.0
    }
}

impl From<BigUint> for IdentifierBigUint {
    fn from(value: BigUint) -> Self {
        Self(value)
    }
}

impl From<IdentifierBigUint> for BigUint {
    fn from(value: IdentifierBigUint) -> Self {
        value.0
    }
}

impl From<Vec<u8>> for IdentifierBigUint {
    fn from(value: Vec<u8>) -> Self {
        Self::from(value.as_slice())
    }
}

impl From<&Vec<u8>> for IdentifierBigUint {
    fn from(value: &Vec<u8>) -> Self {
        Self::from(value.as_slice())
    }
}

impl From<&[u8]> for IdentifierBigUint {
    fn from(value: &[u8]) -> Self {
        Self(BigUint::from_bytes_be(value))
    }
}

impl From<Box<[u8]>> for IdentifierBigUint {
    fn from(value: Box<[u8]>) -> Self {
        Self::from(value.as_ref())
    }
}

impl From<IdentifierBigUint> for Vec<u8> {
    fn from(value: IdentifierBigUint) -> Self {
        value.0.to_bytes_be()
    }
}

impl From<&IdentifierBigUint> for Vec<u8> {
    fn from(value: &IdentifierBigUint) -> Self {
        value.0.to_bytes_be()
    }
}

impl ShareElement for IdentifierBigUint {
    type Serialization = Vec<u8>;
    type Inner = BigUint;

    fn random(mut rng: impl CryptoRng) -> Self {
        let mut buf = vec![0u8; 32];
        rng.fill_bytes(&mut buf);
        IdentifierBigUint(BigUint::from_bytes_be(&buf))
    }

    fn zero() -> Self {
        Self(BigUint::zero())
    }

    fn one() -> Self {
        Self(BigUint::one())
    }

    fn is_zero(&self) -> Choice {
        Choice::from(if self.0.is_zero() { 1 } else { 0 })
    }

    fn serialize(&self) -> Self::Serialization {
        self.0.to_bytes_be()
    }

    fn deserialize(serialized: &Self::Serialization) -> VsssResult<Self> {
        Ok(IdentifierBigUint(BigUint::from_bytes_be(serialized)))
    }

    fn from_slice(vec: &[u8]) -> VsssResult<Self> {
        Ok(IdentifierBigUint(BigUint::from_bytes_be(vec)))
    }

    fn to_vec(&self) -> Vec<u8> {
        self.0.to_bytes_be()
    }
}

impl ShareIdentifier for IdentifierBigUint {
    fn inc(&mut self, increment: &Self) {
        self.0.add_assign(&increment.0);
    }

    fn invert(&self) -> VsssResult<Self> {
        Self::one()
            .0
            .checked_div(&self.0)
            .map(IdentifierBigUint)
            .ok_or(Error::InvalidShareElement)
    }
}

#[cfg(test)]
mod tests {
    use super::IdentifierBigUint;
    use crate::{Error, ShareElement, ShareIdentifier};
    use num::bigint::BigUint;
    use num::traits::{One, Zero};
    use std::{string::ToString, vec::Vec};

    #[test]
    fn conversions_and_share_element_methods_round_trip() {
        let bytes = vec![0x01, 0x23, 0x45, 0x67];
        let from_vec = IdentifierBigUint::from(bytes.clone());
        let from_ref = IdentifierBigUint::from(&bytes);
        let from_slice = IdentifierBigUint::from(bytes.as_slice());
        let from_box = IdentifierBigUint::from(bytes.clone().into_boxed_slice());

        assert_eq!(from_vec, from_ref);
        assert_eq!(from_vec, from_slice);
        assert_eq!(from_vec, from_box);
        assert_eq!(
            from_vec.to_string(),
            BigUint::from_bytes_be(&bytes).to_string()
        );
        assert_eq!(Vec::<u8>::from(from_vec.clone()), bytes);
        assert_eq!(Vec::<u8>::from(&from_vec), bytes);
        assert_eq!(from_vec.serialize(), bytes);
        assert_eq!(IdentifierBigUint::deserialize(&bytes), Ok(from_vec.clone()));
        assert_eq!(IdentifierBigUint::from_slice(&bytes), Ok(from_vec.clone()));
        assert_eq!(from_vec.to_vec(), bytes);
        assert_eq!(IdentifierBigUint::zero().is_zero().unwrap_u8(), 1);
        assert_eq!(IdentifierBigUint::one().is_zero().unwrap_u8(), 0);

        let inner: BigUint = from_vec.clone().into();
        assert_eq!(inner, BigUint::from_bytes_be(&bytes));
    }

    #[test]
    fn identifier_increment_and_invert_follow_biguint_arithmetic() {
        let mut identifier = IdentifierBigUint(BigUint::one());
        identifier.inc(&IdentifierBigUint(BigUint::from(2u8)));
        assert_eq!(*identifier, BigUint::from(3u8));
        assert_eq!(
            IdentifierBigUint::one().invert(),
            Ok(IdentifierBigUint::one())
        );
        assert_eq!(
            IdentifierBigUint(BigUint::zero()).invert(),
            Err(Error::InvalidShareElement)
        );
    }
}
