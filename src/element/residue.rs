use core::{
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut, Mul},
};
use crypto_bigint::modular::{ConstMontyForm as Residue, ConstMontyParams as ResidueParams};
use crypto_bigint::{ArrayEncoding, Encoding, Random, Uint, Zero};

use super::*;
use crate::*;

/// A share value represented as a [`Residue<MOD, LIMBS>`].
pub type ValueResidue<MOD, const LIMBS: usize> = IdentifierResidue<MOD, LIMBS>;

/// A share identifier represented as a residue modulo a modulus known at compile time.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct IdentifierResidue<MOD: ResidueParams<LIMBS>, const LIMBS: usize>(
    pub Residue<MOD, LIMBS>,
)
where
    Uint<LIMBS>: ArrayEncoding;

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> Display for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for &b in &self.0.retrieve().to_be_byte_array() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> Hash for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.retrieve().hash(state);
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> Ord for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.retrieve().cmp(&other.0.retrieve())
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> PartialOrd for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> Deref for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Target = Residue<MOD, LIMBS>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> DerefMut for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> AsRef<Residue<MOD, LIMBS>>
    for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn as_ref(&self) -> &Residue<MOD, LIMBS> {
        &self.0
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> AsMut<Residue<MOD, LIMBS>>
    for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn as_mut(&mut self) -> &mut Residue<MOD, LIMBS> {
        &mut self.0
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> From<Residue<MOD, LIMBS>>
    for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn from(value: Residue<MOD, LIMBS>) -> Self {
        Self(value)
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> From<&Residue<MOD, LIMBS>>
    for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn from(value: &Residue<MOD, LIMBS>) -> Self {
        Self(*value)
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> From<&IdentifierResidue<MOD, LIMBS>>
    for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn from(value: &IdentifierResidue<MOD, LIMBS>) -> Self {
        Self(value.0)
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> From<IdentifierResidue<MOD, LIMBS>>
    for Residue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn from(value: IdentifierResidue<MOD, LIMBS>) -> Self {
        value.0
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> Mul<&IdentifierResidue<MOD, LIMBS>>
    for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Output = IdentifierResidue<MOD, LIMBS>;

    fn mul(self, rhs: &IdentifierResidue<MOD, LIMBS>) -> Self {
        Self(Residue::<MOD, LIMBS>::mul(&self, rhs))
    }
}

#[cfg(feature = "zeroize")]
impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> zeroize::DefaultIsZeroes
    for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding + zeroize::DefaultIsZeroes,
    Residue<MOD, LIMBS>: zeroize::DefaultIsZeroes,
{
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> ShareElement for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Serialization = <Uint<LIMBS> as Encoding>::Repr;
    type Inner = Residue<MOD, LIMBS>;

    fn random(mut rng: impl CryptoRng) -> Self {
        let inner = Uint::<LIMBS>::random_from_rng(&mut rng);
        Self(Residue::<MOD, LIMBS>::new(&inner))
    }

    fn zero() -> Self {
        Self(Residue::<MOD, LIMBS>::ZERO)
    }

    fn one() -> Self {
        Self(Residue::<MOD, LIMBS>::ONE)
    }

    fn is_zero(&self) -> Choice {
        self.0.is_zero().into()
    }

    fn serialize(&self) -> Self::Serialization {
        <Uint<LIMBS> as Encoding>::to_be_bytes(&self.0.retrieve())
    }

    fn deserialize(serialized: &Self::Serialization) -> VsssResult<Self> {
        Ok(Self(Residue::<MOD, LIMBS>::new(
            &<Uint<LIMBS> as Encoding>::from_be_bytes(serialized.clone()),
        )))
    }

    fn from_slice(vec: &[u8]) -> VsssResult<Self> {
        if vec.len() != Uint::<LIMBS>::BYTES {
            return Err(Error::InvalidShareElement);
        }
        Ok(Self(Residue::<MOD, LIMBS>::new(
            &Uint::<LIMBS>::from_be_slice(vec),
        )))
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.serialize().as_ref().to_vec()
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> ShareIdentifier
    for IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn inc(&mut self, increment: &Self) {
        self.0 += increment.0;
    }

    fn invert(&self) -> VsssResult<Self> {
        Option::from(self.0.invert())
            .map(Self)
            .ok_or(Error::InvalidShareElement)
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> IdentifierResidue<MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    /// Identifier with the value 0.
    pub const ZERO: Self = Self(Residue::<MOD, LIMBS>::ZERO);
    /// Identifier with the value 1.
    pub const ONE: Self = Self(Residue::<MOD, LIMBS>::ONE);
}

#[cfg(test)]
mod tests {
    use super::{IdentifierResidue, Residue};
    use crate::{Error, ShareElement, ShareIdentifier};
    use elliptic_curve::bigint::{U64, const_monty_params};
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
        string::ToString,
    };

    const_monty_params!(TestResidueMod, U64, "000000000000000d");

    type TestResidue = IdentifierResidue<TestResidueMod, 1>;

    fn residue(value: u64) -> TestResidue {
        IdentifierResidue(Residue::<TestResidueMod, 1>::new(&U64::from(value)))
    }

    #[test]
    fn residue_identifier_share_element_methods_round_trip() {
        let identifier = residue(3);
        let serialized = identifier.serialize();

        assert_eq!(identifier.to_string(), "0000000000000003");
        assert_eq!(serialized.as_ref(), [0, 0, 0, 0, 0, 0, 0, 3]);
        assert_eq!(TestResidue::deserialize(&serialized), Ok(identifier));
        assert_eq!(TestResidue::from_slice(serialized.as_ref()), Ok(identifier));
        assert_eq!(identifier.to_vec(), serialized.as_ref());
        assert_eq!(
            TestResidue::from_slice(&[1, 2]),
            Err(Error::InvalidShareElement)
        );
        assert_eq!(TestResidue::ZERO, TestResidue::zero());
        assert_eq!(TestResidue::ONE, TestResidue::one());
        assert_eq!(TestResidue::zero().is_zero().unwrap_u8(), 1);
        assert_eq!(TestResidue::one().is_zero().unwrap_u8(), 0);
    }

    #[test]
    fn residue_identifier_ordering_hashing_conversion_and_arithmetic_work() {
        let two = residue(2);
        let three = residue(3);
        let six = residue(6);

        assert!(two < three);
        let mut hasher = DefaultHasher::new();
        two.hash(&mut hasher);
        assert_ne!(hasher.finish(), 0);
        assert_eq!(TestResidue::from(&two), two);
        assert_eq!(TestResidue::from(two.0), two);
        assert_eq!(TestResidue::from(&two.0), two);
        let inner: Residue<TestResidueMod, 1> = two.into();
        assert_eq!(TestResidue::from(inner), residue(2));
        assert_eq!(residue(2) * &three, six);

        let mut incremented = residue(12);
        incremented.inc(&residue(1));
        assert_eq!(incremented, TestResidue::zero());
        assert_eq!(TestResidue::one().invert(), Ok(TestResidue::one()));
        assert_eq!(
            TestResidue::zero().invert(),
            Err(Error::InvalidShareElement)
        );
    }
}
