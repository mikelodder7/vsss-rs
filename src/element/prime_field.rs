use super::*;
use crate::*;
use core::{
    cmp::Ordering,
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut, Mul},
};
#[cfg(feature = "bigint")]
use crypto_bigint::{Encoding, modular::ConstMontyParams};
#[cfg(feature = "bigint")]
use elliptic_curve::{
    bigint::{self, ArrayEncoding, modular::ConstMontyParams as ResidueParams},
    ops::Reduce,
};

use elliptic_curve::{Field, PrimeField, scalar::IsHigh};

/// A share value represented as a [`PrimeField`].
pub type ValuePrimeField<F> = IdentifierPrimeField<F>;

/// A share identifier represented as a prime field element.
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct IdentifierPrimeField<F: PrimeField>(
    #[cfg_attr(
        feature = "curve-serde",
        serde(with = "elliptic_curve_tools::prime_field")
    )]
    pub F,
);

impl<F: PrimeField> Display for IdentifierPrimeField<F> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        for &b in self.0.to_repr().as_ref() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl<F: PrimeField> Hash for IdentifierPrimeField<F> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_repr().as_ref().hash(state);
    }
}

#[allow(clippy::non_canonical_partial_ord_impl)]
impl<F: PrimeField + IsHigh> PartialOrd for IdentifierPrimeField<F> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self.0.is_high().unwrap_u8(), other.0.is_high().unwrap_u8()) {
            (1, 1) => Some(other.0.to_repr().as_ref().cmp(self.0.to_repr().as_ref())),
            (0, 0) => Some(self.0.to_repr().as_ref().cmp(other.0.to_repr().as_ref())),
            (1, 0) => Some(Ordering::Less),
            (0, 1) => Some(Ordering::Greater),
            (_, _) => None,
        }
    }
}

impl<F: PrimeField + IsHigh> Ord for IdentifierPrimeField<F> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).expect("invalid share identifier")
    }
}

impl<F: PrimeField> Deref for IdentifierPrimeField<F> {
    type Target = F;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F: PrimeField> DerefMut for IdentifierPrimeField<F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<F: PrimeField> AsRef<F> for IdentifierPrimeField<F> {
    fn as_ref(&self) -> &F {
        &self.0
    }
}

impl<F: PrimeField> AsMut<F> for IdentifierPrimeField<F> {
    fn as_mut(&mut self) -> &mut F {
        &mut self.0
    }
}

impl<F: PrimeField> From<F> for IdentifierPrimeField<F> {
    fn from(value: F) -> Self {
        Self(value)
    }
}

impl<F: PrimeField> From<&IdentifierPrimeField<F>> for IdentifierPrimeField<F> {
    fn from(value: &IdentifierPrimeField<F>) -> Self {
        *value
    }
}

#[cfg(feature = "primitive")]
impl<F: PrimeField, P: Primitive<BYTES>, const BYTES: usize> From<&IdentifierPrimitive<P, BYTES>>
    for IdentifierPrimeField<F>
{
    fn from(value: &IdentifierPrimitive<P, BYTES>) -> Self {
        #[cfg(target_pointer_width = "64")]
        {
            if BYTES * 8 <= 64 {
                Self(F::from(value.0.to_u64().expect("invalid share identifier")))
            } else {
                Self(F::from_u128(
                    value.0.to_u128().expect("invalid share identifier"),
                ))
            }
        }
        #[cfg(target_pointer_width = "32")]
        {
            Self(F::from(value.0.to_u64().expect("invalid share identifier")))
        }
    }
}

#[cfg(feature = "bigint")]
impl<F: PrimeField + Reduce<bigint::Uint<LIMBS>>, MOD: ResidueParams<LIMBS>, const LIMBS: usize>
    From<&IdentifierResidue<MOD, LIMBS>> for IdentifierPrimeField<F>
where
    bigint::Uint<LIMBS>: ArrayEncoding,
{
    fn from(value: &IdentifierResidue<MOD, LIMBS>) -> Self {
        let t = value.0.retrieve();
        Self(F::reduce(&t))
    }
}

impl<F: PrimeField> Mul<&IdentifierPrimeField<F>> for IdentifierPrimeField<F> {
    type Output = IdentifierPrimeField<F>;

    fn mul(self, rhs: &IdentifierPrimeField<F>) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

#[cfg(feature = "primitive")]
impl<F: PrimeField, P: Primitive<BYTES>, const BYTES: usize> Mul<&IdentifierPrimitive<P, BYTES>>
    for IdentifierPrimeField<F>
{
    type Output = IdentifierPrimeField<F>;

    fn mul(self, rhs: &IdentifierPrimitive<P, BYTES>) -> Self::Output {
        let rhs = IdentifierPrimeField::<F>::from(rhs);
        Self(self.0 * rhs.0)
    }
}

#[cfg(feature = "bigint")]
impl<F: PrimeField + Reduce<bigint::Uint<LIMBS>>, MOD: ResidueParams<LIMBS>, const LIMBS: usize>
    Mul<&IdentifierResidue<MOD, LIMBS>> for IdentifierPrimeField<F>
where
    bigint::Uint<LIMBS>: ArrayEncoding,
{
    type Output = IdentifierPrimeField<F>;

    fn mul(self, rhs: &IdentifierResidue<MOD, LIMBS>) -> Self::Output {
        let rhs = IdentifierPrimeField::<F>::from(rhs);
        Self(self.0 * rhs.0)
    }
}

#[cfg(feature = "bigint")]
impl<F: PrimeField + Reduce<bigint::Uint<LIMBS>>, const LIMBS: usize>
    From<&uint::IdentifierUint<LIMBS>> for IdentifierPrimeField<F>
where
    crypto_bigint::Uint<LIMBS>: Encoding,
{
    fn from(value: &uint::IdentifierUint<LIMBS>) -> Self {
        if LIMBS * 8 != F::Repr::default().as_ref().len() {
            panic!(
                "cannot convert from IdentifierUint to IdentifierPrimeField with different limb size"
            );
        }
        Self(F::reduce(&bigint::Uint::from_words(value.0.to_words())))
    }
}

#[cfg(feature = "bigint")]
impl<F: PrimeField + Reduce<bigint::Uint<LIMBS>>, const LIMBS: usize>
    Mul<&uint::IdentifierUint<LIMBS>> for IdentifierPrimeField<F>
where
    crypto_bigint::Uint<LIMBS>: Encoding,
{
    type Output = IdentifierPrimeField<F>;

    fn mul(self, rhs: &uint::IdentifierUint<LIMBS>) -> Self::Output {
        let rhs = IdentifierPrimeField::<F>::from(rhs);
        Self(self.0 * rhs.0)
    }
}

#[cfg(feature = "bigint")]
impl<F: PrimeField + Reduce<bigint::Uint<LIMBS>>, MOD: ConstMontyParams<LIMBS>, const LIMBS: usize>
    From<&IdentifierConstMontyResidue<MOD, LIMBS>> for IdentifierPrimeField<F>
where
    crypto_bigint::Uint<LIMBS>: Encoding,
{
    fn from(value: &IdentifierConstMontyResidue<MOD, LIMBS>) -> Self {
        let t = value.0.retrieve();
        Self(F::reduce(&bigint::Uint::from_words(t.to_words())))
    }
}

#[cfg(feature = "bigint")]
impl<F: PrimeField + Reduce<bigint::Uint<LIMBS>>, MOD: ConstMontyParams<LIMBS>, const LIMBS: usize>
    Mul<&IdentifierConstMontyResidue<MOD, LIMBS>> for IdentifierPrimeField<F>
where
    crypto_bigint::Uint<LIMBS>: Encoding,
{
    type Output = IdentifierPrimeField<F>;

    fn mul(self, rhs: &IdentifierConstMontyResidue<MOD, LIMBS>) -> Self::Output {
        let rhs = IdentifierPrimeField::<F>::from(rhs);
        Self(self.0 * rhs.0)
    }
}

#[cfg(feature = "zeroize")]
impl<F: PrimeField + zeroize::DefaultIsZeroes> zeroize::DefaultIsZeroes
    for IdentifierPrimeField<F>
{
}

impl<F: PrimeField> ShareElement for IdentifierPrimeField<F> {
    type Serialization = F::Repr;
    type Inner = F;

    fn random(mut rng: impl CryptoRng) -> Self {
        Self(F::random(&mut rng))
    }

    fn zero() -> Self {
        Self(<F as Field>::ZERO)
    }

    fn one() -> Self {
        Self(<F as Field>::ONE)
    }

    fn is_zero(&self) -> Choice {
        F::is_zero(self)
    }

    fn serialize(&self) -> Self::Serialization {
        self.to_repr()
    }

    fn deserialize(serialized: &Self::Serialization) -> VsssResult<Self> {
        Option::from(F::from_repr(*serialized).map(Self)).ok_or(Error::InvalidShareElement)
    }

    fn from_slice(vec: &[u8]) -> VsssResult<Self> {
        let mut repr = F::Repr::default();
        if vec.len() != repr.as_ref().len() {
            return Err(Error::InvalidShareElement);
        }
        repr.as_mut().copy_from_slice(vec);
        Option::from(F::from_repr(repr))
            .map(Self)
            .ok_or(Error::InvalidShareElement)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.to_repr().as_ref().to_vec()
    }
}

impl<F: PrimeField> ShareIdentifier for IdentifierPrimeField<F> {
    fn inc(&mut self, increment: &Self) {
        self.0 += increment.0;
    }

    fn invert(&self) -> VsssResult<Self> {
        Option::from(self.0.invert())
            .map(Self)
            .ok_or(Error::InvalidShareElement)
    }
}

impl<F: PrimeField> IdentifierPrimeField<F> {
    /// Returns additive identity.
    pub const ZERO: Self = Self(F::ZERO);
    /// Returns multiplicative identity.
    pub const ONE: Self = Self(F::ONE);
}

#[cfg(test)]
mod tests {
    use super::IdentifierPrimeField;
    use crate::{
        Error, IdentifierConstMontyResidue, IdentifierPrimitive, IdentifierResidue, ShareElement,
        ShareIdentifier,
    };
    use core::hash::{Hash, Hasher};
    use crypto_bigint::{U256 as CryptoU256, const_monty_params};
    use elliptic_curve::bigint::{U256 as EcU256, const_monty_params as ec_const_monty_params};
    use k256::Scalar;
    use std::{collections::hash_map::DefaultHasher, string::ToString};

    ec_const_monty_params!(
        EcResidueMod,
        EcU256,
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
    );
    const_monty_params!(
        CryptoResidueMod,
        CryptoU256,
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
    );

    #[test]
    fn prime_field_share_element_methods_round_trip() {
        let identifier = IdentifierPrimeField(Scalar::from(11u64));
        let serialized = identifier.serialize();
        let serialized_bytes: &[u8] = serialized.as_ref();

        assert_eq!(identifier.to_string(), hex::encode(serialized_bytes));
        assert_eq!(
            IdentifierPrimeField::<Scalar>::deserialize(&serialized),
            Ok(identifier)
        );
        assert_eq!(
            IdentifierPrimeField::<Scalar>::from_slice(serialized_bytes),
            Ok(identifier)
        );
        assert_eq!(identifier.to_vec(), serialized_bytes);
        assert_eq!(
            IdentifierPrimeField::<Scalar>::from_slice(&[1, 2]),
            Err(Error::InvalidShareElement)
        );
        assert_eq!(
            IdentifierPrimeField::<Scalar>::ZERO,
            IdentifierPrimeField::zero()
        );
        assert_eq!(
            IdentifierPrimeField::<Scalar>::ONE,
            IdentifierPrimeField::one()
        );
        assert_eq!(
            IdentifierPrimeField::<Scalar>::zero().is_zero().unwrap_u8(),
            1
        );
        assert_eq!(
            IdentifierPrimeField::<Scalar>::one().is_zero().unwrap_u8(),
            0
        );
    }

    #[test]
    fn prime_field_reference_access_hash_order_and_arithmetic_work() {
        let mut identifier = IdentifierPrimeField(Scalar::from(2u64));
        assert_eq!(*identifier, Scalar::from(2u64));
        assert_eq!(*identifier.as_ref(), Scalar::from(2u64));
        *identifier.as_mut() = Scalar::from(3u64);
        assert_eq!(identifier.0, Scalar::from(3u64));

        let from_ref = IdentifierPrimeField::from(&identifier);
        assert_eq!(from_ref, identifier);
        assert_eq!(
            identifier * &IdentifierPrimeField(Scalar::from(4u64)),
            IdentifierPrimeField(Scalar::from(12u64))
        );
        identifier.inc(&IdentifierPrimeField(Scalar::from(2u64)));
        assert_eq!(identifier.0, Scalar::from(5u64));
        assert_eq!(
            IdentifierPrimeField::<Scalar>::one().invert(),
            Ok(IdentifierPrimeField::one())
        );
        assert_eq!(
            IdentifierPrimeField::<Scalar>::zero().invert(),
            Err(Error::InvalidShareElement)
        );
        assert!(
            IdentifierPrimeField(Scalar::from(1u64)) < IdentifierPrimeField(Scalar::from(2u64))
        );

        let mut hasher = DefaultHasher::new();
        identifier.hash(&mut hasher);
        assert_ne!(hasher.finish(), 0);
    }

    #[test]
    fn prime_field_converts_and_multiplies_with_supported_identifier_wrappers() {
        let base = IdentifierPrimeField(Scalar::from(3u64));
        let primitive = IdentifierPrimitive::<u16, 2>(4);
        assert_eq!(
            IdentifierPrimeField::<Scalar>::from(&primitive),
            IdentifierPrimeField(Scalar::from(4u64))
        );
        assert_eq!(base * &primitive, IdentifierPrimeField(Scalar::from(12u64)));

        let crypto_uint = crate::element::uint::IdentifierUint::<4>::from_slice(
            CryptoU256::from(6u64).to_be_bytes().as_ref(),
        )
        .unwrap();
        assert_eq!(
            base * &crypto_uint,
            IdentifierPrimeField(Scalar::from(18u64))
        );

        let residue = IdentifierResidue::<EcResidueMod, 4>::from_slice(
            EcU256::from(7u64).to_be_bytes().as_ref(),
        )
        .unwrap();
        assert_eq!(base * &residue, IdentifierPrimeField(Scalar::from(21u64)));

        let const_monty = IdentifierConstMontyResidue::<CryptoResidueMod, 4>::from_slice(
            CryptoU256::from(8u64).to_be_bytes().as_ref(),
        )
        .unwrap();
        assert_eq!(
            base * &const_monty,
            IdentifierPrimeField(Scalar::from(24u64))
        );
    }
}
