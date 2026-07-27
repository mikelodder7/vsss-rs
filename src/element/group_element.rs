#[cfg(feature = "bigint")]
use super::uint;
use crate::*;
use core::{
    fmt::{self, Display, Formatter},
    ops::{Add, AddAssign, Deref, DerefMut, Mul, MulAssign, Neg, Sub, SubAssign},
};
#[cfg(feature = "bigint")]
use crypto_bigint::{Encoding, modular::ConstMontyParams};
use elliptic_curve::{Group, group::GroupEncoding};
#[cfg(feature = "bigint")]
use elliptic_curve::{
    bigint::{self, ArrayEncoding, modular::ConstMontyParams as ResidueParams},
    ops::Reduce,
};
use rand_core::CryptoRng;
#[cfg(feature = "zeroize")]
use zeroize::DefaultIsZeroes;

/// A share verifier group element.
pub type ShareVerifierGroup<G> = ValueGroup<G>;

/// A share element represented as a group field element.
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct ValueGroup<G: Group + GroupEncoding + Default>(
    #[cfg_attr(feature = "curve-serde", serde(with = "elliptic_curve_tools::group"))] pub G,
);

impl<G: Group + GroupEncoding + Default> Display for ValueGroup<G> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for &b in self.0.to_bytes().as_ref() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl<G: Group + GroupEncoding + Default> Deref for ValueGroup<G> {
    type Target = G;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<G: Group + GroupEncoding + Default> DerefMut for ValueGroup<G> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<G: Group + GroupEncoding + Default> AsRef<G> for ValueGroup<G> {
    fn as_ref(&self) -> &G {
        &self.0
    }
}

impl<G: Group + GroupEncoding + Default> AsMut<G> for ValueGroup<G> {
    fn as_mut(&mut self) -> &mut G {
        &mut self.0
    }
}

impl<G: Group + GroupEncoding + Default> From<G> for ValueGroup<G> {
    fn from(value: G) -> Self {
        Self(value)
    }
}

impl<G: Group + GroupEncoding + Default> Add for ValueGroup<G> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl<G: Group + GroupEncoding + Default> AddAssign for ValueGroup<G> {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl<G: Group + GroupEncoding + Default> Sub for ValueGroup<G> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl<G: Group + GroupEncoding + Default> SubAssign for ValueGroup<G> {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl<G: Group + GroupEncoding + Default> Neg for ValueGroup<G> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

impl<G: Group + GroupEncoding + Default> ShareElement for ValueGroup<G> {
    type Serialization = G::Repr;

    type Inner = G;

    fn random(mut rng: impl CryptoRng) -> Self {
        Self(G::random(&mut rng))
    }
    fn zero() -> Self {
        Self(<G as Group>::identity())
    }

    fn one() -> Self {
        Self(<G as Group>::generator())
    }

    fn is_zero(&self) -> Choice {
        G::is_identity(self)
    }

    fn serialize(&self) -> Self::Serialization {
        self.to_bytes()
    }

    fn deserialize(serialized: &Self::Serialization) -> VsssResult<Self> {
        Option::from(G::from_bytes(serialized))
            .map(Self)
            .ok_or(Error::InvalidShareElement)
    }

    fn from_slice(vec: &[u8]) -> VsssResult<Self> {
        let mut repr = G::Repr::default();
        if vec.len() != repr.as_ref().len() {
            return Err(Error::InvalidShareElement);
        }
        repr.as_mut().copy_from_slice(vec);
        Option::from(G::from_bytes(&repr))
            .map(Self)
            .ok_or(Error::InvalidShareElement)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.to_bytes().as_ref().to_vec()
    }
}

impl<G: Group + GroupEncoding + Default> Mul<IdentifierPrimeField<G::Scalar>> for ValueGroup<G> {
    type Output = Self;

    fn mul(self, rhs: IdentifierPrimeField<G::Scalar>) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl<G: Group + GroupEncoding + Default> Mul<&IdentifierPrimeField<G::Scalar>> for ValueGroup<G> {
    type Output = Self;

    fn mul(self, rhs: &IdentifierPrimeField<G::Scalar>) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl<G: Group + GroupEncoding + Default> Mul<IdentifierPrimeField<G::Scalar>> for &ValueGroup<G> {
    type Output = ValueGroup<G>;

    fn mul(self, rhs: IdentifierPrimeField<G::Scalar>) -> Self::Output {
        ValueGroup(self.0 * rhs.0)
    }
}

impl<G: Group + GroupEncoding + Default> Mul<&IdentifierPrimeField<G::Scalar>> for &ValueGroup<G> {
    type Output = ValueGroup<G>;

    fn mul(self, rhs: &IdentifierPrimeField<G::Scalar>) -> Self::Output {
        ValueGroup(self.0 * rhs.0)
    }
}

impl<G: Group + GroupEncoding + Default> MulAssign<IdentifierPrimeField<G::Scalar>>
    for ValueGroup<G>
{
    fn mul_assign(&mut self, rhs: IdentifierPrimeField<G::Scalar>) {
        self.0 *= rhs.0;
    }
}

impl<G: Group + GroupEncoding + Default> MulAssign<&IdentifierPrimeField<G::Scalar>>
    for ValueGroup<G>
{
    fn mul_assign(&mut self, rhs: &IdentifierPrimeField<G::Scalar>) {
        self.0 *= rhs.0;
    }
}

impl<G: Group + GroupEncoding + Default> From<&IdentifierPrimeField<G::Scalar>> for ValueGroup<G> {
    fn from(id: &IdentifierPrimeField<G::Scalar>) -> Self {
        Self(G::generator() * id.0)
    }
}

#[cfg(feature = "primitive")]
impl<G: Group + GroupEncoding + Default, P: Primitive<BYTES>, const BYTES: usize>
    Mul<IdentifierPrimitive<P, BYTES>> for ValueGroup<G>
{
    type Output = Self;

    fn mul(self, rhs: IdentifierPrimitive<P, BYTES>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        Self(self.0 * id.0)
    }
}

#[cfg(feature = "primitive")]
impl<G: Group + GroupEncoding + Default, P: Primitive<BYTES>, const BYTES: usize>
    Mul<&IdentifierPrimitive<P, BYTES>> for ValueGroup<G>
{
    type Output = Self;

    fn mul(self, rhs: &IdentifierPrimitive<P, BYTES>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        Self(self.0 * id.0)
    }
}

#[cfg(feature = "primitive")]
impl<G: Group + GroupEncoding + Default, P: Primitive<BYTES>, const BYTES: usize>
    Mul<IdentifierPrimitive<P, BYTES>> for &ValueGroup<G>
{
    type Output = ValueGroup<G>;

    fn mul(self, rhs: IdentifierPrimitive<P, BYTES>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        ValueGroup(self.0 * id.0)
    }
}

#[cfg(feature = "primitive")]
impl<G: Group + GroupEncoding + Default, P: Primitive<BYTES>, const BYTES: usize>
    Mul<&IdentifierPrimitive<P, BYTES>> for &ValueGroup<G>
{
    type Output = ValueGroup<G>;

    fn mul(self, rhs: &IdentifierPrimitive<P, BYTES>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        ValueGroup(self.0 * id.0)
    }
}

#[cfg(feature = "primitive")]
impl<G: Group + GroupEncoding + Default, P: Primitive<BYTES>, const BYTES: usize>
    MulAssign<IdentifierPrimitive<P, BYTES>> for ValueGroup<G>
{
    fn mul_assign(&mut self, rhs: IdentifierPrimitive<P, BYTES>) {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        self.0 *= id.0;
    }
}

#[cfg(feature = "primitive")]
impl<G: Group + GroupEncoding + Default, P: Primitive<BYTES>, const BYTES: usize>
    MulAssign<&IdentifierPrimitive<P, BYTES>> for ValueGroup<G>
{
    fn mul_assign(&mut self, rhs: &IdentifierPrimitive<P, BYTES>) {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        self.0 *= id.0;
    }
}

#[cfg(feature = "bigint")]
impl<G: Group + GroupEncoding + Default, const LIMBS: usize> Mul<uint::IdentifierUint<LIMBS>>
    for ValueGroup<G>
where
    crypto_bigint::Uint<LIMBS>: Encoding,
    G::Scalar: Reduce<bigint::Uint<LIMBS>>,
{
    type Output = Self;

    fn mul(self, rhs: uint::IdentifierUint<LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        Self(self.0 * id.0)
    }
}

#[cfg(feature = "bigint")]
impl<G: Group + GroupEncoding + Default, const LIMBS: usize> Mul<&uint::IdentifierUint<LIMBS>>
    for ValueGroup<G>
where
    crypto_bigint::Uint<LIMBS>: Encoding,
    G::Scalar: Reduce<bigint::Uint<LIMBS>>,
{
    type Output = Self;

    fn mul(self, rhs: &uint::IdentifierUint<LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        Self(self.0 * id.0)
    }
}

#[cfg(feature = "bigint")]
impl<G: Group + GroupEncoding + Default, const LIMBS: usize> Mul<uint::IdentifierUint<LIMBS>>
    for &ValueGroup<G>
where
    crypto_bigint::Uint<LIMBS>: Encoding,
    G::Scalar: Reduce<bigint::Uint<LIMBS>>,
{
    type Output = ValueGroup<G>;

    fn mul(self, rhs: uint::IdentifierUint<LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        ValueGroup(self.0 * id.0)
    }
}

#[cfg(feature = "bigint")]
impl<G: Group + GroupEncoding + Default, const LIMBS: usize> Mul<&uint::IdentifierUint<LIMBS>>
    for &ValueGroup<G>
where
    crypto_bigint::Uint<LIMBS>: Encoding,
    G::Scalar: Reduce<bigint::Uint<LIMBS>>,
{
    type Output = ValueGroup<G>;

    fn mul(self, rhs: &uint::IdentifierUint<LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        ValueGroup(self.0 * id.0)
    }
}

#[cfg(feature = "bigint")]
impl<G: Group + GroupEncoding + Default, const LIMBS: usize> MulAssign<uint::IdentifierUint<LIMBS>>
    for ValueGroup<G>
where
    crypto_bigint::Uint<LIMBS>: Encoding,
    G::Scalar: Reduce<bigint::Uint<LIMBS>>,
{
    fn mul_assign(&mut self, rhs: uint::IdentifierUint<LIMBS>) {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        self.0 *= id.0;
    }
}

#[cfg(feature = "bigint")]
impl<G: Group + GroupEncoding + Default, const LIMBS: usize> MulAssign<&uint::IdentifierUint<LIMBS>>
    for ValueGroup<G>
where
    crypto_bigint::Uint<LIMBS>: Encoding,
    G::Scalar: Reduce<bigint::Uint<LIMBS>>,
{
    fn mul_assign(&mut self, rhs: &uint::IdentifierUint<LIMBS>) {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        self.0 *= id.0;
    }
}

#[cfg(feature = "bigint")]
impl<G: Group + GroupEncoding + Default, MOD: ConstMontyParams<LIMBS>, const LIMBS: usize>
    Mul<IdentifierConstMontyResidue<MOD, LIMBS>> for ValueGroup<G>
where
    crypto_bigint::Uint<LIMBS>: Encoding,
    G::Scalar: Reduce<bigint::Uint<LIMBS>>,
{
    type Output = Self;

    fn mul(self, rhs: IdentifierConstMontyResidue<MOD, LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        Self(self.0 * id.0)
    }
}

#[cfg(feature = "bigint")]
impl<G: Group + GroupEncoding + Default, MOD: ConstMontyParams<LIMBS>, const LIMBS: usize>
    Mul<&IdentifierConstMontyResidue<MOD, LIMBS>> for ValueGroup<G>
where
    crypto_bigint::Uint<LIMBS>: Encoding,
    G::Scalar: Reduce<bigint::Uint<LIMBS>>,
{
    type Output = Self;

    fn mul(self, rhs: &IdentifierConstMontyResidue<MOD, LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        Self(self.0 * id.0)
    }
}

#[cfg(feature = "bigint")]
impl<G: Group + GroupEncoding + Default, MOD: ConstMontyParams<LIMBS>, const LIMBS: usize>
    Mul<IdentifierConstMontyResidue<MOD, LIMBS>> for &ValueGroup<G>
where
    crypto_bigint::Uint<LIMBS>: Encoding,
    G::Scalar: Reduce<bigint::Uint<LIMBS>>,
{
    type Output = ValueGroup<G>;

    fn mul(self, rhs: IdentifierConstMontyResidue<MOD, LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        ValueGroup(self.0 * id.0)
    }
}

#[cfg(feature = "bigint")]
impl<G: Group + GroupEncoding + Default, MOD: ConstMontyParams<LIMBS>, const LIMBS: usize>
    Mul<&IdentifierConstMontyResidue<MOD, LIMBS>> for &ValueGroup<G>
where
    crypto_bigint::Uint<LIMBS>: Encoding,
    G::Scalar: Reduce<bigint::Uint<LIMBS>>,
{
    type Output = ValueGroup<G>;

    fn mul(self, rhs: &IdentifierConstMontyResidue<MOD, LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        ValueGroup(self.0 * id.0)
    }
}

#[cfg(feature = "bigint")]
impl<G: Group + GroupEncoding + Default, MOD: ConstMontyParams<LIMBS>, const LIMBS: usize>
    MulAssign<IdentifierConstMontyResidue<MOD, LIMBS>> for ValueGroup<G>
where
    crypto_bigint::Uint<LIMBS>: Encoding,
    G::Scalar: Reduce<bigint::Uint<LIMBS>>,
{
    fn mul_assign(&mut self, rhs: IdentifierConstMontyResidue<MOD, LIMBS>) {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        self.0 *= id.0;
    }
}

#[cfg(feature = "bigint")]
impl<G: Group + GroupEncoding + Default, MOD: ConstMontyParams<LIMBS>, const LIMBS: usize>
    MulAssign<&IdentifierConstMontyResidue<MOD, LIMBS>> for ValueGroup<G>
where
    crypto_bigint::Uint<LIMBS>: Encoding,
    G::Scalar: Reduce<bigint::Uint<LIMBS>>,
{
    fn mul_assign(&mut self, rhs: &IdentifierConstMontyResidue<MOD, LIMBS>) {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        self.0 *= id.0;
    }
}

#[cfg(feature = "bigint")]
impl<G: Group + GroupEncoding + Default, MOD: ResidueParams<LIMBS>, const LIMBS: usize>
    Mul<IdentifierResidue<MOD, LIMBS>> for ValueGroup<G>
where
    bigint::Uint<LIMBS>: ArrayEncoding,
    G::Scalar: Reduce<bigint::Uint<LIMBS>>,
{
    type Output = Self;

    fn mul(self, rhs: IdentifierResidue<MOD, LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        Self(self.0 * id.0)
    }
}

#[cfg(feature = "bigint")]
impl<G: Group + GroupEncoding + Default, MOD: ResidueParams<LIMBS>, const LIMBS: usize>
    Mul<&IdentifierResidue<MOD, LIMBS>> for ValueGroup<G>
where
    bigint::Uint<LIMBS>: ArrayEncoding,
    G::Scalar: Reduce<bigint::Uint<LIMBS>>,
{
    type Output = Self;

    fn mul(self, rhs: &IdentifierResidue<MOD, LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        Self(self.0 * id.0)
    }
}

#[cfg(feature = "bigint")]
impl<G: Group + GroupEncoding + Default, MOD: ResidueParams<LIMBS>, const LIMBS: usize>
    Mul<IdentifierResidue<MOD, LIMBS>> for &ValueGroup<G>
where
    bigint::Uint<LIMBS>: ArrayEncoding,
    G::Scalar: Reduce<bigint::Uint<LIMBS>>,
{
    type Output = ValueGroup<G>;

    fn mul(self, rhs: IdentifierResidue<MOD, LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        ValueGroup(self.0 * id.0)
    }
}

#[cfg(feature = "bigint")]
impl<G: Group + GroupEncoding + Default, MOD: ResidueParams<LIMBS>, const LIMBS: usize>
    Mul<&IdentifierResidue<MOD, LIMBS>> for &ValueGroup<G>
where
    bigint::Uint<LIMBS>: ArrayEncoding,
    G::Scalar: Reduce<bigint::Uint<LIMBS>>,
{
    type Output = ValueGroup<G>;

    fn mul(self, rhs: &IdentifierResidue<MOD, LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        ValueGroup(self.0 * id.0)
    }
}

#[cfg(feature = "bigint")]
impl<G: Group + GroupEncoding + Default, MOD: ResidueParams<LIMBS>, const LIMBS: usize>
    MulAssign<IdentifierResidue<MOD, LIMBS>> for ValueGroup<G>
where
    bigint::Uint<LIMBS>: ArrayEncoding,
    G::Scalar: Reduce<bigint::Uint<LIMBS>>,
{
    fn mul_assign(&mut self, rhs: IdentifierResidue<MOD, LIMBS>) {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        self.0 *= id.0;
    }
}

#[cfg(feature = "bigint")]
impl<G: Group + GroupEncoding + Default, MOD: ResidueParams<LIMBS>, const LIMBS: usize>
    MulAssign<&IdentifierResidue<MOD, LIMBS>> for ValueGroup<G>
where
    bigint::Uint<LIMBS>: ArrayEncoding,
    G::Scalar: Reduce<bigint::Uint<LIMBS>>,
{
    fn mul_assign(&mut self, rhs: &IdentifierResidue<MOD, LIMBS>) {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        self.0 *= id.0;
    }
}

#[cfg(feature = "zeroize")]
impl<G: Group + GroupEncoding + Default + DefaultIsZeroes> DefaultIsZeroes for ValueGroup<G> {}

impl<G: Group + GroupEncoding + Default> ValueGroup<G> {
    /// Create the additive identity element.
    pub fn identity() -> Self {
        Self(G::identity())
    }

    /// Create the multiplicative identity element.
    pub fn generator() -> Self {
        Self(G::generator())
    }
}

#[cfg(test)]
mod tests {
    use super::ValueGroup;
    use crate::{
        Error, IdentifierConstMontyResidue, IdentifierPrimeField, IdentifierPrimitive,
        IdentifierResidue, ShareElement,
    };
    use core::ops::{Mul, MulAssign};
    use crypto_bigint::{U256 as CryptoU256, const_monty_params};
    use elliptic_curve::bigint::{U256 as EcU256, const_monty_params as ec_const_monty_params};
    use k256::{ProjectivePoint, Scalar};
    use std::{format, string::ToString};

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

    fn generator() -> ValueGroup<ProjectivePoint> {
        ValueGroup(ProjectivePoint::GENERATOR)
    }

    #[test]
    fn group_share_element_methods_round_trip() {
        let point = generator();
        let serialized = point.serialize();
        let serialized_bytes: &[u8] = serialized.as_ref();

        assert_eq!(point.to_string(), hex::encode(serialized_bytes));
        assert_eq!(format!("{point}"), hex::encode(serialized_bytes));
        assert_eq!(
            ValueGroup::<ProjectivePoint>::deserialize(&serialized),
            Ok(point)
        );
        assert_eq!(
            ValueGroup::<ProjectivePoint>::from_slice(serialized_bytes),
            Ok(point)
        );
        assert_eq!(point.to_vec(), serialized_bytes);
        assert_eq!(
            ValueGroup::<ProjectivePoint>::from_slice(&[1, 2]),
            Err(Error::InvalidShareElement)
        );
        assert_eq!(
            ValueGroup::<ProjectivePoint>::zero().is_zero().unwrap_u8(),
            1
        );
        assert_eq!(ValueGroup::<ProjectivePoint>::one(), point);
        assert_eq!(
            ValueGroup::<ProjectivePoint>::identity(),
            ValueGroup::zero()
        );
        assert_eq!(ValueGroup::<ProjectivePoint>::generator(), point);
    }

    #[test]
    fn group_reference_access_add_sub_neg_and_prime_field_scalars_work() {
        let generator = generator();
        let two = IdentifierPrimeField(Scalar::from(2u64));
        let three = IdentifierPrimeField(Scalar::from(3u64));
        let twice = ValueGroup(ProjectivePoint::GENERATOR * Scalar::from(2u64));
        let thrice = ValueGroup(ProjectivePoint::GENERATOR * Scalar::from(3u64));

        assert_eq!(*generator.as_ref(), ProjectivePoint::GENERATOR);
        let mut mutable = ValueGroup(ProjectivePoint::IDENTITY);
        *mutable.as_mut() = ProjectivePoint::GENERATOR;
        assert_eq!(mutable, generator);
        assert_eq!(ValueGroup::from(ProjectivePoint::GENERATOR), generator);
        assert_eq!(generator + twice, thrice);
        assert_eq!(thrice - generator, twice);
        assert_eq!(-generator + generator, ValueGroup::identity());
        assert_eq!(generator * two, twice);
        assert_eq!(
            <ValueGroup<ProjectivePoint> as Mul<&IdentifierPrimeField<Scalar>>>::mul(
                generator, &three
            ),
            thrice
        );
        assert_eq!(
            <&ValueGroup<ProjectivePoint> as Mul<IdentifierPrimeField<Scalar>>>::mul(
                &generator, two
            ),
            twice
        );
        assert_eq!(
            <&ValueGroup<ProjectivePoint> as Mul<&IdentifierPrimeField<Scalar>>>::mul(
                &generator, &three
            ),
            thrice
        );

        mutable += generator;
        mutable -= generator;
        assert_eq!(mutable, generator);
        mutable *= two;
        assert_eq!(mutable, twice);
        <ValueGroup<ProjectivePoint> as MulAssign<&IdentifierPrimeField<Scalar>>>::mul_assign(
            &mut mutable,
            &three,
        );
        assert_eq!(
            mutable,
            ValueGroup(ProjectivePoint::GENERATOR * Scalar::from(6u64))
        );
        assert_eq!(ValueGroup::<ProjectivePoint>::from(&three), thrice);
    }

    #[test]
    fn group_multiplies_with_supported_identifier_wrappers() {
        let generator = generator();
        let primitive = IdentifierPrimitive::<u16, 2>(4);
        let expected4 = ValueGroup(ProjectivePoint::GENERATOR * Scalar::from(4u64));
        let expected6 = ValueGroup(ProjectivePoint::GENERATOR * Scalar::from(6u64));
        let expected7 = ValueGroup(ProjectivePoint::GENERATOR * Scalar::from(7u64));
        let expected8 = ValueGroup(ProjectivePoint::GENERATOR * Scalar::from(8u64));
        let crypto_uint = crate::element::uint::IdentifierUint::<4>::from_slice(
            CryptoU256::from(6u64).to_be_bytes().as_ref(),
        )
        .unwrap();
        let residue = IdentifierResidue::<EcResidueMod, 4>::from_slice(
            EcU256::from(7u64).to_be_bytes().as_ref(),
        )
        .unwrap();
        let const_monty = IdentifierConstMontyResidue::<CryptoResidueMod, 4>::from_slice(
            CryptoU256::from(8u64).to_be_bytes().as_ref(),
        )
        .unwrap();

        assert_eq!(generator * primitive, expected4);
        assert_eq!(
            <ValueGroup<ProjectivePoint> as Mul<&IdentifierPrimitive<u16, 2>>>::mul(
                generator, &primitive
            ),
            expected4
        );
        assert_eq!(
            <&ValueGroup<ProjectivePoint> as Mul<IdentifierPrimitive<u16, 2>>>::mul(
                &generator, primitive
            ),
            expected4
        );
        assert_eq!(
            <&ValueGroup<ProjectivePoint> as Mul<&IdentifierPrimitive<u16, 2>>>::mul(
                &generator, &primitive
            ),
            expected4
        );

        let mut assigned = generator;
        assigned *= primitive;
        assert_eq!(assigned, expected4);
        <ValueGroup<ProjectivePoint> as MulAssign<&IdentifierPrimitive<u16, 2>>>::mul_assign(
            &mut assigned,
            &primitive,
        );
        assert_eq!(
            assigned,
            ValueGroup(ProjectivePoint::GENERATOR * Scalar::from(16u64))
        );

        assert_eq!(generator * crypto_uint, expected6);
        assert_eq!(
            <ValueGroup<ProjectivePoint> as Mul<&crate::element::uint::IdentifierUint<4>>>::mul(
                generator,
                &crypto_uint
            ),
            expected6
        );
        assert_eq!(
            <&ValueGroup<ProjectivePoint> as Mul<crate::element::uint::IdentifierUint<4>>>::mul(
                &generator,
                crypto_uint
            ),
            expected6
        );
        assert_eq!(
            <&ValueGroup<ProjectivePoint> as Mul<&crate::element::uint::IdentifierUint<4>>>::mul(
                &generator,
                &crypto_uint
            ),
            expected6
        );
        let mut assigned = generator;
        assigned *= crypto_uint;
        assert_eq!(assigned, expected6);
        <ValueGroup<ProjectivePoint> as MulAssign<
            &crate::element::uint::IdentifierUint<4>,
        >>::mul_assign(&mut assigned, &crypto_uint);
        assert_eq!(
            assigned,
            ValueGroup(ProjectivePoint::GENERATOR * Scalar::from(36u64))
        );

        assert_eq!(generator * residue, expected7);
        assert_eq!(
            <ValueGroup<ProjectivePoint> as Mul<&IdentifierResidue<EcResidueMod, 4>>>::mul(
                generator, &residue
            ),
            expected7
        );
        assert_eq!(
            <&ValueGroup<ProjectivePoint> as Mul<IdentifierResidue<EcResidueMod, 4>>>::mul(
                &generator, residue
            ),
            expected7
        );
        assert_eq!(
            <&ValueGroup<ProjectivePoint> as Mul<&IdentifierResidue<EcResidueMod, 4>>>::mul(
                &generator, &residue
            ),
            expected7
        );
        let mut assigned = generator;
        assigned *= residue;
        assert_eq!(assigned, expected7);
        <ValueGroup<ProjectivePoint> as MulAssign<&IdentifierResidue<EcResidueMod, 4>>>::mul_assign(
            &mut assigned,
            &residue,
        );
        assert_eq!(
            assigned,
            ValueGroup(ProjectivePoint::GENERATOR * Scalar::from(49u64))
        );

        assert_eq!(generator * const_monty, expected8);
        assert_eq!(
            <ValueGroup<ProjectivePoint> as Mul<
                &IdentifierConstMontyResidue<CryptoResidueMod, 4>,
            >>::mul(generator, &const_monty),
            expected8
        );
        assert_eq!(
            <&ValueGroup<ProjectivePoint> as Mul<
                IdentifierConstMontyResidue<CryptoResidueMod, 4>,
            >>::mul(&generator, const_monty),
            expected8
        );
        assert_eq!(
            <&ValueGroup<ProjectivePoint> as Mul<
                &IdentifierConstMontyResidue<CryptoResidueMod, 4>,
            >>::mul(&generator, &const_monty),
            expected8
        );
        let mut assigned = generator;
        assigned *= const_monty;
        assert_eq!(assigned, expected8);
        <ValueGroup<ProjectivePoint> as MulAssign<
            &IdentifierConstMontyResidue<CryptoResidueMod, 4>,
        >>::mul_assign(&mut assigned, &const_monty);
        assert_eq!(
            assigned,
            ValueGroup(ProjectivePoint::GENERATOR * Scalar::from(64u64))
        );
    }
}
