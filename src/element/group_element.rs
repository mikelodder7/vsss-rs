use crate::*;
use core::ops::{Add, AddAssign, Deref, DerefMut, Mul, MulAssign, Neg, Sub, SubAssign};
use crypto_bigint::modular::constant_mod::ResidueParams;
use crypto_bigint::{ArrayEncoding, Uint};
use elliptic_curve::ops::Reduce;
use rand_core::{CryptoRng, RngCore};
use zeroize::DefaultIsZeroes;

/// A share element represented as a group field element.
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct GroupElement<G: Group + GroupEncoding + Default>(pub G);

impl<G: Group + GroupEncoding + Default> Deref for GroupElement<G> {
    type Target = G;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<G: Group + GroupEncoding + Default> DerefMut for GroupElement<G> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<G: Group + GroupEncoding + Default> AsRef<G> for GroupElement<G> {
    fn as_ref(&self) -> &G {
        &self.0
    }
}

impl<G: Group + GroupEncoding + Default> AsMut<G> for GroupElement<G> {
    fn as_mut(&mut self) -> &mut G {
        &mut self.0
    }
}

impl<G: Group + GroupEncoding + Default> From<G> for GroupElement<G> {
    fn from(value: G) -> Self {
        Self(value)
    }
}

impl<G: Group + GroupEncoding + Default> Add for GroupElement<G> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl<G: Group + GroupEncoding + Default> AddAssign for GroupElement<G> {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl<G: Group + GroupEncoding + Default> Sub for GroupElement<G> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl<G: Group + GroupEncoding + Default> SubAssign for GroupElement<G> {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl<G: Group + GroupEncoding + Default> Neg for GroupElement<G> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

impl<G: Group + GroupEncoding + Default> ShareElement for GroupElement<G> {
    type Serialization = G::Repr;

    type Inner = G;

    fn random(rng: impl RngCore + CryptoRng) -> Self {
        Self(G::random(rng))
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

impl<G: Group + GroupEncoding + Default> Mul<IdentifierPrimeField<G::Scalar>> for GroupElement<G> {
    type Output = Self;

    fn mul(self, rhs: IdentifierPrimeField<G::Scalar>) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl<G: Group + GroupEncoding + Default> Mul<&IdentifierPrimeField<G::Scalar>> for GroupElement<G> {
    type Output = Self;

    fn mul(self, rhs: &IdentifierPrimeField<G::Scalar>) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl<G: Group + GroupEncoding + Default> Mul<IdentifierPrimeField<G::Scalar>> for &GroupElement<G> {
    type Output = GroupElement<G>;

    fn mul(self, rhs: IdentifierPrimeField<G::Scalar>) -> Self::Output {
        GroupElement(self.0 * rhs.0)
    }
}

impl<G: Group + GroupEncoding + Default> Mul<&IdentifierPrimeField<G::Scalar>>
    for &GroupElement<G>
{
    type Output = GroupElement<G>;

    fn mul(self, rhs: &IdentifierPrimeField<G::Scalar>) -> Self::Output {
        GroupElement(self.0 * rhs.0)
    }
}

impl<G: Group + GroupEncoding + Default> MulAssign<IdentifierPrimeField<G::Scalar>>
    for GroupElement<G>
{
    fn mul_assign(&mut self, rhs: IdentifierPrimeField<G::Scalar>) {
        self.0 *= rhs.0;
    }
}

impl<G: Group + GroupEncoding + Default> MulAssign<&IdentifierPrimeField<G::Scalar>>
    for GroupElement<G>
{
    fn mul_assign(&mut self, rhs: &IdentifierPrimeField<G::Scalar>) {
        self.0 *= rhs.0;
    }
}

impl<G: Group + GroupEncoding + Default> From<&IdentifierPrimeField<G::Scalar>>
    for GroupElement<G>
{
    fn from(id: &IdentifierPrimeField<G::Scalar>) -> Self {
        Self(G::generator() * id.0)
    }
}

impl<G: Group + GroupEncoding + Default, P: Primitive<BYTES>, const BYTES: usize>
    Mul<IdentifierPrimitive<P, BYTES>> for GroupElement<G>
{
    type Output = Self;

    fn mul(self, rhs: IdentifierPrimitive<P, BYTES>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        Self(self.0 * id.0)
    }
}

impl<G: Group + GroupEncoding + Default, P: Primitive<BYTES>, const BYTES: usize>
    Mul<&IdentifierPrimitive<P, BYTES>> for GroupElement<G>
{
    type Output = Self;

    fn mul(self, rhs: &IdentifierPrimitive<P, BYTES>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        Self(self.0 * id.0)
    }
}

impl<G: Group + GroupEncoding + Default, P: Primitive<BYTES>, const BYTES: usize>
    Mul<IdentifierPrimitive<P, BYTES>> for &GroupElement<G>
{
    type Output = GroupElement<G>;

    fn mul(self, rhs: IdentifierPrimitive<P, BYTES>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        GroupElement(self.0 * id.0)
    }
}

impl<G: Group + GroupEncoding + Default, P: Primitive<BYTES>, const BYTES: usize>
    Mul<&IdentifierPrimitive<P, BYTES>> for &GroupElement<G>
{
    type Output = GroupElement<G>;

    fn mul(self, rhs: &IdentifierPrimitive<P, BYTES>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        GroupElement(self.0 * id.0)
    }
}

impl<G: Group + GroupEncoding + Default, P: Primitive<BYTES>, const BYTES: usize>
    MulAssign<IdentifierPrimitive<P, BYTES>> for GroupElement<G>
{
    fn mul_assign(&mut self, rhs: IdentifierPrimitive<P, BYTES>) {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        self.0 *= id.0;
    }
}

impl<G: Group + GroupEncoding + Default, P: Primitive<BYTES>, const BYTES: usize>
    MulAssign<&IdentifierPrimitive<P, BYTES>> for GroupElement<G>
{
    fn mul_assign(&mut self, rhs: &IdentifierPrimitive<P, BYTES>) {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        self.0 *= id.0;
    }
}

impl<G: Group + GroupEncoding + Default, const LIMBS: usize> Mul<IdentifierUint<LIMBS>>
    for GroupElement<G>
where
    Uint<LIMBS>: ArrayEncoding,
    G::Scalar: Reduce<Uint<LIMBS>>,
{
    type Output = Self;

    fn mul(self, rhs: IdentifierUint<LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        Self(self.0 * id.0)
    }
}

impl<G: Group + GroupEncoding + Default, const LIMBS: usize> Mul<&IdentifierUint<LIMBS>>
    for GroupElement<G>
where
    Uint<LIMBS>: ArrayEncoding,
    G::Scalar: Reduce<Uint<LIMBS>>,
{
    type Output = Self;

    fn mul(self, rhs: &IdentifierUint<LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        Self(self.0 * id.0)
    }
}

impl<G: Group + GroupEncoding + Default, const LIMBS: usize> Mul<IdentifierUint<LIMBS>>
    for &GroupElement<G>
where
    Uint<LIMBS>: ArrayEncoding,
    G::Scalar: Reduce<Uint<LIMBS>>,
{
    type Output = GroupElement<G>;

    fn mul(self, rhs: IdentifierUint<LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        GroupElement(self.0 * id.0)
    }
}

impl<G: Group + GroupEncoding + Default, const LIMBS: usize> Mul<&IdentifierUint<LIMBS>>
    for &GroupElement<G>
where
    Uint<LIMBS>: ArrayEncoding,
    G::Scalar: Reduce<Uint<LIMBS>>,
{
    type Output = GroupElement<G>;

    fn mul(self, rhs: &IdentifierUint<LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        GroupElement(self.0 * id.0)
    }
}

impl<G: Group + GroupEncoding + Default, const LIMBS: usize> MulAssign<IdentifierUint<LIMBS>>
    for GroupElement<G>
where
    Uint<LIMBS>: ArrayEncoding,
    G::Scalar: Reduce<Uint<LIMBS>>,
{
    fn mul_assign(&mut self, rhs: IdentifierUint<LIMBS>) {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        self.0 *= id.0;
    }
}

impl<G: Group + GroupEncoding + Default, const LIMBS: usize> MulAssign<&IdentifierUint<LIMBS>>
    for GroupElement<G>
where
    Uint<LIMBS>: ArrayEncoding,
    G::Scalar: Reduce<Uint<LIMBS>>,
{
    fn mul_assign(&mut self, rhs: &IdentifierUint<LIMBS>) {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        self.0 *= id.0;
    }
}

impl<G: Group + GroupEncoding + Default, MOD: ResidueParams<LIMBS>, const LIMBS: usize>
    Mul<IdentifierResidue<MOD, LIMBS>> for GroupElement<G>
where
    Uint<LIMBS>: ArrayEncoding,
    G::Scalar: Reduce<Uint<LIMBS>>,
{
    type Output = Self;

    fn mul(self, rhs: IdentifierResidue<MOD, LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        Self(self.0 * id.0)
    }
}

impl<G: Group + GroupEncoding + Default, MOD: ResidueParams<LIMBS>, const LIMBS: usize>
    Mul<&IdentifierResidue<MOD, LIMBS>> for GroupElement<G>
where
    Uint<LIMBS>: ArrayEncoding,
    G::Scalar: Reduce<Uint<LIMBS>>,
{
    type Output = Self;

    fn mul(self, rhs: &IdentifierResidue<MOD, LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        Self(self.0 * id.0)
    }
}

impl<G: Group + GroupEncoding + Default, MOD: ResidueParams<LIMBS>, const LIMBS: usize>
    Mul<IdentifierResidue<MOD, LIMBS>> for &GroupElement<G>
where
    Uint<LIMBS>: ArrayEncoding,
    G::Scalar: Reduce<Uint<LIMBS>>,
{
    type Output = GroupElement<G>;

    fn mul(self, rhs: IdentifierResidue<MOD, LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        GroupElement(self.0 * id.0)
    }
}

impl<G: Group + GroupEncoding + Default, MOD: ResidueParams<LIMBS>, const LIMBS: usize>
    Mul<&IdentifierResidue<MOD, LIMBS>> for &GroupElement<G>
where
    Uint<LIMBS>: ArrayEncoding,
    G::Scalar: Reduce<Uint<LIMBS>>,
{
    type Output = GroupElement<G>;

    fn mul(self, rhs: &IdentifierResidue<MOD, LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        GroupElement(self.0 * id.0)
    }
}

impl<G: Group + GroupEncoding + Default, MOD: ResidueParams<LIMBS>, const LIMBS: usize>
    MulAssign<IdentifierResidue<MOD, LIMBS>> for GroupElement<G>
where
    Uint<LIMBS>: ArrayEncoding,
    G::Scalar: Reduce<Uint<LIMBS>>,
{
    fn mul_assign(&mut self, rhs: IdentifierResidue<MOD, LIMBS>) {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        self.0 *= id.0;
    }
}

impl<G: Group + GroupEncoding + Default, MOD: ResidueParams<LIMBS>, const LIMBS: usize>
    MulAssign<&IdentifierResidue<MOD, LIMBS>> for GroupElement<G>
where
    Uint<LIMBS>: ArrayEncoding,
    G::Scalar: Reduce<Uint<LIMBS>>,
{
    fn mul_assign(&mut self, rhs: &IdentifierResidue<MOD, LIMBS>) {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        self.0 *= id.0;
    }
}

impl<G: Group + GroupEncoding + Default + DefaultIsZeroes> DefaultIsZeroes for GroupElement<G> {}

impl<G: Group + GroupEncoding + Default> GroupElement<G> {
    /// Create the additive identity element.
    pub fn identity() -> Self {
        Self(G::identity())
    }

    /// Create the multiplicative identity element.
    pub fn generator() -> Self {
        Self(G::generator())
    }
}

#[cfg(feature = "serde")]
impl<G: Group + GroupEncoding + Default> serde::Serialize for GroupElement<G> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serdect::array::serialize_hex_lower_or_bin(&self.0.to_bytes(), s)
    }
}

#[cfg(feature = "serde")]
impl<'de, G: Group + GroupEncoding + Default> serde::Deserialize<'de> for GroupElement<G> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut repr = G::Repr::default();
        serdect::array::deserialize_hex_or_bin(repr.as_mut(), d)?;
        Option::from(G::from_bytes(&repr)).map(Self).ok_or_else(|| {
            serde::de::Error::custom("failed to deserialize group element from bytes")
        })
    }
}
