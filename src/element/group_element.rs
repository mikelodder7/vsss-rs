use crate::*;
use core::{
    fmt::{self, Display, Formatter},
    ops::{Add, AddAssign, Deref, DerefMut, Mul, MulAssign, Neg, Sub, SubAssign},
};
use crypto_bigint::modular::constant_mod::ResidueParams;
use crypto_bigint::{ArrayEncoding, Uint};
use elliptic_curve::ops::Reduce;
use rand_core::{CryptoRng, RngCore};
use zeroize::DefaultIsZeroes;

/// A share verifier group element.
pub type ShareVerifierGroup<G> = ValueGroup<G>;

/// A share element represented as a group field element.
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct ValueGroup<G: Group + GroupEncoding + Default>(
    #[cfg_attr(feature = "serde", serde(with = "elliptic_curve_tools::group"))] pub G,
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

impl<G: Group + GroupEncoding + Default, P: Primitive<BYTES>, const BYTES: usize>
    Mul<IdentifierPrimitive<P, BYTES>> for ValueGroup<G>
{
    type Output = Self;

    fn mul(self, rhs: IdentifierPrimitive<P, BYTES>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        Self(self.0 * id.0)
    }
}

impl<G: Group + GroupEncoding + Default, P: Primitive<BYTES>, const BYTES: usize>
    Mul<&IdentifierPrimitive<P, BYTES>> for ValueGroup<G>
{
    type Output = Self;

    fn mul(self, rhs: &IdentifierPrimitive<P, BYTES>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        Self(self.0 * id.0)
    }
}

impl<G: Group + GroupEncoding + Default, P: Primitive<BYTES>, const BYTES: usize>
    Mul<IdentifierPrimitive<P, BYTES>> for &ValueGroup<G>
{
    type Output = ValueGroup<G>;

    fn mul(self, rhs: IdentifierPrimitive<P, BYTES>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        ValueGroup(self.0 * id.0)
    }
}

impl<G: Group + GroupEncoding + Default, P: Primitive<BYTES>, const BYTES: usize>
    Mul<&IdentifierPrimitive<P, BYTES>> for &ValueGroup<G>
{
    type Output = ValueGroup<G>;

    fn mul(self, rhs: &IdentifierPrimitive<P, BYTES>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        ValueGroup(self.0 * id.0)
    }
}

impl<G: Group + GroupEncoding + Default, P: Primitive<BYTES>, const BYTES: usize>
    MulAssign<IdentifierPrimitive<P, BYTES>> for ValueGroup<G>
{
    fn mul_assign(&mut self, rhs: IdentifierPrimitive<P, BYTES>) {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        self.0 *= id.0;
    }
}

impl<G: Group + GroupEncoding + Default, P: Primitive<BYTES>, const BYTES: usize>
    MulAssign<&IdentifierPrimitive<P, BYTES>> for ValueGroup<G>
{
    fn mul_assign(&mut self, rhs: &IdentifierPrimitive<P, BYTES>) {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        self.0 *= id.0;
    }
}

impl<G: Group + GroupEncoding + Default, const LIMBS: usize> Mul<IdentifierUint<LIMBS>>
    for ValueGroup<G>
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
    for ValueGroup<G>
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
    for &ValueGroup<G>
where
    Uint<LIMBS>: ArrayEncoding,
    G::Scalar: Reduce<Uint<LIMBS>>,
{
    type Output = ValueGroup<G>;

    fn mul(self, rhs: IdentifierUint<LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        ValueGroup(self.0 * id.0)
    }
}

impl<G: Group + GroupEncoding + Default, const LIMBS: usize> Mul<&IdentifierUint<LIMBS>>
    for &ValueGroup<G>
where
    Uint<LIMBS>: ArrayEncoding,
    G::Scalar: Reduce<Uint<LIMBS>>,
{
    type Output = ValueGroup<G>;

    fn mul(self, rhs: &IdentifierUint<LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        ValueGroup(self.0 * id.0)
    }
}

impl<G: Group + GroupEncoding + Default, const LIMBS: usize> MulAssign<IdentifierUint<LIMBS>>
    for ValueGroup<G>
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
    for ValueGroup<G>
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
    Mul<IdentifierResidue<MOD, LIMBS>> for ValueGroup<G>
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
    Mul<&IdentifierResidue<MOD, LIMBS>> for ValueGroup<G>
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
    Mul<IdentifierResidue<MOD, LIMBS>> for &ValueGroup<G>
where
    Uint<LIMBS>: ArrayEncoding,
    G::Scalar: Reduce<Uint<LIMBS>>,
{
    type Output = ValueGroup<G>;

    fn mul(self, rhs: IdentifierResidue<MOD, LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(&rhs);
        ValueGroup(self.0 * id.0)
    }
}

impl<G: Group + GroupEncoding + Default, MOD: ResidueParams<LIMBS>, const LIMBS: usize>
    Mul<&IdentifierResidue<MOD, LIMBS>> for &ValueGroup<G>
where
    Uint<LIMBS>: ArrayEncoding,
    G::Scalar: Reduce<Uint<LIMBS>>,
{
    type Output = ValueGroup<G>;

    fn mul(self, rhs: &IdentifierResidue<MOD, LIMBS>) -> Self::Output {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        ValueGroup(self.0 * id.0)
    }
}

impl<G: Group + GroupEncoding + Default, MOD: ResidueParams<LIMBS>, const LIMBS: usize>
    MulAssign<IdentifierResidue<MOD, LIMBS>> for ValueGroup<G>
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
    MulAssign<&IdentifierResidue<MOD, LIMBS>> for ValueGroup<G>
where
    Uint<LIMBS>: ArrayEncoding,
    G::Scalar: Reduce<Uint<LIMBS>>,
{
    fn mul_assign(&mut self, rhs: &IdentifierResidue<MOD, LIMBS>) {
        let id = IdentifierPrimeField::<G::Scalar>::from(rhs);
        self.0 *= id.0;
    }
}

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
