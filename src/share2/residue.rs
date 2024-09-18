use elliptic_curve::bigint::{
    modular::constant_mod::{Residue, ResidueParams},
    ArrayEncoding, Encoding, Uint, Zero,
};

use super::*;

/// A share identifier represented as a residue modulo known at compile time.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct ShareResidue<I: ShareIdentifier, MOD: ResidueParams<LIMBS>, const LIMBS: usize>
where
    Uint<LIMBS>: ArrayEncoding,
{
    /// The share identifier.
    pub identifier: I,
    /// The share value.
    pub value: Residue<MOD, LIMBS>,
}

impl<I: ShareIdentifier, MOD: ResidueParams<LIMBS>, const LIMBS: usize>
    From<(I, Residue<MOD, LIMBS>)> for ShareResidue<I, MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn from((identifier, value): (I, Residue<MOD, LIMBS>)) -> Self {
        Self { identifier, value }
    }
}

impl<I: ShareIdentifier, MOD: ResidueParams<LIMBS>, const LIMBS: usize>
    From<ShareResidue<I, MOD, LIMBS>> for (I, Residue<MOD, LIMBS>)
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn from(share: ShareResidue<I, MOD, LIMBS>) -> (I, Residue<MOD, LIMBS>) {
        (share.identifier, share.value)
    }
}

impl<I: ShareIdentifier, MOD: ResidueParams<LIMBS>, const LIMBS: usize> Share
    for ShareResidue<I, MOD, LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Serialization = <Uint<LIMBS> as Encoding>::Repr;
    type Identifier = I;
    type Value = Residue<MOD, LIMBS>;

    fn with_identifier_and_value(identifier: I, value: Residue<MOD, LIMBS>) -> Self {
        Self { identifier, value }
    }

    fn is_zero(&self) -> Choice {
        self.value.is_zero()
    }

    fn identifier(&self) -> &I {
        &self.identifier
    }

    fn identifier_mut(&mut self) -> &mut I {
        &mut self.identifier
    }

    fn serialize(&self) -> Self::Serialization {
        self.value.retrieve().to_be_bytes()
    }

    fn deserialize(&mut self, serialized: &Self::Serialization) -> VsssResult<()> {
        let inner = <Uint<LIMBS> as Encoding>::from_be_bytes(*serialized);
        self.value = Residue::<MOD, LIMBS>::new(&inner);
        Ok(())
    }

    fn value(&self) -> &Residue<MOD, LIMBS> {
        &self.value
    }

    fn value_mut(&mut self) -> &mut Residue<MOD, LIMBS> {
        &mut self.value
    }

    fn parse_slice(&mut self, slice: &[u8]) -> VsssResult<()> {
        if slice.len() != Uint::<LIMBS>::BYTES {
            return Err(Error::InvalidShareIdentifier);
        }
        let inner = Uint::<LIMBS>::from_be_slice(slice);
        self.value = Residue::<MOD, LIMBS>::new(&inner);
        Ok(())
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn to_vec(&self) -> Vec<u8> {
        self.value.retrieve().to_be_bytes().as_ref().to_vec()
    }
}
