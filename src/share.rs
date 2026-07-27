use super::*;
use core::{
    cmp::Ordering,
    fmt::Debug,
    hash::{Hash, Hasher},
    ops::Mul,
};
#[cfg(feature = "curve")]
use elliptic_curve::{Group, PrimeField, group::GroupEncoding};
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A share.
pub trait Share: Sized + Debug + Eq + PartialEq + Clone + Default {
    /// The identifier type for the share.
    type Identifier: ShareIdentifier;

    /// The value type for the share.
    type Value: ShareElement
        + for<'a> From<&'a Self::Identifier>
        + for<'a> Mul<&'a Self::Identifier, Output = Self::Value>;

    /// A new share with a given value
    fn with_identifier_and_value(identifier: Self::Identifier, value: Self::Value) -> Self;
    /// The identifier for this share
    fn identifier(&self) -> &Self::Identifier;
    /// The mutable identifier for this share
    fn identifier_mut(&mut self) -> &mut Self::Identifier;
    /// Serialize the share value.
    fn value(&self) -> &Self::Value;
    /// The mutable share value
    fn value_mut(&mut self) -> &mut Self::Value;
}

impl<I, V> Share for (I, V)
where
    I: ShareIdentifier,
    V: ShareElement + for<'a> From<&'a I> + for<'a> Mul<&'a I, Output = V>,
{
    type Identifier = I;
    type Value = V;

    fn with_identifier_and_value(identifier: I, value: V) -> Self {
        (identifier, value)
    }

    fn identifier(&self) -> &I {
        &self.0
    }

    fn identifier_mut(&mut self) -> &mut I {
        &mut self.0
    }

    fn value(&self) -> &V {
        &self.1
    }

    fn value_mut(&mut self) -> &mut V {
        &mut self.1
    }
}

/// A default share implementation providing named fields for the identifier and value.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DefaultShare<I, V>
where
    I: ShareIdentifier,
    V: ShareElement + for<'a> From<&'a I> + for<'a> Mul<&'a I, Output = V>,
{
    /// The share identifier
    #[cfg_attr(feature = "serde", serde(bound(serialize = "I: serde::Serialize")))]
    #[cfg_attr(
        feature = "serde",
        serde(bound(deserialize = "I: serde::Deserialize<'de>"))
    )]
    pub identifier: I,
    /// The share value
    #[cfg_attr(feature = "serde", serde(bound(serialize = "V: serde::Serialize")))]
    #[cfg_attr(
        feature = "serde",
        serde(bound(deserialize = "V: serde::Deserialize<'de>"))
    )]
    pub value: V,
}

impl<I, V> Copy for DefaultShare<I, V>
where
    I: ShareIdentifier + Copy,
    V: ShareElement + for<'a> From<&'a I> + for<'a> Mul<&'a I, Output = V> + Copy,
{
}

impl<I, V> Ord for DefaultShare<I, V>
where
    I: ShareIdentifier + Ord + PartialOrd,
    V: ShareElement + for<'a> From<&'a I> + for<'a> Mul<&'a I, Output = V>,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.identifier.cmp(&other.identifier)
    }
}

impl<I, V> PartialOrd for DefaultShare<I, V>
where
    I: ShareIdentifier + Ord + PartialOrd,
    V: ShareElement + for<'a> From<&'a I> + for<'a> Mul<&'a I, Output = V>,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<I, V> Hash for DefaultShare<I, V>
where
    I: ShareIdentifier + Hash,
    V: ShareElement + for<'a> From<&'a I> + for<'a> Mul<&'a I, Output = V>,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.identifier.hash(state);
    }
}

#[cfg(feature = "zeroize")]
impl<I, V> Zeroize for DefaultShare<I, V>
where
    I: ShareIdentifier + Zeroize,
    V: ShareElement + for<'a> From<&'a I> + for<'a> Mul<&'a I, Output = V> + Zeroize,
{
    fn zeroize(&mut self) {
        self.identifier.zeroize();
        self.value.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<I, V> ZeroizeOnDrop for DefaultShare<I, V>
where
    I: ShareIdentifier + ZeroizeOnDrop,
    V: ShareElement + for<'a> From<&'a I> + for<'a> Mul<&'a I, Output = V> + ZeroizeOnDrop,
{
}

#[cfg(feature = "curve")]
impl<F: PrimeField> From<(F, F)> for DefaultShare<IdentifierPrimeField<F>, ValuePrimeField<F>> {
    fn from((identifier, value): (F, F)) -> Self {
        Self {
            identifier: IdentifierPrimeField(identifier),
            value: IdentifierPrimeField(value),
        }
    }
}

#[cfg(feature = "curve")]
impl<F: PrimeField> From<DefaultShare<IdentifierPrimeField<F>, ValuePrimeField<F>>> for (F, F) {
    fn from(share: DefaultShare<IdentifierPrimeField<F>, ValuePrimeField<F>>) -> Self {
        (share.identifier.0, share.value.0)
    }
}

#[cfg(feature = "curve")]
impl<G: Group + GroupEncoding + Default> From<(G::Scalar, G)>
    for DefaultShare<IdentifierPrimeField<G::Scalar>, ValueGroup<G>>
{
    fn from((identifier, value): (G::Scalar, G)) -> Self {
        Self {
            identifier: IdentifierPrimeField(identifier),
            value: ValueGroup(value),
        }
    }
}

#[cfg(feature = "curve")]
impl<G: Group + GroupEncoding + Default>
    From<DefaultShare<IdentifierPrimeField<G::Scalar>, ValueGroup<G>>> for (G::Scalar, G)
{
    fn from(share: DefaultShare<IdentifierPrimeField<G::Scalar>, ValueGroup<G>>) -> Self {
        (share.identifier.0, share.value.0)
    }
}

impl<I, V> Share for DefaultShare<I, V>
where
    I: ShareIdentifier,
    V: ShareElement + for<'a> From<&'a I> + for<'a> Mul<&'a I, Output = V>,
{
    type Identifier = I;
    type Value = V;

    fn with_identifier_and_value(identifier: Self::Identifier, value: Self::Value) -> Self {
        Self { identifier, value }
    }

    fn identifier(&self) -> &Self::Identifier {
        &self.identifier
    }

    fn identifier_mut(&mut self) -> &mut Self::Identifier {
        &mut self.identifier
    }

    fn value(&self) -> &Self::Value {
        &self.value
    }

    fn value_mut(&mut self) -> &mut Self::Value {
        &mut self.value
    }
}

#[cfg(test)]
mod tests {
    use super::{DefaultShare, Share};
    use crate::{GroupShare, IdentifierPrimeField, PrimeFieldShare, ValueGroup};
    use core::hash::{Hash, Hasher};
    use k256::{ProjectivePoint, Scalar};
    use std::collections::hash_map::DefaultHasher;

    #[test]
    fn tuple_share_accessors_read_and_mutate_identifier_and_value() {
        let mut share = (
            IdentifierPrimeField(Scalar::from(1u64)),
            IdentifierPrimeField(Scalar::from(2u64)),
        );

        assert_eq!(share.identifier().0, Scalar::from(1u64));
        assert_eq!(share.value().0, Scalar::from(2u64));
        share.identifier_mut().0 = Scalar::from(3u64);
        share.value_mut().0 = Scalar::from(4u64);

        assert_eq!(share.identifier().0, Scalar::from(3u64));
        assert_eq!(share.value().0, Scalar::from(4u64));
    }

    #[test]
    fn default_share_accessors_ordering_and_hash_use_identifier() {
        let mut share = PrimeFieldShare::<Scalar>::with_identifier_and_value(
            IdentifierPrimeField(Scalar::from(1u64)),
            IdentifierPrimeField(Scalar::from(2u64)),
        );
        let larger = PrimeFieldShare::<Scalar>::with_identifier_and_value(
            IdentifierPrimeField(Scalar::from(2u64)),
            IdentifierPrimeField(Scalar::from(2u64)),
        );

        assert!(share < larger);
        share.identifier_mut().0 = Scalar::from(3u64);
        share.value_mut().0 = Scalar::from(4u64);
        assert_eq!(share.identifier().0, Scalar::from(3u64));
        assert_eq!(share.value().0, Scalar::from(4u64));

        let mut left = DefaultHasher::new();
        let mut right = DefaultHasher::new();
        share.hash(&mut left);
        share.identifier.hash(&mut right);
        assert_eq!(left.finish(), right.finish());
    }

    #[test]
    fn default_share_converts_to_and_from_field_and_group_tuples() {
        let field_share: PrimeFieldShare<Scalar> = (Scalar::from(5u64), Scalar::from(8u64)).into();
        let field_tuple: (Scalar, Scalar) = field_share.into();
        assert_eq!(field_tuple, (Scalar::from(5u64), Scalar::from(8u64)));

        let point = ProjectivePoint::GENERATOR * Scalar::from(3u64);
        let group_share: GroupShare<ProjectivePoint> = (Scalar::from(7u64), point).into();
        let group_tuple: (Scalar, ProjectivePoint) = group_share.into();
        assert_eq!(group_tuple, (Scalar::from(7u64), point));

        let named = DefaultShare {
            identifier: IdentifierPrimeField(Scalar::from(9u64)),
            value: ValueGroup(point),
        };
        assert_eq!(named.identifier().0, Scalar::from(9u64));
        assert_eq!(named.value().0, point);
    }
}
