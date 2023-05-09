//! Sets are used for storing shares and other data associated with
//! secret sharing operations like splitting, combining, and verifying
//! Sizes greater than 32 should probably use Vec instead of fixed sizes
//! due to stack allocations
use crate::*;
use elliptic_curve::{
    ff::Field,
    generic_array::{typenum, GenericArray},
    group::GroupEncoding,
    Group, PrimeField,
};

/// Represents a readable data store for secret shares
pub trait ReadableShareSet<I: ShareIdentifier, S: Share<Identifier = I>>: AsRef<[S]> {
    /// Convert the given shares into a field element
    fn combine_to_field_element<F, C>(&self) -> VsssResult<F>
    where
        F: PrimeField,
        C: ShareSetCombiner<I, S, F, F>,
    {
        C::combine(self.as_ref(), |s| s.as_field_element())
    }

    /// Convert the given shares into a group element
    fn combine_to_group_element<G, C>(&self) -> VsssResult<G>
    where
        G: Group + GroupEncoding + Default,
        C: ShareSetCombiner<I, S, G::Scalar, G>,
    {
        C::combine(self.as_ref(), |s| s.as_group_element())
    }
}

/// Represents a data store for secret shares
pub trait WriteableShareSet<I: ShareIdentifier, S: Share<Identifier = I>>:
    ReadableShareSet<I, S> + AsMut<[S]>
{
    /// Create a new share set
    fn create(size_hint: usize) -> Self;
}

impl<I: ShareIdentifier, S: Share<Identifier = I>, B: AsRef<[S]>> ReadableShareSet<I, S> for B {}

/// A data store for reconstructing secret shares
pub trait ShareSetCombiner<I, S, F, G>: Sized + AsRef<[(F, G)]> + AsMut<[(F, G)]>
where
    I: ShareIdentifier,
    S: Share<Identifier = I>,
    F: PrimeField,
    G: Default + Copy + core::ops::AddAssign + core::ops::Mul<F, Output = G>,
{
    /// Create a new combiner
    fn create(size_hint: usize) -> Self;

    /// Combine the secret shares into a single secret
    /// using Lagrange interpolation
    fn combine<B, M>(shares: B, mut m: M) -> VsssResult<G>
    where
        B: AsRef<[S]>,
        M: FnMut(&S) -> VsssResult<G>,
    {
        let shares = shares.as_ref();
        if shares.len() < 2 {
            return Err(Error::SharingMinThreshold);
        }
        let mut values = Self::create(shares.len());
        {
            let indexer = values.as_mut();
            for (i, s) in shares.iter().enumerate() {
                if s.identifier().is_zero().into() {
                    return Err(Error::SharingInvalidIdentifier);
                }
                if s.is_zero().into() {
                    return Err(Error::InvalidShare);
                }
                let x = s.identifier().as_field_element()?;
                let y = m(s)?;
                indexer[i] = (x, y);
            }
        }
        let inner_values = &values.as_ref()[..shares.len()];
        if dup_checker(inner_values) {
            return Err(Error::SharingDuplicateIdentifier);
        }
        interpolate(inner_values)
    }
}

fn interpolate<F, S>(shares: &[(F, S)]) -> VsssResult<S>
where
    F: PrimeField,
    S: Default + Copy + core::ops::AddAssign + core::ops::Mul<F, Output = S>,
{
    let mut secret = S::default();
    // Calculate lagrange interpolation
    for (i, (x_i, s)) in shares.iter().enumerate() {
        let mut basis = F::ONE;
        for (j, (x_j, _)) in shares.iter().enumerate() {
            if i == j {
                continue;
            }

            let denom = *x_j - *x_i;
            let inv = denom.invert().unwrap();
            // x_j / (x_j - x_i) * ...
            basis *= *x_j * inv;
        }

        secret += *s * basis;
    }

    Ok(secret)
}

macro_rules! impl_ga_set {
    ($($size:ident => $num:expr),+$(,)*) => {
        $(
            impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for GenericArray<S, typenum::$size> {
               fn create(size_hint: usize) -> Self {
                   GenericArray::from(<[S; $num] as WriteableShareSet<I, S>>::create(size_hint))
               }
           }

            impl<
                I: ShareIdentifier,
                S: Share<Identifier = I>,
                F: PrimeField,
                G: Default + Copy + core::ops::AddAssign + core::ops::Mul<F, Output = G>
            > ShareSetCombiner<I, S, F, G> for GenericArray<(F, G), typenum::$size> {
                fn create(_size_hint: usize) -> Self {
                                           Self::from([(F::default(), G::default()); $num])
                                           }
            }
        )+
    };
}

impl_ga_set!(
    U2 => 2,
    U3 => 3,
    U4 => 4,
    U5 => 5,
    U6 => 6,
    U7 => 7,
    U8 => 8,
    U9 => 9,
    U10 => 10,
    U11 => 11,
    U12 => 12,
    U13 => 13,
    U14 => 14,
    U15 => 15,
    U16 => 16,
    U17 => 17,
    U18 => 18,
    U19 => 19,
    U20 => 20,
    U21 => 21,
    U22 => 22,
    U23 => 23,
    U24 => 24,
    U25 => 25,
    U26 => 26,
    U27 => 27,
    U28 => 28,
    U29 => 29,
    U30 => 30,
    U31 => 31,
    U32 => 32,
    U33 => 33, U34 => 34, U35 => 35, U36 => 36, U37 => 37,
    U38 => 38, U39 => 39, U40 => 40, U41 => 41, U42 => 42, U43 => 43, U44 => 44,
    U45 => 45, U46 => 46, U47 => 47, U48 => 48, U49 => 49, U50 => 50, U51 => 51,
    U52 => 52, U53 => 53, U54 => 54, U55 => 55, U56 => 56, U57 => 57, U58 => 58,
    U59 => 59, U60 => 60, U61 => 61, U62 => 62, U63 => 63, U64 => 64,
);

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 2] {
    fn create(_size_hint: usize) -> Self {
        [S::default(), S::default()]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 3] {
    fn create(_size_hint: usize) -> Self {
        [S::default(), S::default(), S::default()]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 4] {
    fn create(_size_hint: usize) -> Self {
        [S::default(), S::default(), S::default(), S::default()]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 5] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 6] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 7] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 8] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 9] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 10] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 11] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 12] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 13] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 14] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 15] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 16] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 17] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 18] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 19] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 20] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 21] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 22] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 23] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 24] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 25] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 26] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 27] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 28] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 29] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 30] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 31] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 32] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 33] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 34] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 35] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 36] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 37] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 38] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 39] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 40] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 41] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 42] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 43] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 44] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 45] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 46] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 47] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 48] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 49] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 50] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 51] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 52] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 53] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 54] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 55] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 56] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 57] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 58] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 59] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 60] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 61] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 62] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 63] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for [S; 64] {
    fn create(_size_hint: usize) -> Self {
        [
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
            S::default(),
        ]
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<I: ShareIdentifier, S: Share<Identifier = I>> WriteableShareSet<I, S> for Vec<S> {
    fn create(size_hint: usize) -> Self {
        vec![S::default(); size_hint]
    }
}

macro_rules! impl_share_set_combiner_for_arr {
    ($($num:expr),+$(,)*) => {
        $(
            impl<
                I: ShareIdentifier,
                S: Share<Identifier = I>,
                F: PrimeField,
                G: Default + Copy + core::ops::AddAssign + core::ops::Mul<F, Output = G>
            > ShareSetCombiner<I, S, F, G> for [(F, G); $num] {
                fn create(_size_hint: usize) -> Self {
                    [(F::default(), G::default()); $num]
                }
            }
        )+
    };
}

impl_share_set_combiner_for_arr!(
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
);

#[cfg(any(feature = "alloc", feature = "std"))]
impl<
        I: ShareIdentifier,
        S: Share<Identifier = I>,
        F: PrimeField,
        G: Default + Copy + core::ops::AddAssign + core::ops::Mul<F, Output = G>,
    > ShareSetCombiner<I, S, F, G> for Vec<(F, G)>
{
    fn create(size_hint: usize) -> Self {
        vec![(F::default(), G::default()); size_hint]
    }
}

fn dup_checker<B, F, G>(set: B) -> bool
where
    B: AsRef<[(F, G)]>,
    F: PrimeField,
    G: Default + Copy + core::ops::AddAssign + core::ops::Mul<F, Output = G>,
{
    let indexer = set.as_ref();
    for (i, (x_i, _)) in indexer.iter().enumerate() {
        for (x_j, _) in indexer.iter().skip(i + 1) {
            if x_i == x_j {
                return true;
            }
        }
    }
    false
}

/// Objects that represent the ability to verify shamir shares using
/// Feldman verifiers
pub trait FeldmanVerifierSet<G: Group>: Sized {
    /// Create a new verifier set
    fn create(size_hint: usize, generator: G) -> Self;

    /// The generator used for the verifiers
    fn generator(&self) -> G;

    /// The verifiers
    fn verifiers(&self) -> &[G];

    /// The verifiers as writeable
    fn verifiers_mut(&mut self) -> &mut [G];

    /// Verify a share with this set
    fn verify_share<I: ShareIdentifier, S: Share<Identifier = I>>(
        &self,
        share: &S,
    ) -> VsssResult<()> {
        if (share.is_zero() | share.identifier().is_zero()).into() {
            return Err(Error::InvalidShare);
        }
        if self.generator().is_identity().into() {
            return Err(Error::InvalidGenerator);
        }

        let s = share.as_field_element::<G::Scalar>()?;

        let x = share.identifier().as_field_element::<G::Scalar>()?;
        let mut i = G::Scalar::ONE;

        // FUTURE: execute this sum of products
        // c_0 * c_1^i * c_2^{i^2} ... c_t^{i^t}
        // as a constant time operation using <https://cr.yp.to/papers/pippenger.pdf>
        // or Guide to Elliptic Curve Cryptography book,
        // "Algorithm 3.48 Simultaneous multiple point multiplication"
        // without precomputing the addition but still reduces doublings

        // c_0
        let commitments = self.verifiers();
        let mut rhs = commitments[0];
        for v in &commitments[1..] {
            i *= x;

            // c_0 * c_1^i * c_2^{i^2} ... c_t^{i^t}
            rhs += *v * i;
        }

        let lhs: G = -self.generator() * s;

        let res: G = lhs + rhs;

        if res.is_identity().into() {
            Ok(())
        } else {
            Err(Error::InvalidShare)
        }
    }
}

/// Objects that represent the ability to verify shamir shares using
/// Pedersen verifiers
pub trait PedersenVerifierSet<G: Group>: Sized {
    /// Create a new verifier set
    fn create(size_hint: usize, secret_generator: G, blinder_generator: G) -> Self;

    /// The generator used for the verifiers of secrets
    fn secret_generator(&self) -> G;

    /// The generator used for the verifiers of blinders
    fn blinder_generator(&self) -> G;

    /// The verifiers
    fn verifiers(&self) -> &[G];

    /// The verifiers as writeable
    fn verifiers_mut(&mut self) -> &mut [G];

    /// Verify a share and blinder with this set
    fn verify_share_and_blinder<I: ShareIdentifier, S: Share<Identifier = I>>(
        &self,
        share: &S,
        blinder: &S,
    ) -> VsssResult<()> {
        if (share.is_zero() | blinder.is_zero() | share.identifier().is_zero()).into() {
            return Err(Error::InvalidShare);
        }
        let blind_generator = self.blinder_generator();
        let generator = self.secret_generator();

        if (generator.is_identity() | blind_generator.is_identity()).into() {
            return Err(Error::InvalidGenerator);
        }

        let secret = share.as_field_element::<G::Scalar>()?;
        let blinder = blinder.as_field_element::<G::Scalar>()?;

        let x = share.identifier().as_field_element::<G::Scalar>()?;
        let mut i = G::Scalar::ONE;

        // FUTURE: execute this sum of products
        // c_0 * c_1^i * c_2^{i^2} ... c_t^{i^t}
        // as a constant time operation using <https://cr.yp.to/papers/pippenger.pdf>
        // or Guide to Elliptic Curve Cryptography book,
        // "Algorithm 3.48 Simultaneous multiple point multiplication"
        // without precomputing the addition but still reduces doublings

        let commitments = self.verifiers();
        // c_0
        let mut rhs = commitments[0];
        for v in &commitments[1..] {
            i *= x;

            // c_0 * c_1^i * c_2^{i^2} ... c_t^{i^t}
            rhs += *v * i;
        }

        let g = (-generator) * secret;
        let h = (-blind_generator) * blinder;

        let res = rhs + g + h;

        if res.is_identity().into() {
            Ok(())
        } else {
            Err(Error::InvalidShare)
        }
    }
}

macro_rules! impl_feldman_verifier_set {
    ($($size:ident => $num:expr),+$(,)*) => {
        $(
            impl<G: Group> FeldmanVerifierSet<G> for [G; $num] {
                fn create(_size_hint: usize, generator: G) -> Self {
                    let mut t = [G::identity(); $num];
                    t[0] = generator;
                    t
                }

                fn generator(&self) -> G {
                    self[0]
                }

                fn verifiers(&self) -> &[G] {
                    &self[1..]
                }

                fn verifiers_mut(&mut self) -> &mut [G] {
                    self[1..].as_mut()
                }
            }

            impl<G: Group> FeldmanVerifierSet<G> for GenericArray<G, typenum::$size> {
                fn create(_size_hint: usize, generator: G) -> Self {
                    let mut t = [G::identity(); $num];
                    t[0] = generator;
                    GenericArray::from(t)
                }

                fn generator(&self) -> G {
                    self[0]
                }

                fn verifiers(&self) -> &[G] {
                    &self[1..]
                }

                fn verifiers_mut(&mut self) -> &mut [G] {
                    self[1..].as_mut()
                }
            }
        )+
    };
}

impl_feldman_verifier_set!(
    U3 => 3,
    U4 => 4,
    U5 => 5,
    U6 => 6,
    U7 => 7,
    U8 => 8,
    U9 => 9,
    U10 => 10,
    U11 => 11,
    U12 => 12,
    U13 => 13,
    U14 => 14,
    U15 => 15,
    U16 => 16,
    U17 => 17,
    U18 => 18,
    U19 => 19,
    U20 => 20,
    U21 => 21,
    U22 => 22,
    U23 => 23,
    U24 => 24,
    U25 => 25,
    U26 => 26,
    U27 => 27,
    U28 => 28,
    U29 => 29,
    U30 => 30,
    U31 => 31,
    U32 => 32,
    U33 => 33,
    U34 => 34,
    U35 => 35, U36 => 36, U37 => 37,
    U38 => 38, U39 => 39, U40 => 40, U41 => 41, U42 => 42, U43 => 43, U44 => 44,
    U45 => 45, U46 => 46, U47 => 47, U48 => 48, U49 => 49, U50 => 50, U51 => 51,
    U52 => 52, U53 => 53, U54 => 54, U55 => 55, U56 => 56, U57 => 57, U58 => 58,
    U59 => 59, U60 => 60, U61 => 61, U62 => 62, U63 => 63, U64 => 64,
);

#[cfg(any(feature = "alloc", feature = "std"))]
impl<G: Group> FeldmanVerifierSet<G> for Vec<G> {
    fn create(size_hint: usize, generator: G) -> Self {
        vec![generator; size_hint + 1]
    }

    fn generator(&self) -> G {
        self[0]
    }

    fn verifiers(&self) -> &[G] {
        &self[1..]
    }

    fn verifiers_mut(&mut self) -> &mut [G] {
        self[1..].as_mut()
    }
}

macro_rules! impl_pedersen_verifier_set {
    ($($size:ident => $num:expr),+$(,)*) => {
        $(
            impl<G: Group> PedersenVerifierSet<G> for [G; $num] {
                fn create(_size_hint: usize, secret_generator: G, blinder_generator: G) -> Self {
                    let mut t = [G::identity(); $num];
                    t[0] = secret_generator;
                    t[1] = blinder_generator;
                    t
                }

                fn secret_generator(&self) -> G {
                    self[0]
                }

                fn blinder_generator(&self) -> G {
                    self[1]
                }

                fn verifiers(&self) -> &[G] {
                    &self[2..]
                }

                fn verifiers_mut(&mut self) -> &mut [G] {
                    self[2..].as_mut()
                }
            }

            impl<G: Group> PedersenVerifierSet<G> for GenericArray<G, typenum::$size> {
                fn create(_size_hint: usize, secret_generator: G, blinder_generator: G) -> Self {
                    let mut t = [G::identity(); $num];
                    t[0] = secret_generator;
                    t[1] = blinder_generator;
                    GenericArray::from(t)
                }

                fn secret_generator(&self) -> G {
                    self[0]
                }

                fn blinder_generator(&self) -> G {
                    self[1]
                }

                fn verifiers(&self) -> &[G] {
                    &self[2..]
                }

                fn verifiers_mut(&mut self) -> &mut [G] {
                    self[2..].as_mut()
                }
            }
        )+
    };
}

impl_pedersen_verifier_set!(
    U4 => 4,
    U5 => 5,
    U6 => 6,
    U7 => 7,
    U8 => 8,
    U9 => 9,
    U10 => 10,
    U11 => 11,
    U12 => 12,
    U13 => 13,
    U14 => 14,
    U15 => 15,
    U16 => 16,
    U17 => 17,
    U18 => 18,
    U19 => 19,
    U20 => 20,
    U21 => 21,
    U22 => 22,
    U23 => 23,
    U24 => 24,
    U25 => 25,
    U26 => 26,
    U27 => 27,
    U28 => 28,
    U29 => 29,
    U30 => 30,
    U31 => 31,
    U32 => 32,
    U33 => 33,
    U34 => 34,
    U35 => 35, U36 => 36, U37 => 37,
    U38 => 38, U39 => 39, U40 => 40, U41 => 41, U42 => 42, U43 => 43, U44 => 44,
    U45 => 45, U46 => 46, U47 => 47, U48 => 48, U49 => 49, U50 => 50, U51 => 51,
    U52 => 52, U53 => 53, U54 => 54, U55 => 55, U56 => 56, U57 => 57, U58 => 58,
    U59 => 59, U60 => 60, U61 => 61, U62 => 62, U63 => 63, U64 => 64,
);

#[cfg(any(feature = "alloc", feature = "std"))]
impl<G: Group> PedersenVerifierSet<G> for Vec<G> {
    fn create(size_hint: usize, secret_generator: G, blinder_generator: G) -> Self {
        let mut t = vec![blinder_generator; size_hint + 2];
        t[0] = secret_generator;
        t
    }

    fn secret_generator(&self) -> G {
        self[0]
    }

    fn blinder_generator(&self) -> G {
        self[1]
    }

    fn verifiers(&self) -> &[G] {
        &self[2..]
    }

    fn verifiers_mut(&mut self) -> &mut [G] {
        self[2..].as_mut()
    }
}
