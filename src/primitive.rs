use super::*;
use core::{
    fmt::{Debug, Display},
    hash::Hash,
};
use num::{
    traits::{
        ConstOne, ConstZero, FromBytes, NumAssign, NumAssignRef, NumOps, NumRef, SaturatingAdd,
        SaturatingMul, SaturatingSub, ToBytes, ToPrimitive,
    },
    PrimInt,
};

#[cfg(feature = "zeroize")]
/// Placeholder for conditionally compiling in [`zeroize::DefaultIsZeroes`].
pub trait PrimitiveZeroize: zeroize::DefaultIsZeroes {}
#[cfg(not(feature = "zeroize"))]
/// Placeholder for conditionally compiling in [`zeroize::DefaultIsZeroes`].
pub trait PrimitiveZeroize {}

/// An extension trait for primitive integers that are used as share identifiers.
pub trait Primitive<const BYTES: usize>:
    Sized
    + PrimInt
    + NumOps
    + NumRef
    + NumAssignRef
    + NumAssign
    + SaturatingAdd
    + SaturatingSub
    + SaturatingMul
    + ConstOne
    + ConstZero
    + FixedArray<BYTES>
    + ToBytes
    + FromBytes<Bytes = <Self as ToBytes>::Bytes>
    + ToPrimitive
    + Copy
    + Clone
    + Default
    + Debug
    + Display
    + 'static
    + Hash
    + PrimitiveZeroize
{
}

impl<
        P: Sized
            + PrimInt
            + NumOps
            + NumRef
            + NumAssignRef
            + NumAssign
            + SaturatingAdd
            + SaturatingSub
            + SaturatingMul
            + ConstOne
            + ConstZero
            + FixedArray<BYTES>
            + ToBytes
            + FromBytes<Bytes = <Self as ToBytes>::Bytes>
            + ToPrimitive
            + Copy
            + Clone
            + Default
            + Debug
            + Display
            + 'static
            + Hash
            + PrimitiveZeroize,
        const BYTES: usize,
    > Primitive<BYTES> for P
{
}
