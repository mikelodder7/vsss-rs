use super::*;
use core::fmt::{Debug, Display};
use num::{
    traits::{
        ConstOne, ConstZero, FromBytes, NumAssign, NumAssignRef, NumOps, NumRef, SaturatingAdd,
        SaturatingMul, SaturatingSub, ToBytes, ToPrimitive,
    },
    PrimInt,
};

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
            + 'static,
        const BYTES: usize,
    > Primitive<BYTES> for P
{
}
