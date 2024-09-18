use super::*;
use num::{
    PrimInt, traits::{
        NumOps, NumRef, NumAssignRef, NumAssign, SaturatingAdd, SaturatingSub, SaturatingMul,
        ConstOne, ConstZero, ToBytes, FromBytes
    },
};
use core::fmt::{Display, Debug};

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
