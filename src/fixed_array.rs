use super::*;

/// A trait for converting a type to and from a fixed size array.
pub trait FixedArray<const LIMBS: usize> {
    /// Convert the type to a fixed size array.
    fn to_fixed_array(&self) -> [u8; LIMBS];
    /// Convert from a fixed size array to the type.
    fn from_fixed_array(array: &[u8; LIMBS]) -> Self;
}

macro_rules! impl_fixed_array {
    ($($inner:ident => $size:expr),+$(,)*) => {
        $(
            impl FixedArray<$size> for $inner {
                fn to_fixed_array(&self) -> [u8; $size] {
                    self.to_be_bytes()
                }

                fn from_fixed_array(array: &[u8; $size]) -> Self {
                    $inner::from_be_bytes(*array)
                }
            }
        )+
    };
}

impl_fixed_array!(
    u8 => 1,
    u16 => 2,
    u32 => 4,
    u64 => 8,
    u128 => 16,
    usize => USIZE_BYTES,
    i8 => 1,
    i16 => 2,
    i32 => 4,
    i64 => 8,
    i128 => 16,
    isize => ISIZE_BYTES,
);
