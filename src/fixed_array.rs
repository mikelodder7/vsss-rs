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

#[cfg(test)]
mod tests {
    use super::FixedArray;
    use core::mem::size_of;

    fn assert_round_trip<T, const LIMBS: usize>(value: T)
    where
        T: FixedArray<LIMBS> + Copy + Eq + core::fmt::Debug,
    {
        let bytes = value.to_fixed_array();
        assert_eq!(T::from_fixed_array(&bytes), value);
    }

    #[test]
    fn unsigned_primitives_round_trip_as_fixed_arrays() {
        assert_round_trip::<u8, 1>(0xab);
        assert_round_trip::<u16, 2>(0xabcd);
        assert_round_trip::<u32, 4>(0xabcdef12);
        assert_round_trip::<u64, 8>(0xabcdef1234567890);
        assert_round_trip::<u128, 16>(0xabcdef1234567890fedcba0987654321);
        assert_round_trip::<usize, { size_of::<usize>() }>(usize::MAX - 7);
    }

    #[test]
    fn signed_primitives_round_trip_as_fixed_arrays() {
        assert_round_trip::<i8, 1>(-5);
        assert_round_trip::<i16, 2>(-1234);
        assert_round_trip::<i32, 4>(-12345678);
        assert_round_trip::<i64, 8>(-123456789012345);
        assert_round_trip::<i128, 16>(-123456789012345678901234567890);
        assert_round_trip::<isize, { size_of::<isize>() }>(isize::MIN + 7);
    }
}
