/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

#[cfg(feature = "stream")]
use crate::{Error, Vec, VsssResult};
use ctutils::{Choice, CtEq};
#[cfg(feature = "stream")]
use futures_core::Stream;

#[cfg(feature = "stream")]
pub(crate) async fn collect_stream_exact<T>(
    count: usize,
    stream: impl Stream<Item = T>,
    exhausted: Error,
) -> VsssResult<Vec<T>> {
    let mut stream = core::pin::pin!(stream);
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let item = core::future::poll_fn(|cx| stream.as_mut().poll_next(cx))
            .await
            .ok_or(exhausted)?;
        items.push(item);
    }
    Ok(items)
}

/// Uniform non-zero sample in `1..=modulus` from a 32-bit RNG word.
///
/// Used by small-field share-identifier samplers (GF(256) with
/// `modulus = 255`, GF(16) with `modulus = 15`) where the zero element
/// is reserved for the secret and must never be produced. Modulo bias
/// is `(2^32 mod modulus) / 2^32` — at most ~2^-32, cryptographically
/// negligible for public identifiers.
#[inline]
pub(crate) fn uniform_nonzero_u8(bits: u32, modulus: u32) -> u8 {
    (bits % modulus + 1) as u8
}

/// Branch-free field-bounded add: returns `a + b` if the sum is in
/// `0..field_size`, otherwise `0`.
///
/// The zero return is a halt marker: `ParticipantIdGeneratorCollection::iter`
/// detects a zero identifier via `is_zero()` and ends the current
/// generator. Used by small-field `ShareIdentifier::inc` implementations
/// to terminate the sequential x-identifier stream at field exhaustion
/// instead of silently emitting duplicates (audit finding #3).
///
/// `field_size` is `u16` to cover the full `1..=256` range needed for
/// GF(256); the GF(16) caller passes `16`.
#[inline]
pub(crate) fn field_bounded_add(a: u8, b: u8, field_size: u16) -> u8 {
    let sum = a as u16 + b as u16;
    let in_range = ((sum < field_size) as u8).wrapping_neg();
    (sum as u8) & in_range
}

/// A trait for indicating in constant time whether a value is zero.
pub trait CtIsZero {
    /// Returns a [`Choice`] indicating if the value is zero.
    /// Returns 1 if the value is zero, otherwise 0.
    fn ct_is_zero(&self) -> Choice;
}

/// A trait for indicating in constant time whether a value is nonzero.
pub trait CtIsNotZero {
    /// Returns a [`Choice`] indicating if the value is not zero.
    /// Returns 1 if the value is not zero, otherwise 0.
    fn ct_is_not_zero(&self) -> Choice;
}

/// OR of every byte, zero exactly when every byte is zero.
fn or_bytes(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0, |acc, b| acc | b)
}

impl CtIsZero for &[u8] {
    fn ct_is_zero(&self) -> Choice {
        or_bytes(self).ct_is_zero()
    }
}

impl CtIsZero for [u8] {
    fn ct_is_zero(&self) -> Choice {
        or_bytes(self).ct_is_zero()
    }
}

impl CtIsNotZero for &[u8] {
    fn ct_is_not_zero(&self) -> Choice {
        or_bytes(self).ct_is_not_zero()
    }
}

impl CtIsNotZero for [u8] {
    fn ct_is_not_zero(&self) -> Choice {
        or_bytes(self).ct_is_not_zero()
    }
}

/// Implement [`CtIsZero`] and [`CtIsNotZero`] for integers by a
/// constant-time comparison with zero.
macro_rules! impl_ct_is_zero_for_integers {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl CtIsZero for $ty {
                fn ct_is_zero(&self) -> Choice {
                    self.ct_eq(&0)
                }
            }

            impl CtIsNotZero for $ty {
                fn ct_is_not_zero(&self) -> Choice {
                    self.ct_ne(&0)
                }
            }
        )+
    };
}

impl_ct_is_zero_for_integers!(u8, i8, u16, i16, u32, i32, u64, i64, usize);
#[cfg(target_pointer_width = "64")]
impl_ct_is_zero_for_integers!(u128, i128);

#[cfg(test)]
mod tests {
    use super::{CtIsNotZero, CtIsZero, field_bounded_add, or_bytes, uniform_nonzero_u8};

    #[test]
    fn uniform_nonzero_u8_maps_into_one_through_modulus() {
        assert_eq!(uniform_nonzero_u8(0, 15), 1);
        assert_eq!(uniform_nonzero_u8(14, 15), 15);
        assert_eq!(uniform_nonzero_u8(15, 15), 1);
        assert_eq!(uniform_nonzero_u8(u32::MAX, 255), 1);
    }

    #[test]
    fn field_bounded_add_returns_zero_on_exhaustion() {
        assert_eq!(field_bounded_add(1, 2, 16), 3);
        assert_eq!(field_bounded_add(14, 1, 16), 15);
        assert_eq!(field_bounded_add(15, 1, 16), 0);
        assert_eq!(field_bounded_add(255, 1, 256), 0);
    }

    #[test]
    fn or_bytes_is_zero_only_for_all_zero_input() {
        assert_eq!(or_bytes(&[]), 0);
        assert_eq!(or_bytes(&[0, 0, 0]), 0);
        assert_eq!(or_bytes(&[0, 0x80, 0x01]), 0x81);
    }

    #[test]
    fn byte_slices_report_zero_and_nonzero_in_constant_time_form() {
        let zeros = [0u8; 4];
        let nonzeros = [0u8, 0, 7, 0];
        assert_eq!(zeros.as_slice().ct_is_zero().to_u8(), 1);
        assert_eq!(zeros.as_slice().ct_is_not_zero().to_u8(), 0);
        assert_eq!(nonzeros.as_slice().ct_is_zero().to_u8(), 0);
        assert_eq!(nonzeros.as_slice().ct_is_not_zero().to_u8(), 1);
        assert_eq!(zeros[..].ct_is_zero().to_u8(), 1);
        assert_eq!(nonzeros[..].ct_is_not_zero().to_u8(), 1);
    }

    #[test]
    fn integers_report_zero_and_nonzero_in_constant_time_form() {
        macro_rules! assert_integer_zero_checks {
            ($($ty:ty => $nonzero:expr),+$(,)*) => {
                $(
                    let zero: $ty = 0;
                    let nonzero: $ty = $nonzero;
                    assert_eq!(zero.ct_is_zero().to_u8(), 1);
                    assert_eq!(zero.ct_is_not_zero().to_u8(), 0);
                    assert_eq!(nonzero.ct_is_zero().to_u8(), 0);
                    assert_eq!(nonzero.ct_is_not_zero().to_u8(), 1);
                )+
            };
        }

        assert_integer_zero_checks!(
            u8 => 7,
            i8 => -7,
            u16 => 7,
            i16 => -7,
            u32 => 7,
            i32 => -7,
            u64 => 7,
            i64 => -7,
            usize => 7,
        );

        #[cfg(target_pointer_width = "64")]
        assert_integer_zero_checks!(
            u128 => 7,
            i128 => -7,
        );
    }
}
