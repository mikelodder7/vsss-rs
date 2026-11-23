/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Negacyclic polynomial multiplication shared by every coefficient type.
//!
//! One Karatsuba implementation serves `R_q` (wrapping `u32`, exact modulo
//! `2^32` and therefore modulo `q = 2^29`), the integer ring (`i128`), and
//! the NTRU solver (`BigInt`).
use core::ops::{Add, AddAssign, Mul, SubAssign};
use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero};
use std::vec::Vec;

/// Below this length Karatsuba falls back to schoolbook multiplication.
const KARATSUBA_THRESHOLD: usize = 32;

/// The ring operations Karatsuba needs from a coefficient.
pub(crate) trait Coeff: Clone {
    /// The additive identity.
    fn zero() -> Self;
    /// `self += other`.
    fn add_assign_ref(&mut self, other: &Self);
    /// `self -= other`.
    fn sub_assign_ref(&mut self, other: &Self);
    /// `self + other` as a new value.
    fn add_ref(&self, other: &Self) -> Self;
    /// `self * other`.
    fn mul_ref(&self, other: &Self) -> Self;
}

/// Every type with by-reference ring operations is a coefficient. For
/// `i128`, callers bound the operands with [`checked_mul_i128`] first.
impl<T> Coeff for T
where
    T: Clone + Zero + for<'a> AddAssign<&'a T> + for<'a> SubAssign<&'a T>,
    for<'a> &'a T: Add<&'a T, Output = T> + Mul<&'a T, Output = T>,
{
    fn zero() -> Self {
        <T as Zero>::zero()
    }
    fn add_assign_ref(&mut self, other: &Self) {
        *self += other;
    }
    fn sub_assign_ref(&mut self, other: &Self) {
        *self -= other;
    }
    fn add_ref(&self, other: &Self) -> Self {
        self + other
    }
    fn mul_ref(&self, other: &Self) -> Self {
        self * other
    }
}

/// Write the full product `a·b` in `T[x]` into `out`, of length
/// `a.len() + b.len()`. Karatsuba splits equal even lengths above the
/// threshold and keeps its operand sums and middle products in `scratch`,
/// which needs `4·n` slots to reach every level; with less, the remaining
/// levels are schoolbook.
fn product_into<T: Coeff>(a: &[T], b: &[T], out: &mut [T], scratch: &mut [T]) {
    let n = a.len();
    if n != b.len() || n <= KARATSUBA_THRESHOLD || !n.is_multiple_of(2) || scratch.len() < 2 * n {
        out.iter_mut().for_each(|o| *o = T::zero());
        for (i, ai) in a.iter().enumerate() {
            for (o, bj) in out[i..].iter_mut().zip(b) {
                o.add_assign_ref(&ai.mul_ref(bj));
            }
        }
        return;
    }
    let m = n / 2;
    let (a0, a1) = a.split_at(m);
    let (b0, b1) = b.split_at(m);
    let (sums, rest) = scratch.split_at_mut(n);
    let (sum_a, sum_b) = sums.split_at_mut(m);
    let (z1, rest) = rest.split_at_mut(n);
    {
        let (z0, z2) = out.split_at_mut(n);
        product_into(a0, b0, z0, rest);
        product_into(a1, b1, z2, rest);
    }
    sum_into(a0, a1, sum_a);
    sum_into(b0, b1, sum_b);
    product_into(sum_a, sum_b, z1, rest);
    // z1 − z0 − z2 is the middle term, added at x^m.
    for (mid, (lo, hi)) in z1.iter_mut().zip(out[..n].iter().zip(&out[n..])) {
        mid.sub_assign_ref(lo);
        mid.sub_assign_ref(hi);
    }
    out[m..m + n]
        .iter_mut()
        .zip(z1.iter())
        .for_each(|(o, mid)| o.add_assign_ref(mid));
}

/// Coefficient-wise `out = a + b` for equal-length slices.
fn sum_into<T: Coeff>(a: &[T], b: &[T], out: &mut [T]) {
    out.iter_mut()
        .zip(a.iter().zip(b))
        .for_each(|(o, (x, y))| *o = x.add_ref(y));
}

/// `a·b` in `T[x]/(x^n + 1)` where `n = a.len() = b.len()`.
///
/// One allocation holds the full product followed by the Karatsuba
/// workspace; the product is then folded with `x^n = −1` and the buffer
/// truncated to the result.
pub(crate) fn negacyclic_mul<T: Coeff>(a: &[T], b: &[T]) -> Vec<T> {
    let n = a.len().max(b.len());
    let full_len = a.len() + b.len();
    let mut buffer = std::vec![T::zero(); full_len + 4 * n];
    let (full, scratch) = buffer.split_at_mut(full_len);
    product_into(a, b, full, scratch);
    let (low, high) = full.split_at_mut(n);
    low.iter_mut()
        .zip(high.iter())
        .for_each(|(l, h)| l.sub_assign_ref(h));
    buffer.truncate(n);
    buffer
}

/// Number of bits in `|x|`.
fn bits_i128(x: i128) -> u32 {
    x.unsigned_abs().bit_width()
}

/// Whether Karatsuba over `i128` cannot overflow for operands of `bits_a`
/// and `bits_b` bits and length `n`. Each Karatsuba level doubles the
/// operand sums and a product accumulates up to `n` terms, so the bound is
/// `bits_a + bits_b + 3·log2(n) + 2 < 127`.
fn fits_i128(bits_a: u32, bits_b: u32, n: usize) -> bool {
    let log_n = usize::BITS - n.leading_zeros();
    bits_a + bits_b + 3 * log_n + 2 < i128::BITS - 1
}

/// `a·b` in `Z[x]/(x^n + 1)` over `i128`, or `None` if the operands are too
/// large for exact `i128` accumulation.
pub(crate) fn checked_mul_i128(a: &[i128], b: &[i128]) -> Option<Vec<i128>> {
    let max_bits = |p: &[i128]| p.iter().map(|&c| bits_i128(c)).max().unwrap_or(0);
    fits_i128(max_bits(a), max_bits(b), a.len().max(b.len())).then(|| negacyclic_mul(a, b))
}

/// `a·b` in `Z[x]/(x^n + 1)`, using `i128` arithmetic when the operands are
/// small enough and big integers otherwise.
pub(crate) fn negacyclic_mul_big(a: &[BigInt], b: &[BigInt]) -> Vec<BigInt> {
    let small =
        |p: &[BigInt]| -> Option<Vec<i128>> { p.iter().map(ToPrimitive::to_i128).collect() };
    small(a)
        .zip(small(b))
        .and_then(|(sa, sb)| checked_mul_i128(&sa, &sb))
        .map_or_else(
            || negacyclic_mul(a, b),
            |p| p.into_iter().map(BigInt::from).collect(),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    /// Schoolbook negacyclic product over `i128`, the reference.
    fn naive(a: &[i128], b: &[i128]) -> Vec<i128> {
        let n = a.len();
        let mut out = std::vec![0i128; n];
        for (i, ai) in a.iter().enumerate() {
            for (j, bj) in b.iter().enumerate() {
                let k = i + j;
                if k < n {
                    out[k] += ai * bj;
                } else {
                    out[k - n] -= ai * bj;
                }
            }
        }
        out
    }

    #[test]
    fn karatsuba_matches_schoolbook_for_every_coefficient_type() {
        let mut rng = StdRng::from_seed([7u8; 32]);
        for &n in &[1usize, 2, 33, 64, 256] {
            let a: Vec<i128> = (0..n).map(|_| i128::from(rng.random::<i32>())).collect();
            let b: Vec<i128> = (0..n).map(|_| i128::from(rng.random::<i32>())).collect();
            let expected = naive(&a, &b);
            assert_eq!(negacyclic_mul(&a, &b), expected, "i128, n = {n}");

            let big = |p: &[i128]| p.iter().map(|&c| BigInt::from(c) << 70).collect::<Vec<_>>();
            let big_expected: Vec<BigInt> =
                expected.iter().map(|&c| BigInt::from(c) << 140).collect();
            assert_eq!(
                negacyclic_mul_big(&big(&a), &big(&b)),
                big_expected,
                "BigInt, n = {n}"
            );
        }
    }

    #[test]
    fn blanket_coefficient_ops_match_the_operators() {
        let mut acc: BigInt = BigInt::from(1u64 << 63) * 4;
        assert_eq!(acc.add_ref(&BigInt::from(2)), &acc + 2);
        acc.add_assign_ref(&BigInt::from(2));
        acc.sub_assign_ref(&BigInt::from(5));
        assert_eq!(acc, BigInt::from(1u64 << 63) * 4 - 3);
        assert_eq!(acc.mul_ref(&BigInt::from(2)), &acc * 2);
        assert_eq!(<core::num::Wrapping<u32> as Coeff>::zero().0, 0);
        assert_eq!(
            core::num::Wrapping(5u32).mul_ref(&core::num::Wrapping(u32::MAX)),
            core::num::Wrapping(5u32.wrapping_neg())
        );
    }

    #[test]
    fn sum_and_product_match_their_definitions() {
        let mut out = [0i128; 3];
        sum_into(&[1, 2, 3], &[10, 20, 30], &mut out);
        assert_eq!(out, [11, 22, 33]);
        // (1 + 2x)(3 + 4x) = 3 + 10x + 8x²; stale output is overwritten.
        let mut full = [9i128; 4];
        product_into(&[1, 2], &[3, 4], &mut full, &mut []);
        assert_eq!(full, [3, 10, 8, 0]);
        assert!(negacyclic_mul::<i128>(&[], &[]).is_empty());
    }

    #[test]
    fn karatsuba_without_enough_scratch_falls_back_to_schoolbook() {
        let mut rng = StdRng::from_seed([8u8; 32]);
        let a: Vec<i128> = (0..128).map(|_| i128::from(rng.random::<i16>())).collect();
        let b: Vec<i128> = (0..128).map(|_| i128::from(rng.random::<i16>())).collect();
        let mut fast = std::vec![0i128; 256];
        product_into(&a, &b, &mut fast, &mut std::vec![0i128; 4 * 128]);
        let mut slow = std::vec![0i128; 256];
        product_into(&a, &b, &mut slow, &mut []);
        assert_eq!(fast, slow);
    }

    #[test]
    fn i128_bound_is_conservative() {
        assert!(fits_i128(40, 40, 1024));
        assert!(!fits_i128(60, 60, 1024));
        assert_eq!(bits_i128(0), 0);
        assert_eq!(bits_i128(-8), 4);
    }

    #[test]
    fn checked_mul_i128_multiplies_or_refuses_large_operands() {
        // (1 + x)(1 − x) = 1 − x² = 1 + 1 in Z[x]/(x² + 1).
        assert_eq!(checked_mul_i128(&[1, 1], &[1, -1]), Some(std::vec![2, 0]));
        let big = [1i128 << 62; 4];
        assert_eq!(checked_mul_i128(&big, &big), None);
    }
}
