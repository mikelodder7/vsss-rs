/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Negacyclic polynomial multiplication shared by every coefficient type.
//!
//! One Karatsuba implementation serves `R_q` (wrapping `u32`, exact modulo
//! `2^32` and therefore modulo `q = 2^29`), the integer ring (`i128`), and
//! the NTRU solver (`BigInt`).
use core::num::Wrapping;
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

impl Coeff for Wrapping<u32> {
    fn zero() -> Self {
        Wrapping(0)
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

/// Callers must bound the operands with [`fits_i128`] first.
impl Coeff for i128 {
    fn zero() -> Self {
        0
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

impl Coeff for BigInt {
    fn zero() -> Self {
        <BigInt as Zero>::zero()
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

/// The full product `a·b` in `T[x]`, of length `a.len() + b.len()`.
fn product<T: Coeff>(a: &[T], b: &[T]) -> Vec<T> {
    let n = a.len();
    let mut out = std::vec![T::zero(); n + b.len()];
    if n != b.len() || n <= KARATSUBA_THRESHOLD || !n.is_multiple_of(2) {
        for (i, ai) in a.iter().enumerate() {
            for (o, bj) in out[i..].iter_mut().zip(b) {
                o.add_assign_ref(&ai.mul_ref(bj));
            }
        }
        return out;
    }
    let m = n / 2;
    let (a0, a1) = a.split_at(m);
    let (b0, b1) = b.split_at(m);
    let z0 = product(a0, b0);
    let z2 = product(a1, b1);
    let z1 = product(&sum(a0, a1), &sum(b0, b1));
    out[..n]
        .iter_mut()
        .zip(&z0)
        .for_each(|(o, z)| o.add_assign_ref(z));
    out[2 * m..]
        .iter_mut()
        .zip(&z2)
        .for_each(|(o, z)| o.add_assign_ref(z));
    out[m..m + n]
        .iter_mut()
        .zip(z1.iter().zip(z0.iter().zip(&z2)))
        .for_each(|(o, (mid, (lo, hi)))| {
            o.add_assign_ref(mid);
            o.sub_assign_ref(lo);
            o.sub_assign_ref(hi);
        });
    out
}

/// Coefficient-wise `a + b` for equal-length slices.
fn sum<T: Coeff>(a: &[T], b: &[T]) -> Vec<T> {
    a.iter().zip(b).map(|(x, y)| x.add_ref(y)).collect()
}

/// `a·b` in `T[x]/(x^n + 1)` where `n = a.len() = b.len()`.
pub(crate) fn negacyclic_mul<T: Coeff>(a: &[T], b: &[T]) -> Vec<T> {
    let n = a.len().max(b.len());
    if n == 0 {
        return Vec::new();
    }
    let mut out = std::vec![T::zero(); n];
    for (i, c) in product(a, b).iter().enumerate() {
        let slot = &mut out[i % n];
        if (i / n).is_multiple_of(2) {
            slot.add_assign_ref(c);
        } else {
            slot.sub_assign_ref(c);
        }
    }
    out
}

/// Number of bits in `|x|`.
pub(crate) fn bits_i128(x: i128) -> u32 {
    x.unsigned_abs().bit_width()
}

/// Whether Karatsuba over `i128` cannot overflow for operands of `bits_a`
/// and `bits_b` bits and length `n`. Each Karatsuba level doubles the
/// operand sums and a product accumulates up to `n` terms, so the bound is
/// `bits_a + bits_b + 3·log2(n) + 2 < 127`.
pub(crate) fn fits_i128(bits_a: u32, bits_b: u32, n: usize) -> bool {
    let log_n = usize::BITS - n.leading_zeros();
    bits_a + bits_b + 3 * log_n + 2 < i128::BITS - 1
}

/// `a·b` in `Z[x]/(x^n + 1)`, using `i128` arithmetic when the operands are
/// small enough and big integers otherwise.
pub(crate) fn negacyclic_mul_big(a: &[BigInt], b: &[BigInt]) -> Vec<BigInt> {
    let small =
        |p: &[BigInt]| -> Option<Vec<i128>> { p.iter().map(ToPrimitive::to_i128).collect() };
    if let (Some(sa), Some(sb)) = (small(a), small(b)) {
        let max_bits = |p: &[i128]| p.iter().map(|&c| bits_i128(c)).max().unwrap_or(0);
        if fits_i128(max_bits(&sa), max_bits(&sb), a.len().max(b.len())) {
            return negacyclic_mul(&sa, &sb)
                .into_iter()
                .map(BigInt::from)
                .collect();
        }
    }
    negacyclic_mul(a, b)
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
    fn coefficient_ops_agree_for_every_type() {
        fn check<T: Coeff + PartialEq + core::fmt::Debug>(a: T, b: T, sum_ab: T, diff: T, prod: T) {
            assert_eq!(a.add_ref(&b), sum_ab);
            let mut acc = a.clone();
            acc.add_assign_ref(&b);
            assert_eq!(acc, sum_ab);
            acc.sub_assign_ref(&b);
            acc.sub_assign_ref(&b);
            assert_eq!(acc, diff);
            assert_eq!(a.mul_ref(&b), prod);
            assert_eq!(T::zero().add_ref(&a), a);
        }
        check(7i128, -3, 4, 10, -21);
        check(
            Wrapping(5u32),
            Wrapping(u32::MAX),
            Wrapping(4),
            Wrapping(6),
            Wrapping(5u32.wrapping_neg()),
        );
        check(
            BigInt::from(1u64 << 63) * 4,
            BigInt::from(2),
            BigInt::from(1u64 << 63) * 4 + 2,
            BigInt::from(1u64 << 63) * 4 - 2,
            BigInt::from(1u64 << 63) * 8,
        );
    }

    #[test]
    fn sum_and_product_match_their_definitions() {
        assert_eq!(sum(&[1i128, 2, 3], &[10, 20, 30]), std::vec![11, 22, 33]);
        // (1 + 2x)(3 + 4x) = 3 + 10x + 8x².
        assert_eq!(product(&[1i128, 2], &[3, 4]), std::vec![3, 10, 8, 0]);
        assert!(negacyclic_mul::<i128>(&[], &[]).is_empty());
    }

    #[test]
    fn i128_bound_is_conservative() {
        assert!(fits_i128(40, 40, 1024));
        assert!(!fits_i128(60, 60, 1024));
        assert_eq!(bits_i128(0), 0);
        assert_eq!(bits_i128(-8), 4);
    }
}
