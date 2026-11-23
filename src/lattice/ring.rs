/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! The rings `R_q = Z_q[x]/(x^N + 1)` and `R = Z[x]/(x^N + 1)`.
use super::poly::{checked_mul_i128, negacyclic_mul};
use super::{LOG_Q, N, Q};
use crate::{Error, VsssResult};
use core::num::Wrapping;
use core::ops::{Add, Mul, Neg, Sub};
use std::vec::Vec;

/// Mask selecting the low `log2(q)` bits.
const Q_MASK: u32 = Q - 1;
/// Newton steps for inversion modulo `2^29`. The error squares each step
/// and starts in the ideal `(2, x + 1)`, whose `29·N`-th power lies in
/// `(2^29)`; `2^15 ≥ 29·1024`.
const NEWTON_STEPS: u32 = 15;

/// An element of `R_q = Z_q[x]/(x^N + 1)` with `q = 2^29`.
///
/// Coefficients are stored in `[0, q)`, constant term first.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize))]
pub struct PolyQ {
    coeffs: Vec<u32>,
}

impl PolyQ {
    /// The zero polynomial.
    pub fn zero() -> Self {
        Self {
            coeffs: std::vec![0; N],
        }
    }

    /// The constant polynomial `1`.
    pub fn one() -> Self {
        let mut p = Self::zero();
        p.coeffs[0] = 1;
        p
    }

    /// Build from exactly `N` coefficients, reducing each modulo `q`.
    pub fn from_coeffs(coeffs: &[u32]) -> VsssResult<Self> {
        Self::check_len(coeffs.len())?;
        Ok(Self::from_reduced(
            coeffs.iter().map(|c| c & Q_MASK).collect(),
        ))
    }

    /// Build from exactly `N` signed coefficients, reducing each modulo `q`.
    pub fn from_signed(coeffs: &[i64]) -> VsssResult<Self> {
        Self::check_len(coeffs.len())?;
        Ok(Self::from_reduced(
            coeffs.iter().map(|&c| reduce(c)).collect(),
        ))
    }

    /// Build from exactly `N` canonical coefficients, rejecting any outside
    /// `[0, q)` instead of reducing it.
    pub fn from_canonical(coeffs: Vec<u32>) -> VsssResult<Self> {
        Self::check_len(coeffs.len())?;
        if coeffs.iter().any(|&c| c >= Q) {
            return Err(Error::Lattice("coefficient out of range"));
        }
        Ok(Self::from_reduced(coeffs))
    }

    /// The `4·N`-byte encoding: each coefficient as a little-endian `u32`.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.coeffs.iter().flat_map(|c| c.to_le_bytes()).collect()
    }

    /// Decode [`Self::to_bytes`], rejecting a wrong length or any
    /// coefficient outside `[0, q)`.
    pub fn from_bytes(bytes: &[u8]) -> VsssResult<Self> {
        let (words, rest) = bytes.as_chunks::<4>();
        if !rest.is_empty() {
            return Err(Error::Lattice(
                "a ring element needs exactly N coefficients",
            ));
        }
        Self::from_canonical(words.iter().map(|w| u32::from_le_bytes(*w)).collect())
    }

    /// Wrap coefficients the caller has already reduced into `[0, q)`.
    pub(crate) fn from_reduced(coeffs: Vec<u32>) -> Self {
        Self { coeffs }
    }

    fn check_len(len: usize) -> VsssResult<()> {
        if len == N {
            Ok(())
        } else {
            Err(Error::Lattice(
                "a ring element needs exactly N coefficients",
            ))
        }
    }

    /// The coefficients in `[0, q)`, constant term first.
    pub fn coeffs(&self) -> &[u32] {
        &self.coeffs
    }

    /// The centered representative `[a]_q`, each coefficient in `(−q/2, q/2]`.
    pub fn centered(&self) -> Vec<i64> {
        self.coeffs.iter().map(|&c| center(c)).collect()
    }

    /// The squared Euclidean norm of the centered representative `[a]_q`.
    /// Exact: `2N` squares below `2^56` sum to less than `2^68`.
    pub fn centered_norm_sq(&self) -> u128 {
        sum_of_squares(&self.centered())
    }

    /// The adjoint `a* = a_0 − Σ_{i≥1} a_{N−i} x^i`, so `a*(x) = a(x⁻¹)`.
    pub fn adjoint(&self) -> Self {
        Self::from_reduced(adjoint(&self.coeffs, |c| c.wrapping_neg() & Q_MASK))
    }

    /// The multiplicative inverse modulo `q`. It exists exactly when `a(1)`
    /// is odd; otherwise this returns an error.
    pub fn inverse(&self) -> VsssResult<Self> {
        let two = &Self::one() + &Self::one();
        let mut inv = Self::one();
        for _ in 0..NEWTON_STEPS {
            inv = &inv * &(&two - &(self * &inv));
        }
        if self * &inv == Self::one() {
            Ok(inv)
        } else {
            Err(Error::Lattice("ring element is not invertible mod q"))
        }
    }

    fn zip_with(&self, other: &Self, op: impl Fn(u32, u32) -> u32) -> Self {
        Self::from_reduced(
            self.coeffs
                .iter()
                .zip(&other.coeffs)
                .map(|(&a, &b)| op(a, b) & Q_MASK)
                .collect(),
        )
    }
}

impl Add<&PolyQ> for &PolyQ {
    type Output = PolyQ;
    fn add(self, rhs: &PolyQ) -> PolyQ {
        self.zip_with(rhs, u32::wrapping_add)
    }
}

impl Sub<&PolyQ> for &PolyQ {
    type Output = PolyQ;
    fn sub(self, rhs: &PolyQ) -> PolyQ {
        self.zip_with(rhs, u32::wrapping_sub)
    }
}

impl Neg for &PolyQ {
    type Output = PolyQ;
    fn neg(self) -> PolyQ {
        PolyQ::from_reduced(
            self.coeffs
                .iter()
                .map(|c| c.wrapping_neg() & Q_MASK)
                .collect(),
        )
    }
}

/// Exact negacyclic product. Arithmetic is wrapping modulo `2^32`, which
/// `q = 2^29` divides, so masking the result gives the exact value mod `q`.
impl Mul<&PolyQ> for &PolyQ {
    type Output = PolyQ;
    fn mul(self, rhs: &PolyQ) -> PolyQ {
        let wrap = |p: &PolyQ| p.coeffs.iter().map(|&c| Wrapping(c)).collect::<Vec<_>>();
        PolyQ::from_reduced(
            negacyclic_mul(&wrap(self), &wrap(rhs))
                .into_iter()
                .map(|c| c.0 & Q_MASK)
                .collect(),
        )
    }
}

/// Serialized as the sequence of `N` coefficients in `[0, q)`.
#[cfg(feature = "serde")]
impl serde::Serialize for PolyQ {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.coeffs.serialize(serializer)
    }
}

/// Deserialization rejects a wrong length or a non-canonical coefficient.
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PolyQ {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let coeffs = Vec::<u32>::deserialize(deserializer)?;
        Self::from_canonical(coeffs).map_err(serde::de::Error::custom)
    }
}

impl From<&PolyZ> for PolyQ {
    fn from(p: &PolyZ) -> Self {
        Self::from_reduced(p.coeffs.iter().map(|&c| reduce(c)).collect())
    }
}

/// An element of the integer ring `R = Z[x]/(x^N + 1)` with small
/// coefficients, used for the NTRU trapdoor.
///
/// Coefficients exclude `i64::MIN`, so negation never overflows. Products
/// are computed exactly in `i128` and must fit back into `i64`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize))]
pub struct PolyZ {
    coeffs: Vec<i64>,
}

impl PolyZ {
    /// Build from exactly `N` coefficients, none equal to `i64::MIN`.
    pub fn from_coeffs(coeffs: Vec<i64>) -> VsssResult<Self> {
        PolyQ::check_len(coeffs.len())?;
        if coeffs.contains(&i64::MIN) {
            return Err(Error::Lattice("coefficient out of range"));
        }
        Ok(Self { coeffs })
    }

    /// The constant polynomial `c`.
    pub fn constant(c: i64) -> VsssResult<Self> {
        let mut coeffs = std::vec![0; N];
        coeffs[0] = c;
        Self::from_coeffs(coeffs)
    }

    /// The coefficients, constant term first.
    pub fn coeffs(&self) -> &[i64] {
        &self.coeffs
    }

    /// The adjoint `a* = a_0 − Σ_{i≥1} a_{N−i} x^i`.
    pub fn adjoint(&self) -> Self {
        Self {
            coeffs: adjoint(&self.coeffs, |c| -c),
        }
    }

    /// `a(1)`, the sum of the coefficients.
    pub fn eval_at_one(&self) -> i128 {
        self.coeffs.iter().map(|&c| i128::from(c)).sum()
    }

    /// The squared Euclidean norm of the coefficient vector, saturating at
    /// `u128::MAX`.
    pub fn norm_sq(&self) -> u128 {
        sum_of_squares(&self.coeffs)
    }

    /// `self + other`, failing on overflow.
    pub fn checked_add(&self, other: &Self) -> VsssResult<Self> {
        self.zip_checked(other, i64::checked_add)
    }

    /// `self − other`, failing on overflow.
    pub fn checked_sub(&self, other: &Self) -> VsssResult<Self> {
        self.zip_checked(other, i64::checked_sub)
    }

    /// The exact negacyclic product, failing if the operands are too large
    /// for exact `i128` accumulation or a result coefficient leaves `i64`.
    pub fn checked_mul(&self, other: &Self) -> VsssResult<Self> {
        let wide = |p: &Self| p.coeffs.iter().map(|&c| i128::from(c)).collect::<Vec<_>>();
        let coeffs = checked_mul_i128(&wide(self), &wide(other))
            .ok_or(Error::Lattice("operands too large to multiply"))?
            .into_iter()
            .map(|c| i64::try_from(c).map_err(|_| Error::Lattice("product overflow")))
            .collect::<VsssResult<Vec<_>>>()?;
        Self::from_coeffs(coeffs)
    }

    fn zip_checked(&self, other: &Self, op: impl Fn(i64, i64) -> Option<i64>) -> VsssResult<Self> {
        let coeffs = self
            .coeffs
            .iter()
            .zip(&other.coeffs)
            .map(|(&a, &b)| op(a, b).ok_or(Error::Lattice("integer overflow")))
            .collect::<VsssResult<Vec<_>>>()?;
        Self::from_coeffs(coeffs)
    }
}

/// `Σ c²` over the integers in `u128`, saturating at `u128::MAX`. Each
/// square is below `2^126`, so the sum is exact for the small coefficients
/// lattice elements hold and saturates instead of overflowing otherwise.
fn sum_of_squares(coeffs: &[i64]) -> u128 {
    coeffs
        .iter()
        .map(|&c| u128::from(c.unsigned_abs()).pow(2))
        .fold(0, u128::saturating_add)
}

/// `c mod q` in `[0, q)`. Two's complement makes masking exact for negative
/// values because `q` divides `2^64`.
fn reduce(c: i64) -> u32 {
    (c as u64 & u64::from(Q_MASK)) as u32
}

/// Map `[0, q)` to `(−q/2, q/2]`.
fn center(c: u32) -> i64 {
    let c = i64::from(c);
    if c > i64::from(Q >> 1) {
        c - (1i64 << LOG_Q)
    } else {
        c
    }
}

/// `out_0 = c_0`, `out_i = −c_{N−i}`.
fn adjoint<T: Copy>(coeffs: &[T], neg: impl Fn(T) -> T) -> Vec<T> {
    coeffs
        .iter()
        .take(1)
        .copied()
        .chain(coeffs.iter().skip(1).rev().map(|&c| neg(c)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    fn random_q(rng: &mut StdRng) -> PolyQ {
        let c: Vec<u32> = (0..N).map(|_| rng.random::<u32>()).collect();
        PolyQ::from_coeffs(&c).expect("length N")
    }

    /// Schoolbook negacyclic product with `i128` accumulation, reduced at
    /// the end: the reference for [`PolyQ`] multiplication.
    fn naive_mul_q(a: &PolyQ, b: &PolyQ) -> PolyQ {
        let mut acc = std::vec![0i128; N];
        for (i, &ai) in a.coeffs().iter().enumerate() {
            for (j, &bj) in b.coeffs().iter().enumerate() {
                let p = i128::from(ai) * i128::from(bj);
                if i + j < N {
                    acc[i + j] += p;
                } else {
                    acc[i + j - N] -= p;
                }
            }
        }
        let q = i128::from(Q);
        let c: Vec<u32> = acc.iter().map(|&v| v.rem_euclid(q) as u32).collect();
        PolyQ::from_coeffs(&c).expect("length N")
    }

    fn monomial(k: usize) -> PolyQ {
        let mut c = std::vec![0u32; N];
        c[k] = 1;
        PolyQ::from_coeffs(&c).expect("length N")
    }

    #[test]
    fn fast_mul_matches_naive_schoolbook_on_random_inputs() {
        let mut rng = StdRng::from_seed([11u8; 32]);
        for _ in 0..3 {
            let a = random_q(&mut rng);
            let b = random_q(&mut rng);
            assert_eq!(&a * &b, naive_mul_q(&a, &b));
        }
    }

    #[test]
    fn mul_wraps_negacyclically() {
        // x^(N−1) · x = x^N = −1.
        assert_eq!(&monomial(N - 1) * &monomial(1), -&PolyQ::one());
        // x^700 · x^500 = x^1200 = −x^176.
        assert_eq!(&monomial(700) * &monomial(500), -&monomial(176));
        let minus_one = (Q - 1) as i64;
        assert_eq!(
            (&monomial(N - 1) * &monomial(1)).coeffs()[0] as i64,
            minus_one
        );
    }

    #[test]
    fn add_sub_neg_are_consistent() {
        let mut rng = StdRng::from_seed([12u8; 32]);
        let a = random_q(&mut rng);
        let b = random_q(&mut rng);
        assert_eq!(&(&a + &b) - &b, a);
        assert_eq!(&a + &(-&a), PolyQ::zero());
        assert!((&a + &b).coeffs().iter().all(|&c| c < Q));
    }

    #[test]
    fn centered_representative_is_in_range() {
        let mut c = std::vec![0u32; N];
        c[0] = Q / 2;
        c[1] = Q / 2 + 1;
        c[2] = Q - 1;
        c[3] = 5;
        let p = PolyQ::from_coeffs(&c).expect("length N");
        let centered = p.centered();
        assert_eq!(
            &centered[..4],
            &[i64::from(Q / 2), -(i64::from(Q / 2) - 1), -1, 5]
        );
        let half = i64::from(Q / 2);
        assert!(centered.iter().all(|&v| -half < v && v <= half));
        assert_eq!(PolyQ::from_signed(&centered).expect("length N"), p);
    }

    #[test]
    fn adjoint_matches_definition_and_is_multiplicative() {
        let mut rng = StdRng::from_seed([13u8; 32]);
        let a = random_q(&mut rng);
        let b = random_q(&mut rng);
        let star = a.adjoint();
        assert_eq!(star.coeffs()[0], a.coeffs()[0]);
        for i in 1..N {
            assert_eq!(star.coeffs()[i], a.coeffs()[N - i].wrapping_neg() & Q_MASK);
        }
        assert_eq!(star.adjoint(), a);
        assert_eq!((&a * &b).adjoint(), &a.adjoint() * &b.adjoint());
    }

    #[test]
    fn inverse_exists_exactly_when_value_at_one_is_odd() {
        let mut rng = StdRng::from_seed([14u8; 32]);
        let mut a = random_q(&mut rng);
        let sum: u64 = a.coeffs().iter().map(|&c| u64::from(c)).sum();
        if sum.is_multiple_of(2) {
            a = &a + &PolyQ::one();
        }
        let inv = a.inverse().expect("a(1) is odd");
        assert_eq!(&a * &inv, PolyQ::one());
        let even = &a + &PolyQ::one();
        assert!(even.inverse().is_err());
    }

    #[test]
    fn canonical_constructors_and_bytes_reject_bad_input() {
        let mut rng = StdRng::from_seed([16u8; 32]);
        let a = random_q(&mut rng);
        assert_eq!(PolyQ::from_reduced(a.coeffs().to_vec()), a);
        assert_eq!(
            PolyQ::from_canonical(a.coeffs().to_vec()).expect("canonical"),
            a
        );
        let bytes = a.to_bytes();
        assert_eq!(bytes.len(), 4 * N);
        assert_eq!(PolyQ::from_bytes(&bytes).expect("canonical"), a);

        assert!(PolyQ::from_bytes(&bytes[1..]).is_err());
        assert!(PolyQ::from_bytes(&bytes[4..]).is_err());
        let mut high = bytes;
        high[3] = 0x20; // coefficient 0 becomes ≥ 2^29
        assert!(PolyQ::from_bytes(&high).is_err());
        let mut coeffs = a.coeffs().to_vec();
        coeffs[5] = Q;
        assert!(PolyQ::from_canonical(coeffs).is_err());
        assert!(PolyQ::from_canonical(std::vec![0; N - 1]).is_err());
    }

    #[test]
    fn evaluation_at_one_and_norm_match_their_definitions() {
        let mut c = std::vec![0i64; N];
        c[0] = 3;
        c[1] = -4;
        c[N - 1] = 12;
        let p = PolyZ::from_coeffs(c).expect("in range");
        assert_eq!(p.eval_at_one(), 11);
        assert_eq!(p.norm_sq(), 9 + 16 + 144);
        let big = PolyZ::constant(i64::MAX).expect("in range");
        assert_eq!(big.norm_sq(), u128::from(i64::MAX.unsigned_abs()).pow(2));
    }

    #[test]
    fn centered_norm_uses_the_centered_representative() {
        let mut c = std::vec![0u32; N];
        c[0] = Q - 3; // −3
        c[1] = 4;
        c[2] = Q / 2; // q/2 stays positive
        let p = PolyQ::from_coeffs(&c).expect("length N");
        let half = u128::from(Q / 2);
        assert_eq!(p.centered_norm_sq(), 9 + 16 + half * half);
        assert_eq!(sum_of_squares(&[-3, 4]), 25);
        assert_eq!(sum_of_squares(&[i64::MAX; 8]), u128::MAX);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn poly_q_serde_round_trips_and_rejects_non_canonical_input() {
        let mut rng = StdRng::from_seed([17u8; 32]);
        let a = random_q(&mut rng);
        crate::tests::utils::assert_serde_round_trip(&a);
        let mut bad = a.coeffs().to_vec();
        bad[0] = Q;
        let json = serde_json::to_string(&bad).expect("serialize");
        assert!(serde_json::from_str::<PolyQ>(&json).is_err());
        let short = serde_json::to_string(&bad[1..]).expect("serialize");
        assert!(serde_json::from_str::<PolyQ>(&short).is_err());
    }

    #[test]
    fn integer_ring_ops_are_exact() {
        let mut rng = StdRng::from_seed([15u8; 32]);
        let mut small = || {
            let c: Vec<i64> = (0..N)
                .map(|_| i64::from(rng.random::<i32>() >> 8))
                .collect();
            PolyZ::from_coeffs(c).expect("length N")
        };
        let a = small();
        let b = small();
        let prod = a.checked_mul(&b).expect("small operands");
        let mut expected = std::vec![0i128; N];
        for (i, &ai) in a.coeffs().iter().enumerate() {
            for (j, &bj) in b.coeffs().iter().enumerate() {
                let p = i128::from(ai) * i128::from(bj);
                if i + j < N {
                    expected[i + j] += p;
                } else {
                    expected[i + j - N] -= p;
                }
            }
        }
        let got: Vec<i128> = prod.coeffs().iter().map(|&c| i128::from(c)).collect();
        assert_eq!(got, expected);
        assert_eq!(
            a.checked_add(&b)
                .expect("small")
                .checked_sub(&b)
                .expect("small"),
            a
        );
        assert_eq!(a.adjoint().adjoint(), a);
        assert_eq!(PolyQ::from(&prod), &PolyQ::from(&a) * &PolyQ::from(&b));

        let huge = PolyZ::constant(i64::MAX).expect("in range");
        assert!(huge.checked_add(&huge).is_err());
        assert!(huge.checked_mul(&huge).is_err());
        assert!(PolyZ::constant(i64::MIN).is_err());
        assert!(PolyZ::from_coeffs(std::vec![0; 3]).is_err());
        assert!(PolyQ::from_coeffs(&[0; 3]).is_err());
    }
}
