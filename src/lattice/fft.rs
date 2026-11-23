/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Floating-point FFT over `R[x]/(x^n + 1)`.
//!
//! [`fft`] evaluates a real polynomial at the `n` roots `ω^(2j+1)` of
//! `x^n + 1`, where `ω = e^(iπ/n)`. Multiplication becomes pointwise, and the
//! adjoint `a*` becomes complex conjugation.
use core::f64::consts::PI;
use std::vec::Vec;

/// A complex number in `f64`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize))]
pub(crate) struct Complex {
    /// Real part.
    pub(crate) re: f64,
    /// Imaginary part.
    pub(crate) im: f64,
}

impl Complex {
    /// `e^(iθ)`.
    fn from_angle(theta: f64) -> Self {
        Self {
            re: theta.cos(),
            im: theta.sin(),
        }
    }

    /// `self + other`.
    pub(crate) fn plus(self, other: Self) -> Self {
        Self {
            re: self.re + other.re,
            im: self.im + other.im,
        }
    }

    /// `self − other`.
    pub(crate) fn minus(self, other: Self) -> Self {
        Self {
            re: self.re - other.re,
            im: self.im - other.im,
        }
    }

    /// `self · other`.
    pub(crate) fn times(self, other: Self) -> Self {
        Self {
            re: self.re * other.re - self.im * other.im,
            im: self.re * other.im + self.im * other.re,
        }
    }

    /// `self · s` for a real `s`.
    pub(crate) fn scale(self, s: f64) -> Self {
        Self {
            re: self.re * s,
            im: self.im * s,
        }
    }

    /// The complex conjugate.
    pub(crate) fn conj(self) -> Self {
        Self {
            re: self.re,
            im: -self.im,
        }
    }

    /// `|self|²`.
    pub(crate) fn norm_sq(self) -> f64 {
        self.re * self.re + self.im * self.im
    }
}

/// In-place radix-2 transform `A_j = Σ_k a_k e^(sign·2πi·jk/n)`.
/// `a.len()` must be a power of two.
fn transform(a: &mut [Complex], sign: f64) {
    let n = a.len();
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            a.swap(i, j);
        }
    }
    let mut len = 2;
    while len <= n {
        let step = sign * 2.0 * PI / len as f64;
        for chunk in a.chunks_mut(len) {
            let (lo, hi) = chunk.split_at_mut(len / 2);
            for (k, (u, v)) in lo.iter_mut().zip(hi.iter_mut()).enumerate() {
                let t = v.times(Complex::from_angle(step * k as f64));
                let s = *u;
                *u = s.plus(t);
                *v = s.minus(t);
            }
        }
        len <<= 1;
    }
}

/// Evaluate `a ∈ R[x]/(x^n + 1)` at every root of `x^n + 1`.
/// Returns `None` unless `a.len()` is a power of two.
pub(crate) fn fft(a: &[f64]) -> Option<Vec<Complex>> {
    let n = a.len();
    if !n.is_power_of_two() {
        return None;
    }
    let twist = PI / n as f64;
    let mut out: Vec<Complex> = a
        .iter()
        .enumerate()
        .map(|(k, &c)| Complex::from_angle(twist * k as f64).scale(c))
        .collect();
    transform(&mut out, 1.0);
    Some(out)
}

/// Invert [`fft`], returning the real coefficients.
/// Returns `None` unless `a.len()` is a power of two.
pub(crate) fn ifft(a: &[Complex]) -> Option<Vec<f64>> {
    let n = a.len();
    if !n.is_power_of_two() {
        return None;
    }
    let mut buf = a.to_vec();
    transform(&mut buf, -1.0);
    let twist = -PI / n as f64;
    let inv_n = 1.0 / n as f64;
    Some(
        buf.iter()
            .enumerate()
            .map(|(k, c)| c.times(Complex::from_angle(twist * k as f64)).re * inv_n)
            .collect(),
    )
}

/// The root `ζ_j = ω^(2j+1)` of `x^n + 1`, `ω = e^(iπ/n)`, at which [`fft`]
/// evaluates slot `j`.
fn root(j: usize, n: usize) -> Complex {
    Complex::from_angle(PI * (2 * j + 1) as f64 / n as f64)
}

/// Split `a = a0(x²) + x·a1(x²)` in the FFT domain: from the `n` values of
/// `a` return the `n/2` values of `a0` and of `a1`.
///
/// Slots `j` and `j + n/2` hold `a(ζ_j)` and `a(−ζ_j)`, and `ζ_j²` is slot
/// `j` of the half-size ring, so `a0 = (a(ζ) + a(−ζ))/2` and
/// `a1 = (a(ζ) − a(−ζ))/(2ζ)`. `a.len()` must be an even power of two.
pub(crate) fn split_fft(a: &[Complex]) -> (Vec<Complex>, Vec<Complex>) {
    let n = a.len();
    let (lo, hi) = a.split_at(n / 2);
    lo.iter()
        .zip(hi)
        .enumerate()
        .map(|(j, (&x, &y))| {
            let inv_2z = root(j, n).conj().scale(0.5);
            (x.plus(y).scale(0.5), x.minus(y).times(inv_2z))
        })
        .unzip()
}

/// Invert [`split_fft`]: `a(±ζ_j) = a0(ζ_j²) ± ζ_j·a1(ζ_j²)`.
pub(crate) fn merge_fft(a0: &[Complex], a1: &[Complex]) -> Vec<Complex> {
    let n = 2 * a0.len();
    let odd: Vec<Complex> = a1
        .iter()
        .enumerate()
        .map(|(j, &y)| root(j, n).times(y))
        .collect();
    let plus = a0.iter().zip(&odd).map(|(&x, &y)| x.plus(y));
    let minus = a0.iter().zip(&odd).map(|(&x, &y)| x.minus(y));
    plus.chain(minus).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lattice::poly::negacyclic_mul;

    #[test]
    fn fft_round_trips_and_multiplies_negacyclically() {
        let n = 64usize;
        let a: Vec<i128> = (0..n as i128).map(|i| (i * 37) % 23 - 11).collect();
        let b: Vec<i128> = (0..n as i128).map(|i| (i * 53) % 19 - 9).collect();
        let to_f = |p: &[i128]| p.iter().map(|&c| c as f64).collect::<Vec<_>>();
        let fa = fft(&to_f(&a)).expect("power of two");
        let fb = fft(&to_f(&b)).expect("power of two");

        let back = ifft(&fa).expect("power of two");
        for (x, y) in back.iter().zip(&a) {
            assert!((x - *y as f64).abs() < 1e-9);
        }

        let prod: Vec<Complex> = fa.iter().zip(&fb).map(|(x, y)| x.times(*y)).collect();
        let expected = negacyclic_mul(&a, &b);
        for (x, y) in ifft(&prod).expect("power of two").iter().zip(&expected) {
            assert!((x - *y as f64).abs() < 1e-6);
        }
    }

    #[test]
    fn complex_arithmetic_matches_the_definitions() {
        let a = Complex { re: 3.0, im: -2.0 };
        let b = Complex { re: 0.5, im: 4.0 };
        assert_eq!(a.plus(b), Complex { re: 3.5, im: 2.0 });
        assert_eq!(a.minus(b), Complex { re: 2.5, im: -6.0 });
        // (3 − 2i)(0.5 + 4i) = 1.5 + 12i − i + 8 = 9.5 + 11i.
        assert_eq!(a.times(b), Complex { re: 9.5, im: 11.0 });
        assert_eq!(a.scale(-2.0), Complex { re: -6.0, im: 4.0 });
        assert_eq!(a.conj(), Complex { re: 3.0, im: 2.0 });
        assert_eq!(a.norm_sq(), 13.0);
        let unit = Complex::from_angle(PI / 2.0);
        assert!(unit.re.abs() < 1e-15 && (unit.im - 1.0).abs() < 1e-15);
        let r = root(1, 4);
        // ζ_1 = ω^3 with ω = e^(iπ/4).
        assert!((r.re + core::f64::consts::FRAC_1_SQRT_2).abs() < 1e-15);
        assert!((r.im - core::f64::consts::FRAC_1_SQRT_2).abs() < 1e-15);
    }

    #[test]
    fn split_and_merge_match_the_coefficient_split() {
        // a = a0(x²) + x·a1(x²) with a0 = even, a1 = odd coefficients.
        let a: Vec<f64> = (0..16).map(|i| f64::from((i * 7) % 11) - 5.0).collect();
        let even: Vec<f64> = a.iter().step_by(2).copied().collect();
        let odd: Vec<f64> = a.iter().skip(1).step_by(2).copied().collect();
        let fa = fft(&a).expect("power of two");
        let (s0, s1) = split_fft(&fa);
        let close = |x: &[Complex], y: &[Complex]| {
            x.iter().zip(y).all(|(p, q)| p.minus(*q).norm_sq() < 1e-18)
        };
        assert!(close(&s0, &fft(&even).expect("power of two")));
        assert!(close(&s1, &fft(&odd).expect("power of two")));
        assert!(close(&merge_fft(&s0, &s1), &fa));
        // Degree 1: the value at ζ = −1 is the constant coefficient.
        let (c0, c1) = split_fft(&fft(&[2.0, 3.0]).expect("power of two"));
        assert!((c0[0].re - 2.0).abs() < 1e-12 && (c1[0].re - 3.0).abs() < 1e-12);
    }

    #[test]
    fn adjoint_is_conjugation() {
        // a = 1 + 2x + 3x^3 in R[x]/(x^4 + 1); a* = 1 − 3x − 2x^3.
        let a = [1.0, 2.0, 0.0, 3.0];
        let a_star = [1.0, -3.0, 0.0, -2.0];
        let fa = fft(&a).expect("power of two");
        let fs = fft(&a_star).expect("power of two");
        for (x, y) in fa.iter().zip(&fs) {
            assert!((x.conj().re - y.re).abs() < 1e-12);
            assert!((x.conj().im - y.im).abs() < 1e-12);
        }
        assert!(fft(&[1.0, 2.0, 3.0]).is_none());
    }
}
