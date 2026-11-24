/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Floating-point FFT over `R[x]/(x^n + 1)`.
//!
//! [`fft`] evaluates a real polynomial at the `n` roots `ω^(2j+1)` of
//! `x^n + 1`, where `ω = e^(iπ/n)`. Multiplication becomes pointwise, and the
//! adjoint `a*` becomes complex conjugation.
//!
//! # Timing
//!
//! This is the crate's one statement of the floating-point assumptions;
//! the sampler, Gaussian, and NTRU modules refer here.
//!
//! On secret data these routines only add, subtract, and multiply `f64`s,
//! round ([`integer_poly`]), and compare against fixed bounds whose outcome
//! is the same for every honest input. Reciprocals (`1/n`, `0.5`) and the
//! twiddles (`cos`/`sin` of public angles, tabulated once per size) never
//! depend on a secret. The residual assumption is that `f64` add, mul,
//! compare, `floor`/`round`, `min`/`max`, and `f64 → integer` conversion are
//! constant-time for normal operands, which holds on x86-64 (SSE2) and
//! aarch64.
//!
//! Subnormals, the usual exception, cannot occur. Inputs are integers of
//! magnitude at most `2^52` and twiddle components are zero or at least
//! `2^-54` in magnitude (`|sin(π/2^11)| > 2^-11`, and `cos` near `π/2`
//! bottoms out at `6·10^-17`). Through the ten butterfly stages, the
//! sampler's splits, merges, and Klein updates, and the leaf sampler's
//! exponent, every value is a sum or difference of such terms, or a product
//! of at most three of them. A difference of two doubles of magnitude in
//! `[2^-54, 2^60]` is zero or at least `2^-106`, so a product of three such
//! is zero or at least `2^-318`: that is the floor for every value on these
//! paths, far above the subnormal threshold `2^-1022`.
use super::ring::PolyZ;
use crate::{Error, VsssResult};
use core::f64::consts::PI;
use core::ops::{Add, Mul, Sub};
use std::sync::OnceLock;
use std::vec::Vec;

/// The error for an FFT input whose length is not a power of two.
const FFT_LENGTH: Error = Error::Lattice("FFT length must be a power of two");

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

impl Add for Complex {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Self {
            re: self.re + other.re,
            im: self.im + other.im,
        }
    }
}

impl Sub for Complex {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        Self {
            re: self.re - other.re,
            im: self.im - other.im,
        }
    }
}

impl Mul for Complex {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        Self {
            re: self.re * other.re - self.im * other.im,
            im: self.re * other.im + self.im * other.re,
        }
    }
}

/// `|a_j|² + |b_j|²` for each slot `j`.
pub(crate) fn pair_norm_sq(a: &[Complex], b: &[Complex]) -> Vec<f64> {
    a.iter()
        .zip(b)
        .map(|(x, y)| x.norm_sq() + y.norm_sq())
        .collect()
}

/// The constant tables of one transform size `n`, built once.
struct Tables {
    /// Butterfly twiddles for each sign (`[+1, −1]`): stage `len` uses
    /// slots `len/2 .. len`, `e^(sign·2πi·k/len)` for `k < len/2`.
    twiddles: [Vec<Complex>; 2],
    /// [`fft`]'s input twist `e^(iπk/n)` and [`ifft`]'s output twist
    /// `e^(−iπk/n)`, for `k < n`.
    twists: [Vec<Complex>; 2],
}

impl Tables {
    /// The tables for `n`, with the same expressions the transforms used
    /// inline, so every bit is the same.
    fn new(n: usize) -> Self {
        let twiddles = |sign: f64| {
            let mut table = std::vec![Complex::default(); n];
            let mut len = 2;
            while len <= n {
                let step = sign * 2.0 * PI / len as f64;
                for (k, w) in table[len / 2..len].iter_mut().enumerate() {
                    *w = Complex::from_angle(step * k as f64);
                }
                len <<= 1;
            }
            table
        };
        let twists = |twist: f64| {
            (0..n)
                .map(|k| Complex::from_angle(twist * k as f64))
                .collect()
        };
        Self {
            twiddles: [twiddles(1.0), twiddles(-1.0)],
            twists: [twists(PI / n as f64), twists(-PI / n as f64)],
        }
    }

    /// The cached tables for a power of two `n`.
    fn get(n: usize) -> &'static Self {
        /// One slot per power of two a `usize` can hold.
        static CACHE: [OnceLock<Tables>; usize::BITS as usize] =
            [const { OnceLock::new() }; usize::BITS as usize];
        CACHE[n.trailing_zeros() as usize].get_or_init(|| Self::new(n))
    }
}

/// In-place radix-2 transform `A_j = Σ_k a_k w^(jk)` with the given
/// [`Tables::twiddles`]: `e^(2πi/n)` powers for the forward table and
/// `e^(−2πi/n)` powers for the inverse. `a.len()` must be a power of two.
fn transform(a: &mut [Complex], twiddles: &[Complex]) {
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
        let stage = &twiddles[len / 2..len];
        for chunk in a.chunks_mut(len) {
            let (lo, hi) = chunk.split_at_mut(len / 2);
            for ((u, v), &w) in lo.iter_mut().zip(hi.iter_mut()).zip(stage) {
                let t = *v * w;
                let s = *u;
                *u = s + t;
                *v = s - t;
            }
        }
        len <<= 1;
    }
}

/// Evaluate `a ∈ R[x]/(x^n + 1)` at every root of `x^n + 1`.
/// Fails unless `a.len()` is a power of two.
pub(crate) fn fft(a: &[f64]) -> VsssResult<Vec<Complex>> {
    let n = a.len();
    if !n.is_power_of_two() {
        return Err(FFT_LENGTH);
    }
    let tables = Tables::get(n);
    let mut out: Vec<Complex> = a
        .iter()
        .zip(&tables.twists[0])
        .map(|(&c, &w)| w.scale(c))
        .collect();
    transform(&mut out, &tables.twiddles[0]);
    Ok(out)
}

/// Invert [`fft`], returning the real coefficients.
/// Fails unless `a.len()` is a power of two.
pub(crate) fn ifft(a: &[Complex]) -> VsssResult<Vec<f64>> {
    let n = a.len();
    if !n.is_power_of_two() {
        return Err(FFT_LENGTH);
    }
    let tables = Tables::get(n);
    let mut buf = a.to_vec();
    transform(&mut buf, &tables.twiddles[1]);
    let inv_n = 1.0 / n as f64;
    Ok(buf
        .iter()
        .zip(&tables.twists[1])
        .map(|(&c, &w)| (c * w).re * inv_n)
        .collect())
}

/// The FFT image of an integer polynomial.
pub(crate) fn fft_of(p: &PolyZ) -> VsssResult<Vec<Complex>> {
    let coeffs: Vec<f64> = p.coeffs().iter().map(|&c| c as f64).collect();
    fft(&coeffs)
}

/// Round an FFT image of an integer polynomial back to its coefficients;
/// the inverse of [`fft_of`].
pub(crate) fn integer_poly(p: &[Complex]) -> VsssResult<PolyZ> {
    let coeffs = ifft(p)?
        .into_iter()
        .map(|c| {
            let r = c.round();
            (r.is_finite() && r.abs() < (1u64 << 52) as f64)
                .then_some(r as i64)
                .ok_or(Error::Lattice("sampled coefficient out of range"))
        })
        .collect::<VsssResult<Vec<_>>>()?;
    PolyZ::from_coeffs(coeffs)
}

/// The root `ζ_j = ω^(2j+1)` of `x^n + 1`, `ω = e^(iπ/n)`, at which [`fft`]
/// evaluates slot `j`.
fn root(j: usize, n: usize) -> Complex {
    Complex::from_angle(PI * (2 * j + 1) as f64 / n as f64)
}

/// The roots every split down from `x^n + 1` needs, computed once: slot
/// `m/2 + j` holds `ζ_j` of `x^m + 1` for each power of two `m ≤ n`, so
/// [`roots_for`] finds the `m/2` roots of one level at `m/2..m`.
pub(crate) fn split_roots(n: usize) -> Vec<Complex> {
    (0..n)
        .map(|k| {
            let m = (k + 1).next_power_of_two();
            root(k - m / 2, m)
        })
        .collect()
}

/// The `n/2` roots of `x^n + 1` in a [`split_roots`] table, or none if the
/// table is too small.
pub(crate) fn roots_for(table: &[Complex], n: usize) -> &[Complex] {
    table.get(n / 2..n).unwrap_or(&[])
}

/// Split `a = a0(x²) + x·a1(x²)` in the FFT domain: from the `n` values of
/// `a` write the `n/2` values of `a0` and of `a1`. `roots` holds the `n/2`
/// roots of `x^n + 1` from [`roots_for`].
///
/// Slots `j` and `j + n/2` hold `a(ζ_j)` and `a(−ζ_j)`, and `ζ_j²` is slot
/// `j` of the half-size ring, so `a0 = (a(ζ) + a(−ζ))/2` and
/// `a1 = (a(ζ) − a(−ζ))/(2ζ)`. `a.len()` must be an even power of two.
pub(crate) fn split_fft(a: &[Complex], roots: &[Complex], a0: &mut [Complex], a1: &mut [Complex]) {
    let (lo, hi) = a.split_at(a.len() / 2);
    for ((o0, o1), ((&x, &y), z)) in a0
        .iter_mut()
        .zip(a1.iter_mut())
        .zip(lo.iter().zip(hi).zip(roots))
    {
        *o0 = (x + y).scale(0.5);
        *o1 = (x - y) * z.conj().scale(0.5);
    }
}

/// Invert [`split_fft`] into `out`: `a(±ζ_j) = a0(ζ_j²) ± ζ_j·a1(ζ_j²)`.
pub(crate) fn merge_fft(a0: &[Complex], a1: &[Complex], roots: &[Complex], out: &mut [Complex]) {
    let (lo, hi) = out.split_at_mut(out.len() / 2);
    for ((l, h), ((&x, &y), &z)) in lo
        .iter_mut()
        .zip(hi.iter_mut())
        .zip(a0.iter().zip(a1).zip(roots))
    {
        let odd = z * y;
        *l = x + odd;
        *h = x - odd;
    }
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

        let prod: Vec<Complex> = fa.iter().zip(&fb).map(|(&x, &y)| x * y).collect();
        let expected = negacyclic_mul(&a, &b);
        for (x, y) in ifft(&prod).expect("power of two").iter().zip(&expected) {
            assert!((x - *y as f64).abs() < 1e-6);
        }
    }

    #[test]
    fn cached_tables_are_built_once_from_the_inline_formulas() {
        for n in [1usize, 2, 16, 1024] {
            let tables = Tables::get(n);
            assert!(core::ptr::eq(tables, Tables::get(n)));
            for (sign, twiddles) in [1.0, -1.0].into_iter().zip(&tables.twiddles) {
                let mut len = 2;
                while len <= n {
                    let step = sign * 2.0 * PI / len as f64;
                    for k in 0..len / 2 {
                        assert_eq!(twiddles[len / 2 + k], Complex::from_angle(step * k as f64));
                    }
                    len <<= 1;
                }
            }
            for k in 0..n {
                let angle = k as f64;
                assert_eq!(
                    tables.twists[0][k],
                    Complex::from_angle(PI / n as f64 * angle)
                );
                assert_eq!(
                    tables.twists[1][k],
                    Complex::from_angle(-PI / n as f64 * angle)
                );
            }
        }
    }

    #[test]
    fn complex_arithmetic_matches_the_definitions() {
        let a = Complex { re: 3.0, im: -2.0 };
        let b = Complex { re: 0.5, im: 4.0 };
        assert_eq!(a + b, Complex { re: 3.5, im: 2.0 });
        assert_eq!(a - b, Complex { re: 2.5, im: -6.0 });
        // (3 − 2i)(0.5 + 4i) = 1.5 + 12i − i + 8 = 9.5 + 11i.
        assert_eq!(a * b, Complex { re: 9.5, im: 11.0 });
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

    /// [`split_fft`] into fresh buffers.
    fn split(a: &[Complex]) -> (Vec<Complex>, Vec<Complex>) {
        let table = split_roots(a.len());
        let mut a0 = std::vec![Complex::default(); a.len() / 2];
        let mut a1 = a0.clone();
        split_fft(a, roots_for(&table, a.len()), &mut a0, &mut a1);
        (a0, a1)
    }

    #[test]
    fn split_and_merge_match_the_coefficient_split() {
        // a = a0(x²) + x·a1(x²) with a0 = even, a1 = odd coefficients.
        let a: Vec<f64> = (0..16).map(|i| f64::from((i * 7) % 11) - 5.0).collect();
        let even: Vec<f64> = a.iter().step_by(2).copied().collect();
        let odd: Vec<f64> = a.iter().skip(1).step_by(2).copied().collect();
        let fa = fft(&a).expect("power of two");
        let (s0, s1) = split(&fa);
        let close = |x: &[Complex], y: &[Complex]| {
            x.iter().zip(y).all(|(&p, &q)| (p - q).norm_sq() < 1e-18)
        };
        assert!(close(&s0, &fft(&even).expect("power of two")));
        assert!(close(&s1, &fft(&odd).expect("power of two")));
        let mut merged = std::vec![Complex::default(); 16];
        merge_fft(&s0, &s1, roots_for(&split_roots(16), 16), &mut merged);
        assert!(close(&merged, &fa));
        // Degree 1: the value at ζ = −1 is the constant coefficient.
        let (c0, c1) = split(&fft(&[2.0, 3.0]).expect("power of two"));
        assert!((c0[0].re - 2.0).abs() < 1e-12 && (c1[0].re - 3.0).abs() < 1e-12);
    }

    #[test]
    fn split_roots_tabulates_every_level() {
        let table = split_roots(8);
        assert_eq!(table.len(), 8);
        for m in [2usize, 4, 8] {
            let level = roots_for(&table, m);
            assert_eq!(level.len(), m / 2);
            for (j, z) in level.iter().enumerate() {
                assert_eq!(*z, root(j, m));
            }
        }
        assert!(roots_for(&table, 16).is_empty());
    }

    #[test]
    fn pair_norm_sq_adds_the_squared_magnitudes() {
        let a = [Complex { re: 3.0, im: 4.0 }, Complex { re: 1.0, im: 0.0 }];
        let b = [Complex { re: 0.0, im: 2.0 }, Complex { re: -1.0, im: 1.0 }];
        assert_eq!(pair_norm_sq(&a, &b), std::vec![29.0, 3.0]);
    }

    #[test]
    fn fft_of_and_integer_poly_round_trip() {
        let mut coeffs = std::vec![0i64; crate::lattice::N];
        coeffs[0] = 5;
        coeffs[3] = -7;
        let p = PolyZ::from_coeffs(coeffs).expect("in range");
        assert_eq!(integer_poly(&fft_of(&p).expect("power of two")), Ok(p));
        let nan = [Complex {
            re: f64::NAN,
            im: 0.0,
        }];
        assert_eq!(
            integer_poly(&nan),
            Err(Error::Lattice("sampled coefficient out of range"))
        );
        assert_eq!(integer_poly(&[Complex::default(); 3]), Err(FFT_LENGTH));
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
        assert_eq!(fft(&[1.0, 2.0, 3.0]), Err(FFT_LENGTH));
        assert_eq!(ifft(&[Complex::default(); 3]), Err(FFT_LENGTH));
    }
}
