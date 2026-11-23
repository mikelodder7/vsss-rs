/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Falcon-style recursive NTRUSolve.
//!
//! Given `f, g ∈ Z[x]/(x^n + 1)`, find `F, G` with `f·G − g·F = q`. The
//! field norm `N(f)(x²) = f(x)·f(−x)` halves the degree until `n = 1`, where
//! the extended Euclidean algorithm solves `u·N(f) + v·N(g) = 1`. Each level
//! lifts the solution with `F = F'(x²)·g(−x)`, `G = G'(x²)·f(−x)` and shrinks
//! it with Babai's round-off against `(f, g)`, computed in floating point on
//! the top 53 bits as in Pornin–Prest.
//!
//! The degree-1 norms are the resultants `Res(f, x^N + 1)` and
//! `Res(g, x^N + 1)`, so the base case fails exactly when
//! `gcd(R_f, R_g) ≠ 1`.
use super::fft::{Complex, fft, ifft};
use super::poly::negacyclic_mul_big;
use num_bigint::BigInt;
use num_traits::{One, Signed, ToPrimitive, Zero};
use std::vec::Vec;

/// Bits of precision the floating-point round-off works with.
const PRECISION: u64 = 53;
/// Round-off iterations per level before the solve gives up. Each one
/// removes roughly 30 bits, and no level of an `N = 1024` solve needs more
/// than a few hundred.
const MAX_REDUCE_ITERATIONS: usize = 4096;
/// Largest round-off coefficient accepted from the FFT, `2^62`.
const MAX_ROUNDOFF: f64 = (1u64 << 62) as f64;

/// Solve `f·G − g·F = q` over `Z[x]/(x^n + 1)`, `n = f.len()` a power of
/// two. Returns `(F, G)` reduced against `(f, g)`, or `None` if no solution
/// exists (`gcd(R_f, R_g) ≠ 1`) or the reduced solution does not fit `i64`.
pub(crate) fn solve(f: &[i64], g: &[i64], q: u32) -> Option<(Vec<i64>, Vec<i64>)> {
    let big = |p: &[i64]| p.iter().map(|&c| BigInt::from(c)).collect::<Vec<_>>();
    let (big_f, big_g) = solve_big(big(f), big(g), &BigInt::from(q))?;
    let small = |p: &[BigInt]| {
        p.iter()
            .map(ToPrimitive::to_i64)
            .collect::<Option<Vec<_>>>()
    };
    Some((small(&big_f)?, small(&big_g)?))
}

fn solve_big(f: Vec<BigInt>, g: Vec<BigInt>, q: &BigInt) -> Option<(Vec<BigInt>, Vec<BigInt>)> {
    if f.len() != g.len() || !f.len().is_power_of_two() {
        return None;
    }
    if f.len() == 1 {
        let ([f0], [g0]) = (
            <[BigInt; 1]>::try_from(f).ok()?,
            <[BigInt; 1]>::try_from(g).ok()?,
        );
        let Bezout { gcd, x: u, y: v } = xgcd(f0, g0);
        if !gcd.is_one() {
            return None;
        }
        // f0·(q·u) − g0·(−q·v) = q·(u·f0 + v·g0) = q.
        return Some((std::vec![-(q * v)], std::vec![q * u]));
    }
    let (fp, gp) = solve_big(field_norm(&f), field_norm(&g), q)?;
    // `f` and `g` are still needed for the reduction, so their conjugates
    // are fresh copies.
    let mut big_f = negacyclic_mul_big(&lift(fp), &conjugate(&g));
    let mut big_g = negacyclic_mul_big(&lift(gp), &conjugate(&f));
    reduce(&f, &g, &mut big_f, &mut big_g)?;
    Some((big_f, big_g))
}

/// Bézout coefficients: `x·a + y·b = gcd` with `gcd = gcd(a, b) ≥ 0`.
#[derive(Debug, PartialEq, Eq)]
struct Bezout {
    gcd: BigInt,
    x: BigInt,
    y: BigInt,
}

/// The extended Euclidean algorithm.
fn xgcd(a: BigInt, b: BigInt) -> Bezout {
    let (mut r0, mut r1) = (a, b);
    let (mut s0, mut s1) = (BigInt::one(), BigInt::zero());
    let (mut t0, mut t1) = (BigInt::zero(), BigInt::one());
    while !r1.is_zero() {
        let quot = &r0 / &r1;
        let r2 = &r0 - &quot * &r1;
        let s2 = &s0 - &quot * &s1;
        let t2 = &t0 - &quot * &t1;
        r0 = core::mem::replace(&mut r1, r2);
        s0 = core::mem::replace(&mut s1, s2);
        t0 = core::mem::replace(&mut t1, t2);
    }
    if r0.is_negative() {
        Bezout {
            gcd: -r0,
            x: -s0,
            y: -t0,
        }
    } else {
        Bezout {
            gcd: r0,
            x: s0,
            y: t0,
        }
    }
}

/// `N(f) = f0² − x·f1²` in `Z[x]/(x^(n/2) + 1)`, where
/// `f = f0(x²) + x·f1(x²)`.
///
/// The callers keep `f`, so the strided halves are copied into contiguous
/// buffers for the multiplier.
fn field_norm(f: &[BigInt]) -> Vec<BigInt> {
    let even: Vec<BigInt> = f.iter().step_by(2).cloned().collect();
    let odd: Vec<BigInt> = f.iter().skip(1).step_by(2).cloned().collect();
    let even_sq = negacyclic_mul_big(&even, &even);
    let mut shifted = negacyclic_mul_big(&odd, &odd);
    // x·p wraps the top coefficient to the bottom with a sign flip.
    shifted.rotate_right(1);
    if let Some(bottom) = shifted.first_mut() {
        *bottom = -core::mem::take(bottom);
    }
    even_sq
        .into_iter()
        .zip(shifted)
        .map(|(e, s)| e - s)
        .collect()
}

/// `p(x) ↦ p(x²)`, doubling the degree.
fn lift(p: Vec<BigInt>) -> Vec<BigInt> {
    p.into_iter().flat_map(|c| [c, BigInt::zero()]).collect()
}

/// `p(x) ↦ p(−x)`, as a new polynomial: callers keep `p`.
fn conjugate(p: &[BigInt]) -> Vec<BigInt> {
    p.iter()
        .enumerate()
        .map(|(i, c)| if i.is_multiple_of(2) { c.clone() } else { -c })
        .collect()
}

/// Largest coefficient bit length in `p`.
fn max_bits(p: &[BigInt]) -> u64 {
    p.iter().map(BigInt::bits).max().unwrap_or(0)
}

/// The top bits of each coefficient as `f64`: `p >> shift`.
fn top_bits(p: &[BigInt], shift: u64) -> Option<Vec<f64>> {
    p.iter()
        .map(|c| {
            let shifted: BigInt = c >> shift;
            shifted.to_f64()
        })
        .collect()
}

/// Babai round-off: repeatedly subtract `k·(f, g)` from `(F, G)` with
/// `k = ⌊(F·f* + G·g*) / (f·f* + g·g*)⌉` until `k = 0` or `(F, G)` is no
/// longer than `(f, g)`.
fn reduce(f: &[BigInt], g: &[BigInt], big_f: &mut [BigInt], big_g: &mut [BigInt]) -> Option<()> {
    let size = PRECISION.max(max_bits(f)).max(max_bits(g));
    let fa = fft(&top_bits(f, size - PRECISION)?)?;
    let ga = fft(&top_bits(g, size - PRECISION)?)?;
    let den: Vec<f64> = fa
        .iter()
        .zip(&ga)
        .map(|(x, y)| x.norm_sq() + y.norm_sq())
        .collect();

    for _ in 0..MAX_REDUCE_ITERATIONS {
        let big_size = PRECISION.max(max_bits(big_f)).max(max_bits(big_g));
        if big_size < size {
            return Some(());
        }
        let shift = big_size - PRECISION;
        let big_fa = fft(&top_bits(big_f, shift)?)?;
        let big_ga = fft(&top_bits(big_g, shift)?)?;
        let k_fft: Vec<Complex> = big_fa
            .iter()
            .zip(&big_ga)
            .zip(fa.iter().zip(&ga))
            .zip(&den)
            .map(|(((bf, bg), (sf, sg)), d)| {
                bf.times(sf.conj()).plus(bg.times(sg.conj())).scale(1.0 / d)
            })
            .collect();
        let k = ifft(&k_fft)?
            .into_iter()
            .map(|c| {
                let r = c.round();
                (r.is_finite() && r.abs() < MAX_ROUNDOFF).then(|| BigInt::from(r as i64))
            })
            .collect::<Option<Vec<_>>>()?;
        if k.iter().all(Zero::is_zero) {
            return Some(());
        }
        let scale = big_size - size;
        let fk = negacyclic_mul_big(f, &k);
        let gk = negacyclic_mul_big(g, &k);
        big_f
            .iter_mut()
            .zip(&fk)
            .for_each(|(c, d)| *c -= d << scale);
        big_g
            .iter_mut()
            .zip(&gk)
            .for_each(|(c, d)| *c -= d << scale);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    fn to_big(p: &[i64]) -> Vec<BigInt> {
        p.iter().map(|&c| BigInt::from(c)).collect()
    }

    /// `f·G − g·F` as big integers.
    fn residual(f: &[i64], g: &[i64], big_f: &[i64], big_g: &[i64]) -> Vec<BigInt> {
        let fg = negacyclic_mul_big(&to_big(f), &to_big(big_g));
        let gf = negacyclic_mul_big(&to_big(g), &to_big(big_f));
        fg.iter().zip(&gf).map(|(a, b)| a - b).collect()
    }

    #[test]
    fn xgcd_finds_bezout_coefficients() {
        let a = BigInt::from(240);
        let b = BigInt::from(-46);
        let bezout = xgcd(a.clone(), b.clone());
        assert_eq!(bezout.gcd, BigInt::from(2));
        assert_eq!(&bezout.x * &a + &bezout.y * &b, bezout.gcd);
        // A negative gcd is normalized to its absolute value.
        let neg = xgcd(BigInt::from(-12), BigInt::from(0));
        assert_eq!(
            neg,
            Bezout {
                gcd: BigInt::from(12),
                x: BigInt::from(-1),
                y: BigInt::zero(),
            }
        );
    }

    #[test]
    fn lift_and_conjugate_match_their_definitions() {
        let p = to_big(&[1, 2, 3, 4]);
        assert_eq!(lift(p.clone()), to_big(&[1, 0, 2, 0, 3, 0, 4, 0]));
        assert_eq!(conjugate(&p), to_big(&[1, -2, 3, -4]));
        assert_eq!(max_bits(&to_big(&[0, -9, 3])), 4);
        assert_eq!(
            top_bits(&to_big(&[1 << 20, -(1 << 21)]), 10),
            Some(std::vec![1024.0, -2048.0])
        );
    }

    #[test]
    fn field_norm_satisfies_its_defining_identity() {
        // N(f)(x²) = f(x)·f(−x).
        let f = to_big(&[3, -1, 4, 1, -5, 9, 2, -6]);
        let lhs = lift(field_norm(&f));
        let rhs = negacyclic_mul_big(&f, &conjugate(&f));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn solve_satisfies_ntru_equation_at_small_degree() {
        let mut rng = StdRng::from_seed([31u8; 32]);
        let q = 12_289;
        let mut solved = 0;
        for _ in 0..40 {
            let f: Vec<i64> = (0..64)
                .map(|_| i64::from(rng.random::<i8>() >> 4))
                .collect();
            let g: Vec<i64> = (0..64)
                .map(|_| i64::from(rng.random::<i8>() >> 4))
                .collect();
            if let Some((big_f, big_g)) = solve(&f, &g, q) {
                let mut expected = std::vec![BigInt::zero(); 64];
                expected[0] = BigInt::from(q);
                assert_eq!(residual(&f, &g, &big_f, &big_g), expected);
                // Reduced: no coefficient is wildly larger than q.
                assert!(
                    big_f
                        .iter()
                        .chain(&big_g)
                        .all(|c| c.unsigned_abs() < 1 << 20)
                );
                solved += 1;
            }
        }
        assert!(solved > 0);
    }

    #[test]
    fn solve_rejects_a_common_factor() {
        // f = g = 2: Res = 2^n for both, so gcd ≠ 1.
        let mut f = std::vec![0i64; 8];
        f[0] = 2;
        assert!(solve(&f, &f, 12_289).is_none());
        assert!(solve(&f[..3], &f[..3], 12_289).is_none());
    }
}
