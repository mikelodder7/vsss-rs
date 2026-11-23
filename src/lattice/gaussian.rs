/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Discrete Gaussian sampling over the integers.
//!
//! `σ` is the standard-deviation parameter: `z` is drawn with probability
//! proportional to `exp(−(z − c)² / (2σ²))`. Sampling is by rejection from a
//! uniform proposal on `[c − τσ, c + τσ]` with `τ = 13`, so the tail cut
//! loses less than `2^-120` of the mass. Not constant-time.
use super::N;
use super::ring::PolyZ;
use crate::{Error, VsssResult};
use rand_core::CryptoRng;
use std::vec::Vec;

/// Tail cut `τ` in standard deviations.
const TAIL_CUT: f64 = 13.0;
/// Rejection rounds before giving up. Acceptance is scaled so the integer
/// nearest the center is always accepted, so each round accepts with
/// probability at least `1/30` and failure is below `2^-200`.
const MAX_ATTEMPTS: u32 = 4096;
/// Centers and tails must stay inside the exactly representable integers.
const MAX_MAGNITUDE: f64 = (1u64 << 52) as f64;

/// Sample `z ∈ Z` from the discrete Gaussian with width `sigma` (standard
/// deviation) centered at `center`.
///
/// Fails if `sigma` is not finite and positive, if `center` is not finite,
/// if the support leaves `±2^52`, or, with negligible probability, if every
/// rejection round fails.
pub fn sample_z<R: CryptoRng + ?Sized>(sigma: f64, center: f64, rng: &mut R) -> VsssResult<i64> {
    let tail = TAIL_CUT * sigma;
    if !(sigma.is_finite() && sigma > 0.0 && center.is_finite())
        || center.abs() + tail + 1.0 >= MAX_MAGNITUDE
    {
        return Err(Error::Lattice("invalid Gaussian parameters"));
    }
    let lo = (center - tail).floor() as i64;
    let hi = (center + tail).ceil() as i64;
    // `hi − lo + 1 ≤ 2^54`, well inside u64.
    let width = (hi - lo + 1) as u64;
    let limit = u64::MAX - u64::MAX % width;
    let two_sigma_sq = 2.0 * sigma * sigma;
    let nearest = center - center.round();
    let peak = nearest * nearest;
    for _ in 0..MAX_ATTEMPTS {
        let r = rng.next_u64();
        if r >= limit {
            continue;
        }
        let z = lo + (r % width) as i64;
        let d = z as f64 - center;
        if uniform_unit(rng) < ((peak - d * d) / two_sigma_sq).exp() {
            return Ok(z);
        }
    }
    Err(Error::Lattice("Gaussian sampler exhausted its attempts"))
}

/// Sample a polynomial from `D_{N,σ}`: every coefficient independently from
/// the discrete Gaussian with width `sigma` centered at zero.
pub fn sample_poly<R: CryptoRng + ?Sized>(sigma: f64, rng: &mut R) -> VsssResult<PolyZ> {
    let coeffs = (0..N)
        .map(|_| sample_z(sigma, 0.0, rng))
        .collect::<VsssResult<Vec<_>>>()?;
    PolyZ::from_coeffs(coeffs)
}

/// A uniform `f64` in `[0, 1)` with 53 random bits.
fn uniform_unit<R: CryptoRng + ?Sized>(rng: &mut R) -> f64 {
    const SCALE: f64 = 1.0 / (1u64 << 53) as f64;
    (rng.next_u64() >> 11) as f64 * SCALE
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    fn moments(sigma: f64, center: f64, samples: usize) -> (f64, f64) {
        let mut rng = StdRng::from_seed([21u8; 32]);
        let xs: Vec<f64> = (0..samples)
            .map(|_| sample_z(sigma, center, &mut rng).expect("valid parameters") as f64)
            .collect();
        let mean = xs.iter().sum::<f64>() / samples as f64;
        let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (samples as f64 - 1.0);
        (mean, var)
    }

    #[test]
    fn sample_z_mean_and_variance_match_at_several_settings() {
        let samples = 20_000;
        // (σ, center): the key-generation width, and a small width with a
        // fractional center like the Klein sampler will use.
        for &(sigma, center) in &[(super::super::SIGMA_F, 0.0), (2.5, 0.37), (4.0, -1234.75)] {
            let (mean, var) = moments(sigma, center, samples);
            let stderr = sigma / (samples as f64).sqrt();
            assert!(
                (mean - center).abs() < 5.0 * stderr,
                "σ = {sigma}, c = {center}: mean {mean}"
            );
            assert!(
                (var / (sigma * sigma) - 1.0).abs() < 0.06,
                "σ = {sigma}, c = {center}: variance {var}"
            );
        }
    }

    #[test]
    fn sample_z_rejects_bad_parameters() {
        let mut rng = StdRng::from_seed([22u8; 32]);
        assert!(sample_z(0.0, 0.0, &mut rng).is_err());
        assert!(sample_z(-1.0, 0.0, &mut rng).is_err());
        assert!(sample_z(f64::NAN, 0.0, &mut rng).is_err());
        assert!(sample_z(1.0, f64::INFINITY, &mut rng).is_err());
        assert!(sample_z(1.0, 1e300, &mut rng).is_err());
        // A tiny width still terminates and returns the nearest integer,
        // even when the center is almost halfway between two integers.
        assert_eq!(sample_z(0.05, 3.1, &mut rng).expect("valid"), 3);
        for _ in 0..32 {
            let z = sample_z(0.01, 7.4999, &mut rng).expect("valid");
            assert!(z == 7 || z == 8, "z = {z}");
        }
    }

    #[test]
    fn sample_poly_has_n_centered_coefficients() {
        let mut rng = StdRng::from_seed([23u8; 32]);
        let p = sample_poly(super::super::SIGMA_F, &mut rng).expect("valid");
        assert_eq!(p.coeffs().len(), N);
        let mean = p.eval_at_one() as f64 / N as f64;
        assert!(mean.abs() < 5.0 * super::super::SIGMA_F / (N as f64).sqrt());
    }
}
