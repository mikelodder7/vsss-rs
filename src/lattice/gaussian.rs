/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Isochronous discrete Gaussian sampling over the integers.
//!
//! `σ` is the standard-deviation parameter: `z` is drawn with probability
//! proportional to `exp(−(z − c)² / (2σ²))`. Two samplers live here, both
//! built so that their running time does not depend on the center, the
//! width, or the value drawn.
//!
//! # [`SamplerZ`]: the extract leaves
//!
//! The Klein sampler draws every coordinate with a width `σ'_i = σ/‖b̃_i‖`
//! around a center that both derive from the trapdoor. This follows Howe,
//! Prest, Ricosset, and Rossi, "Isochronous Gaussian Sampling" (PKC 2020),
//! the design Falcon ships:
//!
//! 1. `z0 ← D⁺_{σ_max}`, a half-Gaussian of fixed width, by a full scan of a
//!    reverse cumulative table ([`RCDT_EXTRACT`]) with branch-free compares;
//! 2. a sign bit turns it into the bimodal proposal `z ∈ {−z0, z0 + 1}`;
//! 3. `z` is accepted with probability
//!    `(σ_min/σ')·exp(−((z − r)²/(2σ'²) − z0²/(2σ_max²)))`, `r` the
//!    fractional part of the center. The exponent is non-negative because
//!    `(z − r)² ≥ z0²` and `σ' ≤ σ_max`, so this is a valid rejection step
//!    whose output is exactly `D_{Z,σ',c}` (restricted to the table's
//!    support). The factor `σ_min/σ'` makes the acceptance probability
//!    `σ_min·ρ_{σ',r}(Z) / (2σ'·ρ_{σ_max}(Z≥0))`, which by Poisson summation
//!    equals `σ_min·√(2π) / (2·ρ_{σ_max}(Z≥0)) ≈ 0.625` up to a relative
//!    `2·exp(−2π²σ_min²) < 2^-112`: the number of rounds is a geometric
//!    variable whose law is independent of `c` and `σ'`, and each round does
//!    the same work.
//!
//! `exp` is evaluated in `u64` fixed point ([`exp_fixed`]): the argument is
//! reduced to `[0, ln 2)` with a shift `s = ⌊x/ln 2⌉`, and a degree-18 Taylor
//! polynomial with coefficients `⌊2^63/k!⌉` is run through Horner's rule. Its
//! error is at most 1.49 units of `2^-63` over `[0, ln 2]` (checked against
//! 80-digit arithmetic), a relative error below `2^-61`. The result is
//! compared with 127 random bits after the shift, so the shift costs no
//! precision. No `f64::exp`, division, or square root runs on secret data:
//! `1/(2σ'²)` and `σ_min/σ'` are computed once per trapdoor.
//!
//! ## Parameters
//!
//! - `σ_min = σ/(1.17·√q) = 2` exactly: the smallest leaf width any trapdoor
//!   passing key generation's Gram–Schmidt bound can have.
//! - `σ_max = 2.8`. The NTRU basis satisfies `‖b̃_i‖·‖b̃_{2N−1−i}‖ = q`, so
//!   the largest leaf width is `2·1.17² ≈ 2.738`; 24 generated keys measured
//!   `σ' ∈ [2.0003, 2.7374]`. The 2.3% margin absorbs rounding, and key
//!   generation rejects any trapdoor whose leaves leave `[σ_min, σ_max]`.
//! - Table: 38 rows (`z0 ≤ 37`), `P(z0 ≥ 38) < 2^-134`, entries scaled by
//!   `2^127`. Rows `0..=27` are rounded to nearest and rows `28..=37` up,
//!   so the far tail is never under-weighted (excess mass `2^-125`); every
//!   row up to 28 is within a relative `2^-53` of the ideal.
//!
//! ## Closeness
//!
//! Within `13.3σ'` of the center (the ideal mass beyond is below `2^-128`)
//! the implemented probabilities are within a relative `δ ≤ 2^-43` of the
//! ideal: `2^-53` from the table, `2^-61` from `exp_fixed`, and the rest
//! from evaluating `x = (z − r)²/(2σ'²) − z0²/(2σ_max²)` in `f64`, whose
//! absolute error grows with `x` and reaches `2^-43` relative at the edge of
//! that range. Over-weighting the tail rows only helps: for the Rényi
//! divergence `R_a(ideal ‖ implemented)` of the whole run of `Q_s` samples
//! (Prest, ASIACRYPT 2017, Lemma 3; Bai et al., CRYPTO 2015),
//! `log2 R_a ≤ Q_s·a·δ²/(2 ln 2) + Q_s·a·2^-125`, and an adversary with
//! advantage `ε` against the implementation has advantage at least
//! `ε^{a/(a−1)}/R_a` against the ideal sampler. With `a = 2λ = 220` and
//! `Q_ext ≤ 2^53` extractions (`Q_s = 2N·Q_ext = 2^64` leaf samples),
//! `log2 R_a < 2^-14`, so the loss is `λ/(a−1) ≈ 0.5` bit plus a `2^-64`
//! statistical distance from the tail cut.
//!
//! The paper's analysis (ePrint 2026/813, Lemma B.4) assumes an exact
//! one-dimensional sampler and bounds the Klein sampler's relative error by
//! `δ ≈ 2^-97` from the smoothing parameter alone (`ε = 2^-109`), for up to
//! `Q_ext ≤ 2^110` extractions. Supporting `2^110` extractions through the
//! Rényi argument would need `δ ≤ 2^-64`, which no double-precision sampler
//! reaches: the previous rejection sampler's `f64::exp` had `δ ≈ 2^-50`.
//! This sampler therefore does not weaken what was implemented before, but
//! the `2^-97` figure should be read as the error with an exact `SampleZ`;
//! the implementation supports the bound above instead. The centers fed in
//! are themselves doubles produced by the FFT tree, as in Falcon; their
//! rounding is not part of this accounting.
//!
//! # [`sample_poly`]: key generation's `f, g`
//!
//! `σ_f = 1.17·512 ≈ 599` is far too wide for a table scan (about 8 000
//! rows per coefficient). Instead each coefficient is a three-level
//! convolution of four draws from a fixed `D_{Z,σ₁}`,
//! `z = (a + 4b) + 18·(c + 4d)` with `σ₁ = σ_f/√(17·362) ≈ 8.059`, so
//! `σ₁²·17·362 = σ_f²` exactly. A sum `x₁ + k·x₂` of two `D_{Z,σ₁}` is
//! `D_{Z,σ₁√(1+k²)}` up to a relative `4·exp(−2π²τ²)` with
//! `τ = σ₁/√(1+k²)` (complete the square and apply Poisson summation):
//! `2^-106` for the inner level and `2^-94` for the outer. The base draw is a
//! full scan of a 108-row cumulative table over `|z|` ([`CDT_KEYGEN`]) with
//! `u64` entries, then a masked sign. Rows `0..=56` are rounded to nearest
//! (relative error `≤ 2^-25`), rows `58..=107` are rounded up (excess mass
//! `2^-58`), row 57 absorbs that rounding (relative error `2^-19`), and
//! `P(|z| ≥ 108) < 2^-132`. Key generation is a one-shot run of
//! `8N` base draws, so by the same Rényi bound its loss is below `2^-18`
//! bit. Cost: four 108-row scans per coefficient, about a quarter of a full
//! `σ_f` table scan.
//!
//! # Residual assumptions
//!
//! `f64` add, mul, compare, `floor`, `min`/`max`, and `f64 → u64`
//! conversion are assumed constant-time for normal operands, as on x86-64
//! (SSE2) and aarch64. No value here can be subnormal: every intermediate
//! is zero or has magnitude above `2^-110` (differences of doubles in
//! `[2^-54, 2^53]`, and products of at most three of them), and subnormals
//! start at `2^-1022`. `u64 × u64 → u128` and variable `u128` shifts are
//! assumed constant-time, as they are on 64-bit targets. The rejection loop
//! exits on a secret-independent coin, and the comparisons use masks with
//! [`core::hint::black_box`] to discourage the compiler from reintroducing
//! branches.
use super::N;
use super::ring::PolyZ;
use crate::{Error, VsssResult};
use core::f64::consts::{LN_2, LOG2_E};
use core::hint::black_box;
use rand_core::CryptoRng;
use std::vec::Vec;

/// Smallest leaf width [`SamplerZ`] accepts: `σ/(1.17·√q) = 2`.
pub const SIGMA_MIN: f64 = 2.0;
/// Largest leaf width [`SamplerZ`] accepts; see the module docs.
pub const SIGMA_MAX: f64 = 2.8;
/// `1/(2σ_max²)`.
const INV_TWO_SIGMA_MAX_SQ: f64 = 1.0 / (2.0 * SIGMA_MAX * SIGMA_MAX);
/// Rejection rounds before giving up. Each accepts with probability `0.625`,
/// so failure has probability `0.375^512 < 2^-724`.
const MAX_ATTEMPTS: u32 = 512;
/// Centers must stay inside the exactly representable integers.
const MAX_MAGNITUDE: f64 = (1u64 << 52) as f64;
/// `2^63` as a float, the fixed-point scale of [`exp_fixed`].
const TWO_POW_63: f64 = (1u64 << 63) as f64;
/// `2^64` as a float.
const TWO_POW_64: f64 = 2.0 * TWO_POW_63;
/// Largest shift [`bernoulli_exp`] applies; beyond it the acceptance
/// probability is below `2^-127` and rounds to that.
const MAX_SHIFT: f64 = 127.0;

/// `⌊2^127·P(z0 > j)⌉` for `z0 ← D⁺_{σ_max}`, `j = 0..=36` (`P(z0 > 37)`
/// is cut). Entries `27..=36` hold rounded-up sums instead; see the module
/// docs. Computed with 80-digit decimal arithmetic.
const RCDT_EXTRACT: [u128; 37] = [
    0x6012f5ea09daf4462b26822e15012262,
    0x421ee3381fbafd4098dbd23e06f20a10,
    0x29621c5998a6dbaf5c0592c40e360a30,
    0x1766680b0d06a1c6cacb38b59e440141,
    0x0be473d33701c15e41ae3b69b977f1a7,
    0x05690eb1b12e79647c1ddd437a9986bd,
    0x023249590a83d760fc3ac6f55df6607b,
    0x00cb302f8a1b3789b384fdfa6b3aeacb,
    0x00413a6fb873b421bccd8717b3fcdccf,
    0x001292c287f2bcceac188c79d35142d4,
    0x0004af5c657580cf9da09fa669f9f3c8,
    0x00010bbada27886ea5ab7496d34e1485,
    0x000034d87377ffb3047a3becf1231a89,
    0x000009378915c33abd57e437d926e77b,
    0x0000016b6f3e88c91ec43707b7fb0afd,
    0x0000003169c21e3a65f5628729410335,
    0x00000005ed8cb8f07e43893cf853079a,
    0x00000000a095a0e7d776c4f09eba7710,
    0x000000000efc070623ce13eb70641723,
    0x00000000013b9173f3f89eadaed82a55,
    0x000000000016e1ba046e4e0702370410,
    0x000000000001764fc73b61d086e1d562,
    0x00000000000015135bfa0e2085765d2a,
    0x000000000000010ba44c2485e50158fd,
    0x000000000000000bb217a9ce76317152,
    0x0000000000000000733f66d6eb907a78,
    0x000000000000000003e839cdd28df15b,
    0x0000000000000000001ddd3df1fcb632,
    0x00000000000000000000c905b030e22f,
    0x0000000000000000000004a78cdf54a8,
    0x0000000000000000000000184b359b3b,
    0x0000000000000000000000006fa6196d,
    0x00000000000000000000000001c3c956,
    0x0000000000000000000000000006499b,
    0x000000000000000000000000000013ba,
    0x00000000000000000000000000000037,
    0x00000000000000000000000000000001,
];

/// Key generation's convolution factors: `z = (a + K1·b) + K2·(c + K1·d)`.
const KEYGEN_K1: i64 = 4;
/// See [`KEYGEN_K1`].
const KEYGEN_K2: i64 = 18;
/// `σ₁ = σ_f/√((1 + K1²)(1 + K2²))`, the width of the base draw.
#[cfg(test)]
const SIGMA_KEYGEN_BASE: f64 = 8.059_158_210_3;

/// `⌊2^64·P(|z| > j)⌉` for `z ← D_{Z,σ₁}`, `j = 0..=106` (`P(|z| > 107)`
/// is cut). Entries `57..=106` hold rounded-up sums instead; see the module
/// docs. Computed with 80-digit decimal arithmetic.
const CDT_KEYGEN: [u64; 107] = [
    0xf353dac50313617a,
    0xda2d51fd2ada2f06,
    0xc199c7272f721af7,
    0xa9f3cd80132de83b,
    0x938b6d6a859de387,
    0x7ea309258c930d28,
    0x6b6d3a26813dce94,
    0x5a0bc0945db39568,
    0x4a8f849edbf13dbf,
    0x3cf99193f9a98eeb,
    0x313cdf444667ddb0,
    0x2740b1445b37a35a,
    0x1ee34db4b6bcbc5a,
    0x17fcce3e580b3902,
    0x1261d4d5ef58ec67,
    0x0de5f8f6c3d63340,
    0x0a5dcf787c4f383a,
    0x07a07d06e2361e15,
    0x0588cfffedb6f9fa,
    0x03f5e8ecaca08c0b,
    0x02cb8049ec6397fb,
    0x01f1dcc07dbf0531,
    0x01558e8392ca0e29,
    0x00e703d55622801d,
    0x009a0858df754990,
    0x00653d8b9e7a1382,
    0x0041971a441e5666,
    0x0029e23f421f0ade,
    0x001a5c44e04dbbd9,
    0x001059ce72479cb8,
    0x0009febf9d4569dc,
    0x0006056b1a5f233b,
    0x0003930b2f2a4c76,
    0x000217463c0b534d,
    0x0001348a0447d6cc,
    0x0000af3d1c262578,
    0x000062112f1aa9fc,
    0x00003612a26f915a,
    0x00001d6020308bb7,
    0x00000fb90ee4d460,
    0x0000084a832c8663,
    0x0000044eae86a25e,
    0x000002345e8a9ae3,
    0x0000011c90acdb2c,
    0x0000008d59bbd98e,
    0x000000452aedd6c4,
    0x0000002157911226,
    0x0000000fd5339505,
    0x0000000767fbc929,
    0x0000000369a56d7c,
    0x000000018c8c4695,
    0x00000000b14ce46e,
    0x000000004e15f982,
    0x0000000021dffde8,
    0x000000000e79a76e,
    0x000000000617b7a8,
    0x000000000286a20d,
    0x0000000001080e9a,
    0x00000000006a3580,
    0x00000000002a13c1,
    0x0000000000106b54,
    0x0000000000064f94,
    0x00000000000263a9,
    0x000000000000e424,
    0x00000000000053de,
    0x0000000000001e6c,
    0x0000000000000aed,
    0x00000000000003ec,
    0x0000000000000171,
    0x0000000000000094,
    0x0000000000000048,
    0x000000000000002e,
    0x0000000000000025,
    0x0000000000000022,
    0x0000000000000021,
    0x0000000000000020,
    0x000000000000001f,
    0x000000000000001e,
    0x000000000000001d,
    0x000000000000001c,
    0x000000000000001b,
    0x000000000000001a,
    0x0000000000000019,
    0x0000000000000018,
    0x0000000000000017,
    0x0000000000000016,
    0x0000000000000015,
    0x0000000000000014,
    0x0000000000000013,
    0x0000000000000012,
    0x0000000000000011,
    0x0000000000000010,
    0x000000000000000f,
    0x000000000000000e,
    0x000000000000000d,
    0x000000000000000c,
    0x000000000000000b,
    0x000000000000000a,
    0x0000000000000009,
    0x0000000000000008,
    0x0000000000000007,
    0x0000000000000006,
    0x0000000000000005,
    0x0000000000000004,
    0x0000000000000003,
    0x0000000000000002,
    0x0000000000000001,
];

/// `⌊2^63/k!⌉` for `k = 0..=18`: the Taylor coefficients of `exp(−x)` in
/// `2^63` fixed point.
const EXP_COEFFS: [u64; 19] = [
    0x8000000000000000,
    0x8000000000000000,
    0x4000000000000000,
    0x1555555555555555,
    0x0555555555555555,
    0x0111111111111111,
    0x002d82d82d82d82e,
    0x0006806806806807,
    0x0000d00d00d00d01,
    0x0000171de3a556c7,
    0x0000024fc9f6ef14,
    0x00000035cc8acfeb,
    0x000000047bb63bfe,
    0x000000005849184f,
    0x00000000064e5d2a,
    0x00000000006b9fd0,
    0x000000000006b9fd,
    0x000000000000654b,
    0x00000000000005a1,
];

/// An isochronous sampler for `D_{Z,σ',c}` with a fixed width
/// `σ' ∈ [σ_min, σ_max]` and any center; see the module docs.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize))]
pub struct SamplerZ {
    /// The width `σ'`.
    sigma: f64,
    /// `1/(2σ'²)`.
    inv_two_sigma_sq: f64,
    /// `σ_min/σ'` in `2^63` fixed point.
    ccs: u64,
}

impl SamplerZ {
    /// Precompute for width `sigma`. Fails unless
    /// `σ_min ≤ sigma ≤ σ_max`, the range the base table covers.
    pub fn new(sigma: f64) -> VsssResult<Self> {
        if !(SIGMA_MIN..=SIGMA_MAX).contains(&sigma) {
            return Err(Error::Lattice("Gaussian width outside [σ_min, σ_max]"));
        }
        Ok(Self {
            sigma,
            inv_two_sigma_sq: 1.0 / (2.0 * sigma * sigma),
            // In (0.71, 1]; at exactly 1 the conversion yields 2^63, which
            // fits.
            ccs: (SIGMA_MIN / sigma * TWO_POW_63) as u64,
        })
    }

    /// The width `σ'`.
    pub fn sigma(&self) -> f64 {
        self.sigma
    }

    /// Draw `z ← D_{Z,σ',center}`. Fails if `|center| ≥ 2^52` or is not a
    /// number, or, with probability below `2^-724`, if every round rejects.
    pub fn sample<R: CryptoRng + ?Sized>(&self, center: f64, rng: &mut R) -> VsssResult<i64> {
        if center.is_nan() || center.abs() >= MAX_MAGNITUDE {
            return Err(Error::Lattice("Gaussian center out of range"));
        }
        let floor = center.floor();
        let r = center - floor;
        for _ in 0..MAX_ATTEMPTS {
            let z0 = half_gaussian(rng);
            let b = (rng.next_u64() & 1) as i64;
            // z = z0 + 1 when b = 1, −z0 when b = 0.
            let z = b + (2 * b - 1) * z0;
            let dz = z as f64 - r;
            let z0f = z0 as f64;
            // Non-negative up to rounding; clamp so the shift stays valid.
            let x = (dz * dz * self.inv_two_sigma_sq - z0f * z0f * INV_TWO_SIGMA_MAX_SQ).max(0.0);
            if bernoulli_exp(x, self.ccs, rng) != 0 {
                return Ok(floor as i64 + z);
            }
        }
        Err(Error::Lattice("Gaussian sampler exhausted its attempts"))
    }
}

/// `z0 ← D⁺_{σ_max}` by a full, branch-free scan of [`RCDT_EXTRACT`]:
/// `z0 = #{j : u < T[j]}` for `u` uniform on `[0, 2^127)`.
fn half_gaussian<R: CryptoRng + ?Sized>(rng: &mut R) -> i64 {
    let u = uniform_127(rng);
    let count = RCDT_EXTRACT
        .iter()
        .fold(0u64, |acc, &t| acc + (ct_lt_u128(u, t) & 1));
    count as i64
}

/// A Bernoulli trial with probability `ccs·exp(−x)` for `x ≥ 0`, `ccs` in
/// `2^63` fixed point: all ones on success, zero otherwise.
fn bernoulli_exp<R: CryptoRng + ?Sized>(x: f64, ccs: u64, rng: &mut R) -> u64 {
    // x = s·ln 2 + r with r ∈ [0, ln 2); s saturates at 127, past which
    // the probability is below 2^-127 anyway.
    let s = (x * LOG2_E).floor().min(MAX_SHIFT);
    let r = x - s * LN_2;
    // Saturating conversions absorb the rounding that can push `r` a few
    // ulps outside [0, ln 2).
    let y = exp_fixed((r * TWO_POW_64) as u64);
    let scaled = ((u128::from(y) * u128::from(ccs)) >> 63) as u64;
    let threshold = (u128::from(scaled) << 64) >> (s as u32);
    ct_lt_u128(uniform_127(rng), threshold)
}

/// `2^63·exp(−x)` for `x = x_fixed/2^64 ∈ [0, 1)`, by Horner's rule over
/// [`EXP_COEFFS`] in `u64` fixed point. Every intermediate is in
/// `(0, 2^63]`, so nothing wraps.
fn exp_fixed(x_fixed: u64) -> u64 {
    let x = u128::from(x_fixed);
    EXP_COEFFS
        .iter()
        .rev()
        .skip(1)
        .fold(EXP_COEFFS[EXP_COEFFS.len() - 1], |y, &c| {
            c - ((u128::from(y) * x) >> 64) as u64
        })
}

/// A uniform integer in `[0, 2^127)`.
fn uniform_127<R: CryptoRng + ?Sized>(rng: &mut R) -> u128 {
    let hi = u128::from(rng.next_u64() >> 1);
    (hi << 64) | u128::from(rng.next_u64())
}

/// All ones if `a < b`, else zero, without a branch: the borrow out of
/// `a − b` (Hacker's Delight, §2-12).
fn ct_lt_u64(a: u64, b: u64) -> u64 {
    let borrow = ((!a & b) | (!(a ^ b) & a.wrapping_sub(b))) >> 63;
    black_box(0u64.wrapping_sub(borrow))
}

/// All ones if `a == b`, else zero, without a branch.
fn ct_eq_u64(a: u64, b: u64) -> u64 {
    let x = a ^ b;
    // The top bit of `x | −x` is set exactly when `x ≠ 0`.
    let nonzero = (x | x.wrapping_neg()) >> 63;
    black_box(0u64.wrapping_sub(nonzero ^ 1))
}

/// All ones if `a < b`, else zero, without a branch.
fn ct_lt_u128(a: u128, b: u128) -> u64 {
    let (ah, al) = ((a >> 64) as u64, a as u64);
    let (bh, bl) = ((b >> 64) as u64, b as u64);
    ct_lt_u64(ah, bh) | (ct_eq_u64(ah, bh) & ct_lt_u64(al, bl))
}

/// One draw from `D_{Z,σ₁}` by a full scan of [`CDT_KEYGEN`] and a masked
/// sign.
fn keygen_base<R: CryptoRng + ?Sized>(rng: &mut R) -> i64 {
    let u = rng.next_u64();
    let magnitude = CDT_KEYGEN
        .iter()
        .fold(0u64, |acc, &t| acc + (ct_lt_u64(u, t) & 1));
    let sign = 0u64.wrapping_sub(rng.next_u64() & 1);
    // Negate under the mask: (m ^ s) − s is −m when s is all ones.
    (magnitude ^ sign).wrapping_sub(sign) as i64
}

/// Draw `z ← D_{Z,σ_f}` centered at zero, as the convolution
/// `(a + 4b) + 18·(c + 4d)` of four draws from the fixed `D_{Z,σ₁}` table;
/// see the module docs.
pub fn sample_keygen_z<R: CryptoRng + ?Sized>(rng: &mut R) -> i64 {
    let inner = |rng: &mut R| keygen_base(rng) + KEYGEN_K1 * keygen_base(rng);
    inner(rng) + KEYGEN_K2 * inner(rng)
}

/// Sample a polynomial from `D_{N,σ_f}`: every coefficient independently
/// from [`sample_keygen_z`].
pub fn sample_poly<R: CryptoRng + ?Sized>(rng: &mut R) -> VsssResult<PolyZ> {
    let coeffs = (0..N).map(|_| sample_keygen_z(rng)).collect::<Vec<_>>();
    PolyZ::from_coeffs(coeffs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lattice::SIGMA_F;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    /// Sample mean and variance of `samples` draws.
    fn moments(xs: &[f64]) -> (f64, f64) {
        let n = xs.len() as f64;
        let mean = xs.iter().sum::<f64>() / n;
        let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
        (mean, var)
    }

    /// The ideal pmf of `D_{Z,σ,c}` on `lo..=hi`, normalized over a wide
    /// window.
    fn ideal_pmf(sigma: f64, center: f64, lo: i64, hi: i64) -> Vec<f64> {
        let rho = |z: i64| (-(z as f64 - center).powi(2) / (2.0 * sigma * sigma)).exp();
        let span = (20.0 * sigma).ceil() as i64;
        let total: f64 = (center.round() as i64 - span..=center.round() as i64 + span)
            .map(rho)
            .sum();
        (lo..=hi).map(|z| rho(z) / total).collect()
    }

    /// Pearson's chi-square of `counts` against `expected`, merging bins
    /// whose expected count is below 10 into their neighbours.
    fn chi_square(counts: &[u64], expected: &[f64]) -> (f64, usize) {
        let mut stat = 0.0;
        let mut dof = 0usize;
        let (mut c, mut e) = (0.0f64, 0.0f64);
        for (&count, &exp) in counts.iter().zip(expected) {
            c += count as f64;
            e += exp;
            if e >= 10.0 {
                stat += (c - e).powi(2) / e;
                dof += 1;
                c = 0.0;
                e = 0.0;
            }
        }
        if e > 0.0 {
            stat += (c - e).powi(2) / e;
            dof += 1;
        }
        (stat, dof - 1)
    }

    /// Fail unless `stat` is within six standard deviations of a chi-square
    /// with `dof` degrees of freedom.
    fn assert_chi_square(stat: f64, dof: usize, what: &str) {
        let dof = dof as f64;
        let bound = dof + 6.0 * (2.0 * dof).sqrt();
        assert!(
            stat <= bound,
            "{what}: chi-square {stat:.1} on {dof} dof exceeds {bound:.1}"
        );
    }

    #[test]
    fn sampler_z_mean_and_variance_match_at_several_settings() {
        let samples = 40_000;
        let mut rng = StdRng::from_seed([21u8; 32]);
        for &(sigma, center) in &[
            (SIGMA_MIN, 0.0),
            (2.3, 0.37),
            (2.5, -1234.75),
            (SIGMA_MAX, 1e9 + 0.5),
        ] {
            let sampler = SamplerZ::new(sigma).expect("in range");
            let xs: Vec<f64> = (0..samples)
                .map(|_| sampler.sample(center, &mut rng).expect("valid") as f64)
                .collect();
            let (mean, var) = moments(&xs);
            let stderr = sigma / (samples as f64).sqrt();
            assert!(
                (mean - center).abs() < 5.0 * stderr,
                "σ = {sigma}, c = {center}: mean {mean}"
            );
            assert!(
                (var / (sigma * sigma) - 1.0).abs() < 0.05,
                "σ = {sigma}, c = {center}: variance {var}"
            );
        }
    }

    #[test]
    fn sampler_z_matches_the_ideal_pmf() {
        let samples = 400_000;
        let mut rng = StdRng::from_seed([24u8; 32]);
        let settings: [(f64, f64); 3] = [(2.0, 0.0), (2.4, 0.37), (SIGMA_MAX, -3.9)];
        for (sigma, center) in settings {
            let sampler = SamplerZ::new(sigma).expect("in range");
            let (lo, hi) = (center.round() as i64 - 20, center.round() as i64 + 20);
            let mut counts = std::vec![0u64; (hi - lo + 1) as usize];
            for _ in 0..samples {
                let z = sampler.sample(center, &mut rng).expect("valid");
                assert!((lo..=hi).contains(&z), "z = {z} is 8σ out");
                counts[(z - lo) as usize] += 1;
            }
            let expected: Vec<f64> = ideal_pmf(sigma, center, lo, hi)
                .into_iter()
                .map(|p| p * samples as f64)
                .collect();
            let (stat, dof) = chi_square(&counts, &expected);
            assert_chi_square(stat, dof, &std::format!("σ = {sigma}, c = {center}"));
        }
    }

    #[test]
    fn sampler_z_rejects_bad_parameters() {
        let mut rng = StdRng::from_seed([22u8; 32]);
        for bad in [0.0, -1.0, f64::NAN, SIGMA_MIN - 1e-9, SIGMA_MAX + 1e-9] {
            assert!(SamplerZ::new(bad).is_err(), "σ = {bad}");
        }
        let sampler = SamplerZ::new(SIGMA_MIN).expect("in range");
        assert_eq!(sampler.sigma(), SIGMA_MIN);
        for bad in [
            f64::INFINITY,
            f64::NAN,
            1e300,
            MAX_MAGNITUDE,
            -MAX_MAGNITUDE,
        ] {
            assert!(sampler.sample(bad, &mut rng).is_err(), "c = {bad}");
        }
        // The boundary widths work, and the output stays near the center.
        for sampler in [sampler, SamplerZ::new(SIGMA_MAX).expect("in range")] {
            for center in [MAX_MAGNITUDE - 1024.0, -(MAX_MAGNITUDE - 1024.0), 7.4999] {
                let z = sampler.sample(center, &mut rng).expect("valid");
                assert!((z as f64 - center).abs() < 40.0, "z = {z}, c = {center}");
            }
        }
    }

    #[test]
    fn rcdt_extract_matches_the_half_gaussian() {
        // Entries are P(z0 > j) for the half-Gaussian of width σ_max, to
        // the precision f64 allows; the tail rows are rounded up.
        let rho = |k: usize| (-(k as f64).powi(2) * INV_TWO_SIGMA_MAX_SQ).exp();
        let total: f64 = (0..200).map(rho).sum();
        let scale = 2f64.powi(127);
        for (j, &t) in RCDT_EXTRACT.iter().enumerate() {
            let tail: f64 = (j + 1..200).map(rho).sum::<f64>() / total;
            let got = t as f64 / scale;
            if j < 27 {
                assert!((got / tail - 1.0).abs() < 1e-12, "row {j}: {got} vs {tail}");
            } else {
                assert!(got >= tail * (1.0 - 1e-12), "row {j}: {got} < {tail}");
            }
        }
        assert!(RCDT_EXTRACT.windows(2).all(|w| w[0] > w[1]));
        // The cut mass beyond the last row is negligible.
        let cut: f64 = (RCDT_EXTRACT.len() + 1..200).map(rho).sum::<f64>() / total;
        assert!(cut < 2f64.powi(-130), "cut {cut}");
    }

    #[test]
    fn cdt_keygen_matches_the_base_gaussian() {
        let sigma = SIGMA_KEYGEN_BASE;
        let k1 = KEYGEN_K1 as f64;
        let k2 = KEYGEN_K2 as f64;
        assert!((sigma * ((1.0 + k1 * k1) * (1.0 + k2 * k2)).sqrt() - SIGMA_F).abs() < 1e-8);
        let rho = |k: usize| (-(k as f64).powi(2) / (2.0 * sigma * sigma)).exp();
        let total: f64 = rho(0) + 2.0 * (1..600).map(rho).sum::<f64>();
        let scale = 2f64.powi(64);
        for (j, &t) in CDT_KEYGEN.iter().enumerate() {
            let tail = 2.0 * (j + 1..600).map(rho).sum::<f64>() / total * scale;
            // Within one unit plus f64 slack of the ideal, in units of 2^-64.
            let slack = 1.0 + 1e-9 * tail;
            if j < 57 {
                assert!((t as f64 - tail).abs() <= slack, "entry {j}: {t} vs {tail}");
            } else {
                assert!(t as f64 >= tail - slack, "entry {j}: {t} < {tail}");
            }
        }
        assert!(CDT_KEYGEN.windows(2).all(|w| w[0] > w[1]));
        let cut: f64 = 2.0 * (CDT_KEYGEN.len() + 1..600).map(rho).sum::<f64>() / total;
        assert!(cut < 2f64.powi(-130), "cut {cut}");
    }

    #[test]
    fn exp_fixed_matches_exp_and_the_reference_vectors() {
        // Independently computed with 80-digit decimal arithmetic.
        const VECTORS: [(u64, u64); 6] = [
            (0x0000000000000000, 0x8000000000000000),
            (0x0000000000000001, 0x8000000000000000),
            (0x1000000000000000, 0x783eafef1c0a8f3a),
            (0x5555555555555555, 0x5bb74c48bcba9345),
            (0x8000000000000000, 0x4da2cbf1be5827fa),
            (0xb17217f7d1cf79ab, 0x4000000000000001),
        ];
        for (x, y) in VECTORS {
            assert_eq!(exp_fixed(x), y, "x = {x:#x}");
        }
        for i in 0..=1000u64 {
            let x = LN_2 * i as f64 / 1000.0;
            let got = exp_fixed((x * TWO_POW_64) as u64) as f64 / TWO_POW_63;
            assert!(((-x).exp() / got - 1.0).abs() < 1e-14, "x = {x}");
        }
        for (k, &c) in EXP_COEFFS.iter().enumerate() {
            let factorial: f64 = (1..=k).map(|i| i as f64).product();
            // Rounded to the nearest unit of 2^-63.
            let exact = TWO_POW_63 / factorial;
            assert!((c as f64 - exact).abs() <= 0.5 + 1e-9 * exact, "k = {k}");
        }
    }

    #[test]
    fn bernoulli_exp_has_the_right_acceptance_rate() {
        let mut rng = StdRng::from_seed([25u8; 32]);
        let trials = 200_000;
        for &(x, ccs) in &[
            (0.0, 1.0),
            (0.3, 1.0),
            (2.5, 0.75),
            (10.0, 0.9),
            (90.0, 1.0),
        ] {
            let ccs_fixed = (ccs * TWO_POW_63) as u64;
            let hits = (0..trials)
                .filter(|_| bernoulli_exp(x, ccs_fixed, &mut rng) != 0)
                .count() as f64;
            let p = ccs * (-x).exp();
            let tolerance = 5.0 * (p * (1.0 - p) / trials as f64).sqrt() + 1e-9;
            assert!(
                (hits / trials as f64 - p).abs() <= tolerance,
                "x = {x}, ccs = {ccs}: {hits} hits"
            );
        }
        // A success mask is all ones, a failure is zero.
        let mask = bernoulli_exp(0.0, u64::MAX, &mut rng);
        assert_eq!(mask, u64::MAX);
    }

    #[test]
    fn constant_time_comparisons_match_the_operators() {
        let mut rng = StdRng::from_seed([26u8; 32]);
        let edge = [0u64, 1, 1 << 63, (1 << 63) - 1, u64::MAX - 1, u64::MAX];
        let mut pairs: Vec<(u64, u64)> = edge
            .iter()
            .flat_map(|&a| edge.iter().map(move |&b| (a, b)))
            .collect();
        pairs.extend((0..10_000).map(|_| (rng.random::<u64>(), rng.random::<u64>())));
        pairs.extend((0..1000).map(|_| {
            let a = rng.random::<u64>();
            (a, a)
        }));
        for &(a, b) in &pairs {
            assert_eq!(
                ct_lt_u64(a, b),
                if a < b { u64::MAX } else { 0 },
                "{a} < {b}"
            );
            assert_eq!(
                ct_eq_u64(a, b),
                if a == b { u64::MAX } else { 0 },
                "{a} == {b}"
            );
            for &(c, d) in &[(a, b), (b, a), (a, a)] {
                let x = (u128::from(c) << 64) | u128::from(d);
                let y = (u128::from(d) << 64) | u128::from(c);
                assert_eq!(ct_lt_u128(x, y), if x < y { u64::MAX } else { 0 });
                let same_hi = (u128::from(c) << 64) | u128::from(c);
                assert_eq!(
                    ct_lt_u128(x, same_hi),
                    if x < same_hi { u64::MAX } else { 0 }
                );
            }
        }
        for _ in 0..1000 {
            let u = uniform_127(&mut rng);
            assert!(u < 1u128 << 127);
        }
    }

    #[test]
    fn keygen_sampler_has_width_sigma_f_and_the_ideal_shape() {
        let mut rng = StdRng::from_seed([27u8; 32]);
        let samples = 200_000;
        let xs: Vec<f64> = (0..samples)
            .map(|_| sample_keygen_z(&mut rng) as f64)
            .collect();
        let (mean, var) = moments(&xs);
        assert!(
            mean.abs() < 5.0 * SIGMA_F / (samples as f64).sqrt(),
            "mean {mean}"
        );
        assert!(
            (var / (SIGMA_F * SIGMA_F) - 1.0).abs() < 0.02,
            "variance {var}"
        );
        // Chi-square on bins of width σ_f/8 out to ±5σ_f.
        let width = SIGMA_F / 8.0;
        let bins = 80usize;
        let mut counts = std::vec![0u64; bins];
        // Anything past ±5σ_f lands in the edge bins.
        let bin = |x: f64| {
            (((x / width) + bins as f64 / 2.0).floor() as i64).clamp(0, bins as i64 - 1) as usize
        };
        for &x in &xs {
            counts[bin(x)] += 1;
        }
        let pmf = ideal_pmf(SIGMA_F, 0.0, -(6 * SIGMA_F as i64), 6 * SIGMA_F as i64);
        let lo = -(6 * SIGMA_F as i64);
        let mut expected = std::vec![0.0f64; bins];
        for (i, p) in pmf.iter().enumerate() {
            expected[bin((lo + i as i64) as f64)] += p * samples as f64;
        }
        let (stat, dof) = chi_square(&counts, &expected);
        assert_chi_square(stat, dof, "keygen sampler");
    }

    #[test]
    fn keygen_base_is_symmetric_and_bounded() {
        let mut rng = StdRng::from_seed([28u8; 32]);
        let xs: Vec<f64> = (0..100_000).map(|_| keygen_base(&mut rng) as f64).collect();
        let (mean, var) = moments(&xs);
        assert!(mean.abs() < 0.15, "mean {mean}");
        assert!(
            (var.sqrt() / SIGMA_KEYGEN_BASE - 1.0).abs() < 0.02,
            "σ {}",
            var.sqrt()
        );
        assert!(xs.iter().all(|x| x.abs() <= CDT_KEYGEN.len() as f64));
    }

    #[test]
    fn sample_poly_has_n_centered_coefficients() {
        let mut rng = StdRng::from_seed([23u8; 32]);
        let p = sample_poly(&mut rng).expect("valid");
        assert_eq!(p.coeffs().len(), N);
        let mean = p.eval_at_one() as f64 / N as f64;
        assert!(mean.abs() < 5.0 * SIGMA_F / (N as f64).sqrt());
    }

    /// Welch's t statistic between two samples.
    fn welch_t(a: &[f64], b: &[f64]) -> f64 {
        let (ma, va) = moments(a);
        let (mb, vb) = moments(b);
        (ma - mb) / (va / a.len() as f64 + vb / b.len() as f64).sqrt()
    }

    /// Timings below the `q`-quantile of the pooled data, per class, as
    /// dudect does to shed interrupt noise.
    fn crop(a: &[f64], b: &[f64], q: f64) -> (Vec<f64>, Vec<f64>) {
        let mut pooled: Vec<f64> = a.iter().chain(b).copied().collect();
        pooled.sort_by(f64::total_cmp);
        let cut = pooled[((pooled.len() - 1) as f64 * q) as usize];
        let keep = |xs: &[f64]| xs.iter().copied().filter(|&x| x <= cut).collect();
        (keep(a), keep(b))
    }

    /// A dudect-style leakage test: fixed (center, width) against random
    /// ones, interleaved at random. Noisy by nature, so ignored by default;
    /// run in release with `--ignored --nocapture`. Passes when
    /// `|t| < 4.5` on the raw and on the cropped timings.
    #[test]
    #[ignore = "timing test; run in release with --ignored"]
    fn timing_is_independent_of_center_and_width() {
        use std::time::Instant;
        let mut rng = StdRng::from_seed([29u8; 32]);
        let fixed = SamplerZ::new(SIGMA_MIN).expect("in range");
        let widths: Vec<SamplerZ> = (0..=64)
            .map(|i| SamplerZ::new(SIGMA_MIN + (SIGMA_MAX - SIGMA_MIN) * i as f64 / 64.0))
            .collect::<VsssResult<_>>()
            .expect("in range");
        let batch = 256;
        let measurements = 40_000;
        let mut classes: [Vec<f64>; 2] = [Vec::new(), Vec::new()];
        let mut sink = 0i64;
        // Warm up.
        for _ in 0..1000 {
            sink ^= fixed.sample(0.5, &mut rng).expect("valid");
        }
        for _ in 0..measurements {
            let class = rng.random::<bool>() as usize;
            let (sampler, center) = if class == 0 {
                (&fixed, 0.5)
            } else {
                (
                    &widths[rng.random_range(0..widths.len())],
                    rng.random_range(-1_048_576.0..1_048_576.0),
                )
            };
            let start = Instant::now();
            for _ in 0..batch {
                sink ^= sampler.sample(center, &mut rng).expect("valid");
            }
            classes[class].push(start.elapsed().as_nanos() as f64);
        }
        let t_raw = welch_t(&classes[0], &classes[1]);
        let (a, b) = crop(&classes[0], &classes[1], 0.9);
        let t_cropped = welch_t(&a, &b);
        let (m0, _) = moments(&classes[0]);
        let (m1, _) = moments(&classes[1]);
        std::println!(
            "dudect: n = {}/{}, mean {:.1}/{:.1} ns per {batch}, |t| raw = {:.2}, cropped = {:.2} (sink {sink})",
            classes[0].len(),
            classes[1].len(),
            m0,
            m1,
            t_raw.abs(),
            t_cropped.abs()
        );
        assert!(t_raw.abs() < 4.5 && t_cropped.abs() < 4.5);
    }
}
