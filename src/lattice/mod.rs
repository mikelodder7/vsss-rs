/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Lattice building blocks for a post-quantum publicly verifiable secret
//! sharing scheme.
//!
//! # Security level
//!
//! **About 110-bit classical security, below the 128-bit level of the rest
//! of this crate.** The parameters `N = 1024`, `q = 2^29` are the paper's;
//! its Table 5 (ePrint 2026/813, App. B.3) estimates the cheapest attack,
//! BDD, at `2^110.1` classical operations with the lattice estimator.
//! Quantum security is lower and is not estimated.
//!
//! **Experimental and unaudited. Do not use to protect real secrets.** See
//! [Timing](#timing) for what is and is not constant-time.
//!
//! This module follows Kate, Mukherjee, Saleem, Sarkar, and Sinha,
//! "Practical Post-Quantum Secure Publicly Verifiable Secret Sharing and
//! Applications", ePrint 2026/813, which builds on the Ducas–Lyubashevsky–Prest
//! NTRU identity-based encryption scheme. It currently provides:
//!
//! - [`PolyQ`], the ring `R_q = Z_q[x]/(x^N + 1)` with `N = 1024` and
//!   `q = 2^29`, and [`PolyZ`], the integer ring `Z[x]/(x^N + 1)`;
//! - [`hash_to_ring`] and [`hash_to_mask`], the hashes `H` and `H'`, generic
//!   over any [`digest::Digest`];
//! - [`SamplerZ`] and [`sample_poly`], isochronous discrete Gaussian
//!   samplers over the integers for the extraction leaves and for `f, g`;
//! - [`keygen`], which produces a [`MasterSecretKey`] (the NTRU trapdoor
//!   `f, g, F, G` with `f·G − g·F = q`) and a [`MasterPublicKey`]
//!   (`h = g·f⁻¹ mod q`);
//! - the identity-based encryption: [`extract`] (a Klein/GPV sampler over
//!   the trapdoor basis in Falcon's fast-Fourier form), [`verify_key`],
//!   [`encrypt`], and [`decrypt`];
//! - [`pvss`], the publicly verifiable secret sharing scheme of Sec. 5.
//!
//! # Timing
//!
//! The Gaussian samplers are isochronous (Howe–Prest–Ricosset–Rossi, the
//! Falcon design): the extraction leaves and key generation's `f, g` run in
//! time independent of the trapdoor, the centers, and the values drawn, with
//! fixed table scans, masked compares, and a fixed-point `exp`. Their
//! rejection loops exit on coins whose law does not depend on secrets. The
//! per-sample floating point in the sampler and FFT paths is add, multiply,
//! compare, and round only; divisions, square roots, and transcendental
//! functions run once per trapdoor or on public data. What remains assumed
//! or variable-time:
//!
//! - `f64` add, mul, compare, `floor`/`round`, `min`/`max`, and `f64 → u64`
//!   conversion are taken to be constant-time for normal operands, as on
//!   x86-64 (SSE2) and aarch64; subnormals cannot arise (the `fft` module
//!   docs and [`SamplerZ`] give the magnitude bounds). `u64 × u64
//!   → u128` multiplication and variable `u128` shifts are taken to be
//!   constant-time, as they are on 64-bit targets. Mask-based selection
//!   relies on the compiler not reintroducing branches; `black_box` hints
//!   discourage it but do not guarantee it.
//! - Key generation's candidate rejection (parity, Gram–Schmidt norm,
//!   `gcd`, the solver's round-off budget) is variable-time, but depends only on candidates that are
//!   discarded and independent of the key returned.
//! - The NTRU solver runs on fixed-width two's-complement integers
//!   (`crypto-bigint`) with widths and loop counts fixed per recursion level,
//!   a Bernstein–Yang base case, and constant-time selects for every
//!   secret-dependent quantity; see `ntru` for the width derivation. Its
//!   intermediate integers are not wiped.
//! - Encryption and decryption ([`encrypt`], [`decrypt`]) have their own
//!   accounting.
//!
//! The sampling tree and workspace, the encryption randomness, the identity
//! keys, and the PVSS secrets are wiped on drop.
//!
//! The one-dimensional samplers are within a relative `2^-43` of the ideal
//! distribution, which supports about `2^53` extractions at a loss under one
//! bit by the Rényi-divergence argument; [`SamplerZ`] gives the derivation
//! and explains why the paper's `2^-97` figure assumes an exact sampler.
mod fft;
mod gaussian;
mod hash;
mod ibe;
mod keygen;
mod ntru;
mod poly;
pub mod pvss;
mod ring;
mod sampler;

pub use gaussian::{SIGMA_MAX, SIGMA_MIN, SamplerZ, sample_keygen_z, sample_poly};
pub use hash::{hash_to_mask, hash_to_ring};
pub use ibe::{Ciphertext, IdentitySecretKey, decrypt, encrypt, extract, verify_key};
pub use keygen::{MasterPublicKey, MasterSecretKey, gram_schmidt_norm, keygen};
pub use ring::{PolyQ, PolyZ};

/// Ring degree `N`; the ring is `Z_q[x]/(x^N + 1)`.
pub const N: usize = 1024;
/// `log2(q)`.
pub const LOG_Q: u32 = 29;
/// Modulus `q = 2^29`. It is a power of two, so there is no NTT modulo `q`.
pub const Q: u32 = 1 << LOG_Q;
/// Width of the key-generation Gaussian, `σ_f = 1.17·√(q / 2N) = 1.17·512`.
pub const SIGMA_F: f64 = 1.17 * 512.0;
/// Bound on the Gram–Schmidt norm of the trapdoor basis, `1.17·√q`.
/// `√(2^29) = 2^14·√2`.
pub const GS_NORM_BOUND: f64 = 1.17 * 16384.0 * core::f64::consts::SQRT_2;
/// Width of the key-extraction sampler, `σ = 2·1.17·√q`.
pub const SIGMA_EXTRACT: f64 = 2.0 * GS_NORM_BOUND;
/// Bound `Γ_key` on `‖(s1, s2)‖₂` that a valid identity key must meet.
pub const GAMMA_KEY: u64 = 3_120_000;
/// Bound `B_x` on `‖(r, e1)‖₂` for the encryption randomness. The vectors
/// are ternary, so `‖(r, e1)‖₂² = wt(r) + wt(e1) ≤ B_x²`.
pub const B_X: usize = 40;
/// Low bits dropped from `v` by encryption, `ℓ`; `v` is rounded to a
/// multiple of `2^ℓ`.
pub const ROUNDING_BITS: u32 = 24;

/// Fixtures shared by the lattice tests.
#[cfg(test)]
pub(crate) mod test_support {
    use super::{MasterPublicKey, MasterSecretKey, keygen};
    use rand::{SeedableRng, rngs::StdRng};
    use std::sync::OnceLock;
    use std::vec::Vec;

    /// Receivers whose keys the tests share: one debug-build key generation
    /// takes several seconds, so they are made once, in parallel.
    pub(crate) const RECEIVERS: usize = 4;

    /// `RECEIVERS` master key pairs from fixed seeds.
    pub(crate) fn keys() -> &'static [(MasterSecretKey, MasterPublicKey)] {
        static KEYS: OnceLock<Vec<(MasterSecretKey, MasterPublicKey)>> = OnceLock::new();
        KEYS.get_or_init(|| {
            std::thread::scope(|scope| {
                let handles: Vec<_> = (0..RECEIVERS)
                    .map(|i| {
                        scope.spawn(move || {
                            keygen(StdRng::from_seed([0x50 + i as u8; 32])).expect("keygen")
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| h.join().expect("keygen thread"))
                    .collect()
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_match_the_paper() {
        assert_eq!(Q, 536_870_912);
        let q = f64::from(Q);
        let n = N as f64;
        assert!((SIGMA_F - 1.17 * (q / (2.0 * n)).sqrt()).abs() < 1e-9);
        assert!((GS_NORM_BOUND - 1.17 * q.sqrt()).abs() < 1e-6);
        assert!((GS_NORM_BOUND - 27_109.456).abs() < 1e-2);
        assert!((SIGMA_EXTRACT - 2.0 * 1.17 * q.sqrt()).abs() < 1e-6);
        assert!((SIGMA_EXTRACT - 54_218.91).abs() < 1e-1);
        // Γ_key sits above the expected key norm σ·√(2N).
        assert!(GAMMA_KEY as f64 > SIGMA_EXTRACT * (2.0 * n).sqrt());
        assert_eq!(B_X * B_X, 1600);
        assert_eq!(ROUNDING_BITS, 24);
    }
}
