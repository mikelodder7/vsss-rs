/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! NTRU trapdoor generation (the IBE `KeyGen`, App. B.3 of ePrint 2026/813).
use super::fft::fft;
use super::gaussian::sample_poly;
use super::ring::{PolyQ, PolyZ};
use super::{GS_NORM_BOUND, Q, SIGMA_F, lattice_error, ntru};
use crate::VsssResult;
use core::fmt::{self, Debug, Formatter};
use rand_core::CryptoRng;
use std::vec::Vec;

/// Candidate `(f, g)` pairs tried before key generation gives up. In a
/// 200-candidate measurement, 49% had `f(1)` odd, 7.5% met the norm bound,
/// and 3 passed every check (about 1.5%), so 10 000 attempts fail with
/// probability near `e^-150`. Rejected candidates are cheap: only those that
/// pass the parity and norm tests reach the NTRU solver.
const MAX_KEYGEN_ATTEMPTS: usize = 10_000;

/// The master secret key: the NTRU trapdoor basis
/// `B = [[A(g), −A(f)], [A(G), −A(F)]]`, stored as `f, g, F, G` with
/// `f·G − g·F = q` over `Z[x]/(x^N + 1)`.
#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct MasterSecretKey {
    f: PolyZ,
    g: PolyZ,
    big_f: PolyZ,
    big_g: PolyZ,
}

impl Debug for MasterSecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("MasterSecretKey { .. }")
    }
}

impl MasterSecretKey {
    /// The trapdoor polynomial `f`.
    pub fn f(&self) -> &PolyZ {
        &self.f
    }

    /// The trapdoor polynomial `g`.
    pub fn g(&self) -> &PolyZ {
        &self.g
    }

    /// The trapdoor polynomial `F`.
    pub fn big_f(&self) -> &PolyZ {
        &self.big_f
    }

    /// The trapdoor polynomial `G`.
    pub fn big_g(&self) -> &PolyZ {
        &self.big_g
    }

    /// The matching public key `h = g·f⁻¹ mod q`.
    pub fn public_key(&self) -> VsssResult<MasterPublicKey> {
        let f_inv = PolyQ::from(&self.f).inverse()?;
        Ok(MasterPublicKey {
            h: &PolyQ::from(&self.g) * &f_inv,
        })
    }
}

/// The master public key `h = g·f⁻¹ mod q`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MasterPublicKey {
    h: PolyQ,
}

impl MasterPublicKey {
    /// The public polynomial `h`.
    pub fn h(&self) -> &PolyQ {
        &self.h
    }
}

/// `‖B̃_{f,g}‖`, the larger Gram–Schmidt norm of the trapdoor basis:
/// `max(‖(g, −f)‖, ‖(q·f*/(f·f* + g·g*), q·g*/(f·f* + g·g*))‖)`.
///
/// The second term is computed in the FFT domain, where by Parseval it is
/// `q·√(Σ_j 1/(|f(ζ_j)|² + |g(ζ_j)|²) / N)`.
pub fn gram_schmidt_norm(f: &PolyZ, g: &PolyZ) -> VsssResult<f64> {
    let first = (f.norm_sq() + g.norm_sq()) as f64;
    let to_fft = |p: &PolyZ| {
        fft(&p.coeffs().iter().map(|&c| c as f64).collect::<Vec<_>>())
            .ok_or(lattice_error("lattice: FFT length must be a power of two"))
    };
    let (ff, gf) = (to_fft(f)?, to_fft(g)?);
    let inv_sum: f64 = ff
        .iter()
        .zip(&gf)
        .map(|(a, b)| 1.0 / (a.norm_sq() + b.norm_sq()))
        .sum();
    let q = f64::from(Q);
    let second = q * q * inv_sum / f.coeffs().len() as f64;
    let norm = first.max(second).sqrt();
    if norm.is_finite() {
        Ok(norm)
    } else {
        Err(lattice_error("lattice: degenerate trapdoor"))
    }
}

/// Generate an NTRU trapdoor `(msk, mpk)` per the paper's `KeyGen(N, q)`.
///
/// Samples `f, g ← D_{N,σ_f}` and rejects until `f(1)` is odd (so `f` is
/// invertible mod `q`), `‖B̃_{f,g}‖ ≤ 1.17·√q`, and `gcd(R_f, R_g) = 1`;
/// then solves `f·G − g·F = q` and sets `h = g·f⁻¹ mod q`.
pub fn keygen(mut rng: impl CryptoRng) -> VsssResult<(MasterSecretKey, MasterPublicKey)> {
    for _ in 0..MAX_KEYGEN_ATTEMPTS {
        let f = sample_poly(SIGMA_F, &mut rng)?;
        let g = sample_poly(SIGMA_F, &mut rng)?;
        // gcd(R_f, 2^29) = 1 ⇔ R_f odd ⇔ f(1) odd. Checked first because it
        // is the cheapest test; the order of rejection tests does not change
        // the output distribution.
        if f.eval_at_one() % 2 == 0 || gram_schmidt_norm(&f, &g)? > GS_NORM_BOUND {
            continue;
        }
        let Some((big_f, big_g)) = ntru::solve(f.coeffs(), g.coeffs(), Q) else {
            continue;
        };
        let msk = MasterSecretKey {
            big_f: PolyZ::from_coeffs(big_f)?,
            big_g: PolyZ::from_coeffs(big_g)?,
            f,
            g,
        };
        let residual = msk
            .f
            .checked_mul(&msk.big_g)?
            .checked_sub(&msk.g.checked_mul(&msk.big_f)?)?;
        if residual != PolyZ::constant(i64::from(Q))? {
            return Err(lattice_error("lattice: NTRU solution failed verification"));
        }
        let mpk = msk.public_key()?;
        return Ok((msk, mpk));
    }
    Err(lattice_error(
        "lattice: key generation exhausted its attempts",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn keygen_produces_a_valid_trapdoor() {
        let (msk, mpk) = keygen(StdRng::from_seed([41u8; 32])).expect("keygen");

        // f·G − g·F == q exactly over Z[x]/(x^N + 1).
        let lhs = msk
            .f()
            .checked_mul(msk.big_g())
            .and_then(|fg| fg.checked_sub(&msk.g().checked_mul(msk.big_f())?))
            .expect("small coefficients");
        assert_eq!(lhs, PolyZ::constant(i64::from(Q)).expect("in range"));

        // h·f == g mod q.
        assert_eq!(mpk.h() * &PolyQ::from(msk.f()), PolyQ::from(msk.g()));

        // Gram–Schmidt norm bound and f(1) odd.
        let norm = gram_schmidt_norm(msk.f(), msk.g()).expect("finite");
        assert!(norm <= GS_NORM_BOUND, "norm {norm}");
        assert_eq!(msk.f().eval_at_one().rem_euclid(2), 1);

        // F, G are size-reduced: comparable to the Gram–Schmidt bound, far
        // below q.
        let reduced = |p: &PolyZ| p.coeffs().iter().all(|c| c.unsigned_abs() < 1 << 20);
        assert!(reduced(msk.big_f()) && reduced(msk.big_g()));

        assert_eq!(msk.public_key().expect("invertible"), mpk);
        assert_eq!(std::format!("{msk:?}"), "MasterSecretKey { .. }");
    }

    #[test]
    fn gram_schmidt_norm_matches_the_direct_formula_on_a_tiny_example() {
        // With f = 1, g = 0 the second term is q·‖1/1‖ = q.
        let one = PolyZ::constant(1).expect("in range");
        let zero = PolyZ::constant(0).expect("in range");
        let norm = gram_schmidt_norm(&one, &zero).expect("finite");
        assert!((norm - f64::from(Q)).abs() < 1e-3);
        assert!(gram_schmidt_norm(&zero, &zero).is_err());
    }
}
