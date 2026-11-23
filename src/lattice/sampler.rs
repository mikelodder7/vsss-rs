/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Klein/GPV Gaussian sampling over the NTRU trapdoor basis.
//!
//! The basis is `B = [[A(g), −A(f)], [A(G), −A(F)]]`. Running Klein's sampler
//! directly on its `2N` rows costs `O(N²)` per sample after an `O(N²)`
//! Gram–Schmidt pass. This module uses the equivalent fast-Fourier form of
//! Ducas–Prest (Falcon's ffLDL and ffSampling): the Gram matrix
//! `B·B*` is factored as `L·D·L*` recursively over `R[x]/(x^n + 1)` for
//! `n = N, N/2, …, 1`, and the `2N` leaves of the tree are the squared
//! Gram–Schmidt norms `‖b̃_i‖²` in the tree's row order. Sampling walks the
//! tree last row first, drawing each integer coordinate with width
//! `σ / ‖b̃_i‖` around its updated center, exactly as Klein's sampler does,
//! in `O(N log N)` time.
use super::fft::{Complex, fft, ifft, merge_fft, split_fft};
use super::gaussian::sample_z;
use super::keygen::MasterSecretKey;
use super::ring::{PolyQ, PolyZ};
use super::{Q, lattice_error, wipe};
use crate::VsssResult;
use rand_core::CryptoRng;
use std::vec::Vec;

/// One node of the ffLDL tree of a `2×2` Gram matrix over `R[x]/(x^n + 1)`,
/// stored in the FFT domain.
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
struct LdlTree {
    /// `L10 = G10 / G00`.
    l10: Vec<Complex>,
    /// At a leaf (`n = 1`), `σ / ‖b̃‖` for the first and second coordinate.
    sigma: [f64; 2],
    /// Below an inner node, the trees of `D00` and `D11`.
    children: Vec<LdlTree>,
}

impl LdlTree {
    /// Factor the self-adjoint Gram matrix `[[g00, g01], [g01*, g11]]`
    /// (`g00` and `g11` are real in the FFT domain) for width `sigma`.
    fn new(g00: &[f64], g01: &[Complex], g11: &[f64], sigma: f64) -> VsssResult<Self> {
        let l10: Vec<Complex> = g01
            .iter()
            .zip(g00)
            .map(|(c, &d)| c.conj().scale(1.0 / d))
            .collect();
        // D11 = G11 − G10·G00⁻¹·G01 = G11 − |G01|² / G00.
        let mut d11: Vec<f64> = g11
            .iter()
            .zip(g01.iter().zip(g00))
            .map(|(&a, (c, &d))| a - c.norm_sq() / d)
            .collect();
        if g00.iter().chain(&d11).any(|&d| !(d.is_finite() && d > 0.0)) {
            return Err(lattice_error("lattice: degenerate trapdoor"));
        }
        let tree = match (g00, d11.as_slice()) {
            ([d00], [d11]) => Self {
                l10,
                sigma: [sigma / d00.sqrt(), sigma / d11.sqrt()],
                children: Vec::new(),
            },
            _ => Self {
                l10,
                sigma: [0.0; 2],
                children: std::vec![Self::split(g00, sigma)?, Self::split(&d11, sigma)?],
            },
        };
        wipe(&mut d11);
        Ok(tree)
    }

    /// The tree of a self-adjoint `d` viewed over the half-size ring, where
    /// it becomes the Gram matrix `[[d0, d1], [d1*, d0]]` with
    /// `d = d0(x²) + x·d1(x²)`.
    fn split(d: &[f64], sigma: f64) -> VsssResult<Self> {
        let mut full: Vec<Complex> = d.iter().map(|&re| Complex { re, im: 0.0 }).collect();
        let (mut d0, mut d1) = split_fft(&full);
        let mut d0_re: Vec<f64> = d0.iter().map(|c| c.re).collect();
        let tree = Self::new(&d0_re, &d1, &d0_re, sigma);
        wipe(&mut full);
        wipe(&mut d0);
        wipe(&mut d1);
        wipe(&mut d0_re);
        tree
    }

    /// Sample `(z0, z1)`, integer polynomials in the FFT domain, from the
    /// discrete Gaussian of this tree's lattice around `(t0, t1)`.
    fn sample<R: CryptoRng + ?Sized>(
        &self,
        t0: &[Complex],
        t1: &[Complex],
        rng: &mut R,
    ) -> VsssResult<(Vec<Complex>, Vec<Complex>)> {
        let [child0, child1] = self.children.as_slice() else {
            return self.sample_leaf(t0, t1, rng);
        };
        let z1 = child1.sample_split(t1, rng)?;
        // Klein's update: move the remaining center by (t1 − z1)·L10.
        let mut t0_new: Vec<Complex> = t0
            .iter()
            .zip(t1.iter().zip(&z1))
            .zip(&self.l10)
            .map(|((&a, (&b, &z)), &l)| a.plus(b.minus(z).times(l)))
            .collect();
        let z0 = child0.sample_split(&t0_new, rng)?;
        wipe(&mut t0_new);
        Ok((z0, z1))
    }

    /// Sample around `t` by splitting it over the half-size ring.
    fn sample_split<R: CryptoRng + ?Sized>(
        &self,
        t: &[Complex],
        rng: &mut R,
    ) -> VsssResult<Vec<Complex>> {
        let (a, b) = split_fft(t);
        let (za, zb) = self.sample(&a, &b, rng)?;
        Ok(merge_fft(&za, &zb))
    }

    /// The `n = 1` base case: two one-dimensional Gaussians, second first.
    fn sample_leaf<R: CryptoRng + ?Sized>(
        &self,
        t0: &[Complex],
        t1: &[Complex],
        rng: &mut R,
    ) -> VsssResult<(Vec<Complex>, Vec<Complex>)> {
        let ([c0], [c1], [l]) = (t0, t1, self.l10.as_slice()) else {
            return Err(lattice_error("lattice: sampler input has the wrong length"));
        };
        let z1 = sample_z(self.sigma[1], c1.re, rng)? as f64;
        let z0 = sample_z(self.sigma[0], c0.re + (c1.re - z1) * l.re, rng)? as f64;
        let real = |re| std::vec![Complex { re, im: 0.0 }];
        Ok((real(z0), real(z1)))
    }

    /// Every leaf width `σ / ‖b̃_i‖`, in row order.
    #[cfg(test)]
    fn leaf_sigmas(&self) -> Vec<f64> {
        if self.children.is_empty() {
            self.sigma.to_vec()
        } else {
            self.children.iter().flat_map(Self::leaf_sigmas).collect()
        }
    }
}

/// Klein/GPV sampling for one master secret key, with the ffLDL tree and
/// the FFT images of the trapdoor precomputed. Everything derived from the
/// key is wiped on drop.
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub(crate) struct TrapdoorSampler<'a> {
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    msk: &'a MasterSecretKey,
    f: Vec<Complex>,
    big_f: Vec<Complex>,
    tree: LdlTree,
}

impl<'a> TrapdoorSampler<'a> {
    /// Precompute sampling at width `sigma` for `msk`.
    pub(crate) fn new(msk: &'a MasterSecretKey, sigma: f64) -> VsssResult<Self> {
        let mut g = fft_of(msk.g())?;
        let f = fft_of(msk.f())?;
        let mut big_g = fft_of(msk.big_g())?;
        let big_f = fft_of(msk.big_f())?;
        // Gram matrix of the rows (g, −f) and (G, −F).
        let mut g00: Vec<f64> = g
            .iter()
            .zip(&f)
            .map(|(a, b)| a.norm_sq() + b.norm_sq())
            .collect();
        let mut g01: Vec<Complex> = g
            .iter()
            .zip(&big_g)
            .zip(f.iter().zip(&big_f))
            .map(|((&a, &bg), (&b, &bf))| a.times(bg.conj()).plus(b.times(bf.conj())))
            .collect();
        let mut g11: Vec<f64> = big_g
            .iter()
            .zip(&big_f)
            .map(|(a, b)| a.norm_sq() + b.norm_sq())
            .collect();
        let tree = LdlTree::new(&g00, &g01, &g11, sigma);
        wipe(&mut g);
        wipe(&mut big_g);
        wipe(&mut g00);
        wipe(&mut g01);
        wipe(&mut g11);
        Ok(Self {
            msk,
            f,
            big_f,
            tree: tree?,
        })
    }

    /// Sample `(s1, s2) = (t, 0) − v` where `v = (v1, v2) ∈ L(B)` is drawn
    /// from the discrete Gaussian of width `σ` centered at `(t, 0)`, and
    /// return the identity key `s2 = −v2`. Then `s1 = t − s2·h (mod q)`.
    pub(crate) fn sample_key<R: CryptoRng + ?Sized>(
        &self,
        t: &PolyQ,
        rng: &mut R,
    ) -> VsssResult<PolyZ> {
        let t_fft = fft_of(&PolyZ::from_coeffs(t.centered())?)?;
        // (τ0, τ1) = (t, 0)·B⁻¹ = (−t·F/q, t·f/q).
        let inv_q = 1.0 / f64::from(Q);
        let tau0: Vec<Complex> = t_fft
            .iter()
            .zip(&self.big_f)
            .map(|(a, b)| a.times(*b).scale(-inv_q))
            .collect();
        let tau1: Vec<Complex> = t_fft
            .iter()
            .zip(&self.f)
            .map(|(a, b)| a.times(*b).scale(inv_q))
            .collect();
        let (mut z0_fft, mut z1_fft) = self.tree.sample(&tau0, &tau1, rng)?;
        let mut z0 = integer_poly(&z0_fft)?;
        let mut z1 = integer_poly(&z1_fft)?;
        wipe(&mut z0_fft);
        wipe(&mut z1_fft);
        // v = z0·(g, −f) + z1·(G, −F), so −v2 = z0·f + z1·F.
        let s2 = z0
            .checked_mul(self.msk.f())
            .and_then(|x| x.checked_add(&z1.checked_mul(self.msk.big_f())?));
        wipe(&mut z0);
        wipe(&mut z1);
        s2
    }
}

/// The FFT image of an integer polynomial.
fn fft_of(p: &PolyZ) -> VsssResult<Vec<Complex>> {
    let coeffs: Vec<f64> = p.coeffs().iter().map(|&c| c as f64).collect();
    fft(&coeffs).ok_or(lattice_error("lattice: FFT length must be a power of two"))
}

/// Round an FFT image of an integer polynomial back to its coefficients.
fn integer_poly(p: &[Complex]) -> VsssResult<PolyZ> {
    let coeffs = ifft(p)
        .ok_or(lattice_error("lattice: FFT length must be a power of two"))?
        .into_iter()
        .map(|c| {
            let r = c.round();
            (r.is_finite() && r.abs() < (1u64 << 52) as f64)
                .then_some(r as i64)
                .ok_or(lattice_error("lattice: sampled coefficient out of range"))
        })
        .collect::<VsssResult<Vec<_>>>()?;
    PolyZ::from_coeffs(coeffs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lattice::test_support::keys;
    use crate::lattice::{GS_NORM_BOUND, N, SIGMA_EXTRACT, hash_to_ring};
    use rand::{SeedableRng, rngs::StdRng};
    use sha2::Sha256;

    #[test]
    fn tree_leaves_are_the_gram_schmidt_norms_of_the_basis() {
        let (msk, _) = &keys()[0];
        let sampler = TrapdoorSampler::new(msk, 1.0).expect("sampler");
        let sigmas = sampler.tree.leaf_sigmas();
        assert_eq!(sigmas.len(), 2 * N);
        // With σ = 1 the leaves are 1/‖b̃_i‖, and Π‖b̃_i‖ = det B = q^N.
        let log_det: f64 = sigmas.iter().map(|s| -s.ln()).sum();
        let expected = N as f64 * f64::from(Q).ln();
        assert!(
            (log_det - expected).abs() < 1e-6 * expected,
            "log det {log_det}, expected {expected}"
        );
        let max_norm = sigmas.iter().map(|s| 1.0 / s).fold(0.0, f64::max);
        assert!(max_norm <= GS_NORM_BOUND * (1.0 + 1e-9), "max {max_norm}");
    }

    #[test]
    fn sampled_keys_are_short_and_hit_the_target() {
        let (msk, mpk) = &keys()[1];
        let sampler = TrapdoorSampler::new(msk, SIGMA_EXTRACT).expect("sampler");
        let mut rng = StdRng::from_seed([61u8; 32]);
        let expected = SIGMA_EXTRACT * (2.0 * N as f64).sqrt();
        for id in [b"alpha".as_slice(), b"beta"] {
            let t = hash_to_ring::<Sha256>(id);
            let s2 = sampler.sample_key(&t, &mut rng).expect("sample");
            let s2_q = PolyQ::from(&s2);
            // s2 is small, so it is its own centered representative.
            assert_eq!(s2_q.centered(), s2.coeffs());
            // s1 = t − s2·h, so s1 + s2·h ≡ t (mod q), and s1 is short.
            let s1 = &t - &(&s2_q * mpk.h());
            assert_eq!(&s1 + &(&s2_q * mpk.h()), t);
            // ‖(s1, s2)‖ is close to σ·√(2N), as a Gaussian of width σ
            // over a 2N-dimensional lattice should be; a wrong sampler
            // gives a norm near q·√N instead.
            let norm = ((s1.centered_norm_sq() + s2.norm_sq()) as f64).sqrt();
            assert!(
                (norm / expected - 1.0).abs() < 0.1,
                "norm {norm}, expected {expected}"
            );
        }
    }

    #[test]
    fn degenerate_gram_matrices_and_bad_inputs_are_rejected() {
        let zero = Complex::default();
        assert!(LdlTree::new(&[0.0], &[zero], &[1.0], 1.0).is_err());
        // G11 − |G01|²/G00 = 1 − 4 < 0.
        let big = Complex { re: 2.0, im: 0.0 };
        assert!(LdlTree::new(&[1.0], &[big], &[1.0], 1.0).is_err());
        let leaf = LdlTree::new(&[4.0], &[zero], &[9.0], 6.0).expect("valid");
        assert_eq!(leaf.sigma, [3.0, 2.0]);
        let mut rng = StdRng::from_seed([62u8; 32]);
        assert!(leaf.sample(&[zero, zero], &[zero], &mut rng).is_err());
        let (z0, z1) = leaf
            .sample(&[Complex { re: 1e6, im: 0.0 }], &[zero], &mut rng)
            .expect("valid");
        assert!((z0[0].re - 1e6).abs() < 100.0 && z1[0].re.abs() < 100.0);
        assert!(
            integer_poly(&[Complex {
                re: f64::NAN,
                im: 0.0
            }])
            .is_err()
        );
        assert!(fft_of(&PolyZ::constant(1).expect("in range")).is_ok());
    }
}
