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
//!
//! # Timing
//!
//! Every leaf holds a precomputed [`SamplerZ`], the isochronous sampler of
//! [`super::gaussian`], so the per-sample work is that sampler plus `f64`
//! adds and multiplies in the splits, merges, and Klein updates. Divisions
//! and square roots happen once per trapdoor, in [`LdlTree::new`] and the
//! reciprocal `1/q` of [`TrapdoorSampler::sample_key`]; [`LdlTree::new`]
//! also rejects any leaf width outside `[σ_min, σ_max]`, so the sampler's
//! precondition holds whenever a tree exists. See
//! [`super::fft`](super::fft#timing) for the floating-point assumptions.
use super::Q;
use super::fft::{
    Complex, fft_of, integer_poly, merge_fft, pair_norm_sq, roots_for, split_fft, split_roots,
};
use super::gaussian::SamplerZ;
use super::keygen::MasterSecretKey;
use super::ring::{PolyQ, PolyZ};
use crate::secret::Secret;
use crate::{Error, VsssResult};
use rand_core::CryptoRng;
use std::boxed::Box;
use std::vec::Vec;

/// The ffLDL tree of a `2×2` Gram matrix over `R[x]/(x^n + 1)`, stored in
/// the FFT domain.
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
enum LdlTree {
    /// The `n = 1` base case.
    Leaf {
        /// `L10 = G10 / G00`.
        l10: Complex,
        /// Samplers of width `σ / ‖b̃‖` for the first and second coordinate.
        widths: [SamplerZ; 2],
    },
    /// An inner node.
    Node {
        /// `L10 = G10 / G00`.
        l10: Vec<Complex>,
        /// The trees of `D00` and `D11`. Each wipes itself on drop.
        #[cfg_attr(feature = "zeroize", zeroize(skip))]
        children: Box<[LdlTree; 2]>,
    },
}

impl LdlTree {
    /// Factor the self-adjoint Gram matrix `[[g00, g01], [g01*, g11]]`
    /// (`g00` and `g11` are real in the FFT domain) for width `sigma`.
    /// `roots` is a [`split_roots`] table for the splits below. Fails if the
    /// matrix is not positive definite or a leaf width `σ/‖b̃_i‖` leaves
    /// `[σ_min, σ_max]`.
    fn new(
        g00: &[f64],
        g01: &[Complex],
        g11: &[f64],
        sigma: f64,
        roots: &[Complex],
    ) -> VsssResult<Self> {
        // D11 = G11 − G10·G00⁻¹·G01 = G11 − |G01|² / G00.
        let d11 = Secret::new(
            g11.iter()
                .zip(g01.iter().zip(g00))
                .map(|(&a, (c, &d))| a - c.norm_sq() / d)
                .collect::<Vec<f64>>(),
        );
        if g00
            .iter()
            .chain(d11.iter())
            .any(|&d| !(d.is_finite() && d > 0.0))
        {
            return Err(Error::Lattice("degenerate trapdoor"));
        }
        let l10 = |c: &Complex, d: f64| c.conj().scale(1.0 / d);
        Ok(match (g00, g01, d11.as_slice()) {
            ([d00], [g01], [d11]) => Self::Leaf {
                l10: l10(g01, *d00),
                widths: [
                    SamplerZ::new(sigma / d00.sqrt())?,
                    SamplerZ::new(sigma / d11.sqrt())?,
                ],
            },
            _ => Self::Node {
                l10: g01.iter().zip(g00).map(|(c, &d)| l10(c, d)).collect(),
                children: Box::new([
                    Self::split(g00, sigma, roots)?,
                    Self::split(&d11, sigma, roots)?,
                ]),
            },
        })
    }

    /// The tree of a self-adjoint `d` viewed over the half-size ring, where
    /// it becomes the Gram matrix `[[d0, d1], [d1*, d0]]` with
    /// `d = d0(x²) + x·d1(x²)`.
    fn split(d: &[f64], sigma: f64, roots: &[Complex]) -> VsssResult<Self> {
        let full = Secret::new(
            d.iter()
                .map(|&re| Complex { re, im: 0.0 })
                .collect::<Vec<_>>(),
        );
        let mut halves = Secret::new(std::vec![Complex::default(); d.len()]);
        let (d0, d1) = halves.split_at_mut(d.len() / 2);
        split_fft(&full, roots_for(roots, d.len()), d0, d1);
        let d0_re = Secret::new(d0.iter().map(|c| c.re).collect::<Vec<f64>>());
        Self::new(&d0_re, d1, &d0_re, sigma, roots)
    }

    /// Sample `(z0, z1)`, integer polynomials in the FFT domain, from the
    /// discrete Gaussian of this tree's lattice around `(t0, t1)`. `t0` is
    /// used as working space, and `work` needs `4·n` scratch slots.
    fn sample<R: CryptoRng + ?Sized>(
        &self,
        (t0, t1): (&mut [Complex], &[Complex]),
        (z0, z1): (&mut [Complex], &mut [Complex]),
        work: &mut Workspace<'_>,
        rng: &mut R,
    ) -> VsssResult<()> {
        match self {
            // The `n = 1` base case: two one-dimensional Gaussians, second
            // first.
            Self::Leaf { l10, widths } => {
                for ((z0, z1), (c0, c1)) in z0.iter_mut().zip(z1.iter_mut()).zip(t0.iter().zip(t1))
                {
                    let s1 = widths[1].sample(c1.re, rng)? as f64;
                    let s0 = widths[0].sample(c0.re + (c1.re - s1) * l10.re, rng)? as f64;
                    *z0 = Complex { re: s0, im: 0.0 };
                    *z1 = Complex { re: s1, im: 0.0 };
                }
                Ok(())
            }
            Self::Node { l10, children } => {
                let [child0, child1] = &**children;
                child1.sample_split(t1, z1, work, rng)?;
                // Klein's update: move the remaining center by (t1 − z1)·L10.
                for ((a, (&b, &z)), &l) in t0.iter_mut().zip(t1.iter().zip(z1.iter())).zip(l10) {
                    *a = *a + (b - z) * l;
                }
                child0.sample_split(t0, z0, work, rng)
            }
        }
    }

    /// Sample around `t` into `z` by splitting it over the half-size ring.
    fn sample_split<R: CryptoRng + ?Sized>(
        &self,
        t: &[Complex],
        z: &mut [Complex],
        work: &mut Workspace<'_>,
        rng: &mut R,
    ) -> VsssResult<()> {
        let n = t.len();
        let roots = roots_for(work.roots, n);
        let (halves, rest) = work
            .scratch
            .split_at_mut_checked(2 * n)
            .ok_or(Error::Lattice("sampler workspace is too small"))?;
        let (t_half, z_half) = halves.split_at_mut(n);
        let (a, b) = t_half.split_at_mut(n / 2);
        split_fft(t, roots, a, b);
        let (za, zb) = z_half.split_at_mut(n / 2);
        let mut inner = Workspace {
            roots: work.roots,
            scratch: rest,
        };
        self.sample((a, b), (za, zb), &mut inner, rng)?;
        merge_fft(za, zb, roots, z);
        Ok(())
    }

    /// Every leaf width `σ / ‖b̃_i‖`, in row order.
    #[cfg(test)]
    fn leaf_sigmas(&self) -> Vec<f64> {
        match self {
            Self::Leaf { widths, .. } => widths.iter().map(SamplerZ::sigma).collect(),
            Self::Node { children, .. } => children.iter().flat_map(Self::leaf_sigmas).collect(),
        }
    }
}

/// What one sampling pass works in: the split roots and the scratch space
/// still free at this depth.
struct Workspace<'a> {
    roots: &'a [Complex],
    scratch: &'a mut [Complex],
}

/// Klein/GPV sampling for one master secret key, with the ffLDL tree, the
/// split roots, and the FFT images of the trapdoor precomputed. Everything
/// derived from the key is wiped on drop.
pub(crate) struct TrapdoorSampler<'a> {
    msk: &'a MasterSecretKey,
    f: Secret<Vec<Complex>>,
    big_f: Secret<Vec<Complex>>,
    roots: Vec<Complex>,
    tree: LdlTree,
}

impl<'a> TrapdoorSampler<'a> {
    /// Precompute sampling at width `sigma` for `msk`. Fails if the
    /// trapdoor is degenerate or a leaf width leaves `[σ_min, σ_max]`.
    pub(crate) fn new(msk: &'a MasterSecretKey, sigma: f64) -> VsssResult<Self> {
        let g = Secret::new(fft_of(msk.g())?);
        let f = Secret::new(fft_of(msk.f())?);
        let big_g = Secret::new(fft_of(msk.big_g())?);
        let big_f = Secret::new(fft_of(msk.big_f())?);
        let roots = split_roots(f.len());
        // Gram matrix of the rows (g, −f) and (G, −F).
        let g00 = Secret::new(pair_norm_sq(&g, &f));
        let g01 = Secret::new(
            g.iter()
                .zip(big_g.iter())
                .zip(f.iter().zip(big_f.iter()))
                .map(|((&a, &bg), (&b, &bf))| a * bg.conj() + b * bf.conj())
                .collect::<Vec<_>>(),
        );
        let g11 = Secret::new(pair_norm_sq(&big_g, &big_f));
        let tree = LdlTree::new(&g00, &g01, &g11, sigma, &roots)?;
        Ok(Self {
            msk,
            f,
            big_f,
            roots,
            tree,
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
        let n = t_fft.len();
        // (τ0, τ1) = (t, 0)·B⁻¹ = (−t·F/q, t·f/q).
        let inv_q = 1.0 / f64::from(Q);
        let mut tau0 = Secret::new(
            t_fft
                .iter()
                .zip(self.big_f.iter())
                .map(|(&a, &b)| (a * b).scale(-inv_q))
                .collect::<Vec<_>>(),
        );
        let tau1 = Secret::new(
            t_fft
                .iter()
                .zip(self.f.iter())
                .map(|(&a, &b)| (a * b).scale(inv_q))
                .collect::<Vec<_>>(),
        );
        // One buffer for the sample and every level's splits.
        let mut buffer = Secret::new(std::vec![Complex::default(); 6 * n]);
        let (z, scratch) = buffer.split_at_mut(2 * n);
        let (z0, z1) = z.split_at_mut(n);
        let mut work = Workspace {
            roots: &self.roots,
            scratch,
        };
        self.tree
            .sample((&mut tau0, &tau1), (z0, z1), &mut work, rng)?;
        let z0 = Secret::new(integer_poly(z0)?);
        let z1 = Secret::new(integer_poly(z1)?);
        // v = z0·(g, −f) + z1·(G, −F), so −v2 = z0·f + z1·F.
        let z0_f = Secret::new(z0.checked_mul(self.msk.f())?);
        let z1_big_f = Secret::new(z1.checked_mul(self.msk.big_f())?);
        z0_f.checked_add(&z1_big_f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lattice::gaussian::{SIGMA_MAX, SIGMA_MIN};
    use crate::lattice::test_support::keys;
    use crate::lattice::{GS_NORM_BOUND, N, SIGMA_EXTRACT, hash_to_ring};
    use rand::{SeedableRng, rngs::StdRng};
    use sha2::Sha256;

    #[test]
    fn tree_leaves_are_the_gram_schmidt_norms_of_the_basis() {
        for (msk, _) in keys() {
            let sampler = TrapdoorSampler::new(msk, SIGMA_EXTRACT).expect("sampler");
            let sigmas = sampler.tree.leaf_sigmas();
            assert_eq!(sigmas.len(), 2 * N);
            // The leaves are σ/‖b̃_i‖, and Π‖b̃_i‖ = det B = q^N.
            let log_det: f64 = sigmas.iter().map(|s| (SIGMA_EXTRACT / s).ln()).sum();
            let expected = N as f64 * f64::from(Q).ln();
            assert!(
                (log_det - expected).abs() < 1e-6 * expected,
                "log det {log_det}, expected {expected}"
            );
            let max_norm = sigmas.iter().map(|s| SIGMA_EXTRACT / s).fold(0.0, f64::max);
            assert!(max_norm <= GS_NORM_BOUND * (1.0 + 1e-9), "max {max_norm}");
            // Every leaf width sits in the sampler's range, and by
            // ‖b̃_i‖·‖b̃_{2N−1−i}‖ = q the largest is at most 2·1.17².
            let (lo, hi) = sigmas
                .iter()
                .fold((f64::MAX, 0.0f64), |(lo, hi), &s| (lo.min(s), hi.max(s)));
            assert!(
                lo >= SIGMA_MIN && hi <= SIGMA_MAX,
                "leaf widths in [{lo}, {hi}]"
            );
            assert!(
                hi <= 2.0 * 1.17 * 1.17 * (1.0 + 1e-9),
                "max leaf width {hi}"
            );
        }
    }

    #[test]
    fn leaf_widths_outside_the_sampler_range_are_rejected() {
        let (msk, _) = &keys()[0];
        // Scaling σ scales every leaf width with it.
        assert!(TrapdoorSampler::new(msk, 1.0).is_err());
        assert!(TrapdoorSampler::new(msk, SIGMA_EXTRACT * 1.5).is_err());
        assert!(TrapdoorSampler::new(msk, SIGMA_EXTRACT).is_ok());
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
    fn degenerate_gram_matrices_are_rejected_and_leaves_sample() {
        let zero = Complex::default();
        assert!(LdlTree::new(&[0.0], &[zero], &[1.0], 1.0, &[]).is_err());
        // G11 − |G01|²/G00 = 1 − 4 < 0.
        let big = Complex { re: 2.0, im: 0.0 };
        assert!(LdlTree::new(&[1.0], &[big], &[1.0], 1.0, &[]).is_err());
        // Leaf widths σ/√D00 = 2.5 and σ/√D11 = 2.
        let leaf = LdlTree::new(&[1.0], &[zero], &[1.5625], 2.5, &[]).expect("valid");
        let LdlTree::Leaf { widths, .. } = &leaf else {
            panic!("n = 1 is a leaf");
        };
        assert_eq!(widths.map(|w| w.sigma()), [2.5, 2.0]);
        // A leaf width outside [σ_min, σ_max] is an error.
        assert!(LdlTree::new(&[1.0], &[zero], &[1.0], 3.0, &[]).is_err());
        let mut rng = StdRng::from_seed([62u8; 32]);
        let (mut z0, mut z1) = ([zero], [zero]);
        let mut work = Workspace {
            roots: &[],
            scratch: &mut [],
        };
        leaf.sample(
            (&mut [Complex { re: 1e6, im: 0.0 }], &[zero]),
            (&mut z0, &mut z1),
            &mut work,
            &mut rng,
        )
        .expect("valid");
        assert!((z0[0].re - 1e6).abs() < 100.0 && z1[0].re.abs() < 100.0);
    }

    /// Release-mode timings of key generation, extraction, and decryption,
    /// plus the leaf-width range over several keys. Ignored because it is
    /// a report, not a check; run with `--release --ignored --nocapture`.
    #[test]
    #[ignore = "timing report; run in release with --ignored"]
    fn report_timings_and_leaf_width_range() {
        use crate::lattice::{decrypt, encrypt, extract, keygen};
        use std::time::Instant;
        let n_keys = 24;
        let (mut lo, mut hi) = (f64::MAX, 0.0f64);
        let mut keygen_total = 0.0;
        let mut first = None;
        for i in 0..n_keys {
            let start = Instant::now();
            let (msk, mpk) = keygen(StdRng::from_seed([i as u8; 32])).expect("keygen");
            keygen_total += start.elapsed().as_secs_f64();
            let sampler = TrapdoorSampler::new(&msk, SIGMA_EXTRACT).expect("sampler");
            for s in sampler.tree.leaf_sigmas() {
                lo = lo.min(s);
                hi = hi.max(s);
            }
            first.get_or_insert((msk, mpk));
        }
        let (msk, mpk) = first.expect("one key");
        let mut rng = StdRng::from_seed([9u8; 32]);
        let reps = 20u8;
        let start = Instant::now();
        let keys: Vec<_> = (0..reps)
            .map(|i| extract::<Sha256>(&msk, &mpk, &[i], &mut rng).expect("extract"))
            .collect();
        let extract_ms = start.elapsed().as_secs_f64() * 1e3 / f64::from(reps);
        let message = [7u8; 64];
        let ct = encrypt::<Sha256>(&mpk, &[0], &message, &mut rng).expect("encrypt");
        let start = Instant::now();
        for _ in 0..reps {
            assert_eq!(decrypt::<Sha256>(&keys[0], &ct), message);
        }
        let decrypt_ms = start.elapsed().as_secs_f64() * 1e3 / f64::from(reps);
        std::println!(
            "leaf widths over {n_keys} keys: [{lo}, {hi}]; keygen {:.3} s, extract {extract_ms:.3} ms, decrypt {decrypt_ms:.3} ms",
            keygen_total / f64::from(n_keys)
        );
    }

    #[test]
    fn a_short_workspace_is_an_error() {
        let (msk, _) = &keys()[0];
        let sampler = TrapdoorSampler::new(msk, SIGMA_EXTRACT).expect("sampler");
        let t = std::vec![Complex::default(); N];
        let mut z = std::vec![Complex::default(); N];
        let mut work = Workspace {
            roots: &sampler.roots,
            scratch: &mut [],
        };
        let mut rng = StdRng::from_seed([63u8; 32]);
        let LdlTree::Node { children, .. } = &sampler.tree else {
            panic!("the root is a node");
        };
        assert_eq!(
            children[1].sample_split(&t, &mut z, &mut work, &mut rng),
            Err(Error::Lattice("sampler workspace is too small"))
        );
    }
}
