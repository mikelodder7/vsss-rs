/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Falcon-style recursive NTRUSolve on fixed-width integers.
//!
//! Given `f, g ∈ Z[x]/(x^n + 1)`, find `F, G` with `f·G − g·F = q`. The
//! field norm `N(f)(x²) = f(x)·f(−x)` halves the degree until `n = 1`, where
//! `u·N(f) + v·N(g) = 1` is solved with a modular inverse. Each level lifts
//! the solution with `F = F'(x²)·g(−x)`, `G = G'(x²)·f(−x)` and shrinks it
//! with Babai's round-off against `(f, g)`, computed in floating point on
//! the top 53 bits as in Pornin–Prest.
//!
//! The degree-1 norms are the resultants `R_f = Res(f, x^N + 1)` and
//! `R_g = Res(g, x^N + 1)`, so the base case fails exactly when
//! `gcd(R_f, R_g) ≠ 1`. Key generation guarantees `R_f` odd (`f(1)` odd).
//!
//! # Timing
//!
//! Every integer is a two's-complement [`Int`] whose width is fixed per
//! recursion level (a [`Level`]), so no allocation, loop count, or branch
//! depends on the values of `f` and `g`:
//!
//! - ring arithmetic wraps modulo `2^width`, which is exact whenever the
//!   true value fits: reduction modulo `2^width` is a ring homomorphism, so
//!   Karatsuba's intermediates need no headroom of their own;
//! - the base case is `crypto-bigint`'s Bernstein–Yang inversion
//!   (`invert_odd_mod`: a fixed number of division steps, no data-dependent
//!   branches), completed to Bézout coefficients with a Hensel inverse modulo
//!   `2^width` (see [`FixedInt::bezout`]);
//! - Babai's round-off runs a fixed, public number of iterations per level
//!   ([`Level::REDUCE_ITERATIONS`]). The bit lengths and shifts it needs are
//!   computed with constant-time selects, and every shift is constant-time
//!   in the shift amount.
//!
//! What remains observable is whether the solve succeeded (a public
//! rejection in key generation) and the floating-point FFT, which only sees
//! normal numbers; the sampler and FFT modules cover their own timing.
//!
//! # Widths
//!
//! `N = 1024`, `σ_f = 1.17·512`. A coefficient of the field norm at degree
//! `n` is a product of `1024/n` values `|f(ζ_j)|`, so its length in bits is a
//! sum of `1024/n` terms with mean `½·log₂(N·σ_f²) − γ/(2·ln 2) ≈ 13.84` and
//! standard deviation `0.93` (`|f(ζ)|²` is exponential). Measured over 60
//! solves, the resultant has `14 170 ± 35` bits, matching `13.84·1024`. The
//! `f, g` width at degree `n` is therefore
//!
//! ```text
//! S(n) = ⌈14 170/n + 8·35/√n + 32⌉₆₄   (n ≤ 512; S(1024) = 64, the i64 input)
//! ```
//!
//! eight standard deviations plus sign and slack, rounded up to 64 bits.
//! A reduced `F` at degree `n` has at most `R(n) = S(n) + log₂(n) + 2` bits
//! (Babai leaves `|F_i| ≤ (n/2)·max|f_j|`), or `S(1) + log₂(q)` at the base,
//! and the lifted `F` at degree `n` has at most
//!
//! ```text
//! L(n) = ⌈R(n/2) + S(n) + log₂(n) + 32⌉₆₄
//! ```
//!
//! bits; `F, G` live in `L(n)` from the lift through the round-off. The
//! tables are [`SMALL_BITS`], [`reduced_bits`], and [`large_bits`]; the
//! largest measured sizes sit 52–284 bits under them. Exceeding a width
//! yields a wrong `(F, G)`, which key generation's `f·G − g·F = q` check
//! turns into an error.
use super::LOG_Q;
use super::fft::{Complex, fft, ifft, pair_norm_sq};
use super::poly::{Coeff, negacyclic_mul};
use crypto_bigint::{Choice, CtEq, CtOption, CtSelect, Int, Limb, Odd, U64, Uint, nlimbs};
use std::vec::Vec;

/// Bits of precision the floating-point round-off works with.
const PRECISION: u32 = 53;
/// The round-off quotient is scaled so that its largest FFT-domain value has
/// this exponent: every coefficient then stays below `2^61` before rounding
/// and fits the `f64 → i64` conversion.
const QUOTIENT_LIMIT: i32 = 60;
/// Largest round-off coefficient accepted from the FFT, `2^62`.
const MAX_ROUNDOFF: f64 = (1u64 << 62) as f64;

/// Width in bits of `f, g` at degree `2^i`, indexed by `i`: see the module
/// docs. Measured maxima over 60 solves: 14 244, 7 122, 3 570, 1 795, 900,
/// 455, 229, 113, 56, 26, 12.
const SMALL_BITS: [u32; 11] = [
    14_528, 7_360, 3_776, 1_920, 1_024, 576, 320, 192, 128, 128, 64,
];

/// Width in bits of `f, g` at degree `2^log_n`.
const fn small_bits(log_n: usize) -> u32 {
    SMALL_BITS[log_n]
}

/// Bits a reduced `F` or `G` at degree `2^log_n` occupies.
const fn reduced_bits(log_n: usize) -> u32 {
    if log_n == 0 {
        small_bits(0) + LOG_Q
    } else {
        small_bits(log_n) + log_n as u32 + 2
    }
}

/// Width in bits of `F, G` at degree `2^log_n`, from the lift through the
/// round-off. At the base it holds the Bézout coefficients times `q`.
const fn large_bits(log_n: usize) -> u32 {
    let raw = if log_n == 0 {
        reduced_bits(0)
    } else {
        reduced_bits(log_n - 1) + small_bits(log_n) + log_n as u32
    };
    (raw + 32).next_multiple_of(64)
}

/// A fixed-width two's-complement integer: the coefficient type of one
/// recursion level. Ring arithmetic wraps modulo `2^BITS`, which is exact
/// whenever the true value fits.
trait FixedInt: Coeff + Copy {
    /// `v`, sign-extended.
    fn from_i64(v: i64) -> Self;
    /// `self` as an `i64`, with whether it fit.
    fn to_i64(&self) -> (i64, Choice);
    /// `w`, sign-extended or truncated to this width.
    fn resize_from<W: FixedInt>(w: &W) -> Self;
    /// The limbs, least significant first.
    fn limbs(&self) -> &[Limb];
    /// Whether `self < 0`.
    fn is_negative(&self) -> Choice;
    /// `−self`.
    fn neg(&self) -> Self;
    /// The bit length of `|self|`, in constant time.
    fn magnitude_bits(&self) -> u32;
    /// `self >> shift` as a float, exact when the result has at most 53
    /// bits. Constant-time in both `self` and `shift`.
    fn shifted_to_f64(&self, shift: u32) -> f64;
    /// `self << shift`, wrapping. Constant-time in both `self` and `shift`.
    fn shl(&self, shift: u32) -> Self;
    /// `self · k`.
    fn mul_i64(&self, k: i64) -> Self;
    /// `u·a + v·b = 1` for odd `a` and `b`, both read as unsigned, or `None`
    /// when `a` is even or `gcd(a, b) ≠ 1`. The flag is constant-time; the
    /// computation is `v = b⁻¹ mod a` (Bernstein–Yang) and
    /// `u = (1 − v·b)·a⁻¹ mod 2^BITS`, exact because `a` divides `1 − v·b`.
    /// `b = 0` is reported as not coprime.
    fn bezout(a: &Self, b: &Self) -> CtOption<Bezout<Self>>;
}

/// Bézout coefficients `u·a + v·b = 1`.
#[derive(Clone, Copy, Debug)]
struct Bezout<W> {
    u: W,
    v: W,
}

/// An [`Int`] with the wrapping ring operations Karatsuba needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Wide<const L: usize>(Int<L>);

impl<const L: usize> Coeff for Wide<L> {
    fn zero() -> Self {
        Self(Int::ZERO)
    }
    fn add_assign_ref(&mut self, other: &Self) {
        self.0 = self.0.wrapping_add(&other.0);
    }
    fn sub_assign_ref(&mut self, other: &Self) {
        self.0 = self.0.wrapping_sub(&other.0);
    }
    fn add_ref(&self, other: &Self) -> Self {
        Self(self.0.wrapping_add(&other.0))
    }
    fn mul_ref(&self, other: &Self) -> Self {
        Self(self.0.wrapping_mul(&other.0))
    }
}

/// Limbs holding 64 bits.
const I64_LIMBS: usize = nlimbs(64);

/// The low 64 bits of `x`.
fn low_u64<const L: usize>(x: &Uint<L>) -> u64 {
    let narrow: U64 = x.resize();
    u64::from_le_bytes(narrow.to_le_bytes().into())
}

/// The `(F, G)` of a level, or `None` when no solution exists.
type Solution<L> = Option<(Vec<<L as Level>::Large>, Vec<<L as Level>::Large>)>;

impl<const L: usize> FixedInt for Wide<L> {
    fn from_i64(v: i64) -> Self {
        Self(Int::from_i64(v))
    }

    fn to_i64(&self) -> (i64, Choice) {
        let narrow: Int<I64_LIMBS> = self.0.resize();
        let round_trip: Int<L> = narrow.resize();
        (low_u64(narrow.as_uint()) as i64, round_trip.ct_eq(&self.0))
    }

    fn resize_from<W: FixedInt>(w: &W) -> Self {
        let fill = Limb::ZERO.ct_select(&Limb::MAX, w.is_negative());
        let src = w.limbs();
        let mut limbs = [Limb::ZERO; L];
        for (i, limb) in limbs.iter_mut().enumerate() {
            *limb = src.get(i).copied().unwrap_or(fill);
        }
        Self(*Uint::new(limbs).as_int())
    }

    fn limbs(&self) -> &[Limb] {
        self.0.as_uint().as_limbs()
    }

    fn is_negative(&self) -> Choice {
        self.0.is_negative()
    }

    fn neg(&self) -> Self {
        Self(self.0.wrapping_neg())
    }

    fn magnitude_bits(&self) -> u32 {
        self.0.abs().bit_width()
    }

    fn shifted_to_f64(&self, shift: u32) -> f64 {
        let (magnitude, negative) = self.0.abs_sign();
        let top = magnitude.overflowing_shr(shift).unwrap_or(Uint::ZERO);
        let sign = 1.0 - 2.0 * f64::from(negative.to_u8());
        sign * low_u64(&top) as f64
    }

    fn shl(&self, shift: u32) -> Self {
        Self(self.0.wrapping_shl(shift))
    }

    fn mul_i64(&self, k: i64) -> Self {
        Self(self.0.wrapping_mul(&Int::<I64_LIMBS>::from_i64(k)))
    }

    fn bezout(a: &Self, b: &Self) -> CtOption<Bezout<Self>> {
        let (a, b) = (*a.0.as_uint(), *b.0.as_uint());
        // `Odd::new` substitutes 1 for an even `a`, so the inversion below
        // always sees an odd modulus; the flag records the substitution.
        let modulus = Odd::new(a);
        let v = b.invert_odd_mod(modulus.as_inner_unchecked());
        let is_some = modulus.is_some().and(v.is_some());
        let v = v.to_inner_unchecked();
        // `a` odd makes it invertible modulo 2^BITS.
        let a_inv = a.invert_mod2k(Uint::<L>::BITS).to_inner_unchecked();
        let u = Uint::ONE
            .wrapping_sub(&v.wrapping_mul(&b))
            .wrapping_mul(&a_inv);
        CtOption::new(
            Bezout {
                u: Self(*u.as_int()),
                v: Self(*v.as_int()),
            },
            is_some,
        )
    }
}

/// One recursion level: the ring degree, the integer widths, and the next
/// (deeper, wider) level. The base level is its own `Next`.
trait Level {
    /// `log2` of the ring degree.
    const LOG_N: usize;
    /// Round-off iterations, fixed and public. The lifted `(F, G)` exceed
    /// the reduced ones by about `2·S(n)` bits, and a pass removes about
    /// 52 bits when `|f̂|, |ĝ|` are even across the roots of `x^n + 1`, but
    /// only about `50 − D` when the smallest `|f̂(ζ)|² + |ĝ(ζ)|²` sits `2^D`
    /// below the largest, because the 53-bit truncation error at that root
    /// is amplified. The spread is widest at `n = 4 … 16`. Over 385
    /// keygen-grade pairs the passes needed were (median / 99th percentile /
    /// max) 1/1/1, 2/2/2, 3/3/3, 5/6/6, 11/12/12, 22/26/29, 45/70/101,
    /// 93/222/482, 167/1293/3091, 268/274/275 for `n = 1024 … 2`. The table
    /// covers all but 0.5% of those pairs; a pair that misses yields a wrong
    /// `(F, G)`, which key generation detects and rejects like a gcd
    /// failure. Deep levels are cheap, so the budget there is generous.
    const REDUCE_ITERATIONS: usize;
    /// The width of `f, g` and of the field norms arriving from above.
    type Small: FixedInt;
    /// The width of `F, G` from the lift through the round-off.
    type Large: FixedInt;
    /// The level of half the degree.
    type Next: Level;
}

macro_rules! levels {
    ($($name:ident: $log_n:literal, $iterations:literal, $next:ident;)*) => {$(
        struct $name;
        impl Level for $name {
            const LOG_N: usize = $log_n;
            const REDUCE_ITERATIONS: usize = $iterations;
            type Small = Wide<{ nlimbs(small_bits($log_n)) }>;
            type Large = Wide<{ nlimbs(large_bits($log_n)) }>;
            type Next = $next;
        }
    )*};
}

levels! {
    L1024: 10, 4, L512;
    L512: 9, 6, L256;
    L256: 8, 8, L128;
    L128: 7, 14, L64;
    L64: 6, 28, L32;
    L32: 5, 64, L16;
    L16: 4, 240, L8;
    L8: 3, 800, L4;
    L4: 2, 1600, L2;
    L2: 1, 560, L1;
    L1: 0, 0, L1;
}

/// Solve `f·G − g·F = q` over `Z[x]/(x^n + 1)`, `n = f.len()` a power of
/// two at most `N`. Returns `(F, G)` reduced against `(f, g)`, or `None` if
/// no solution exists (`gcd(R_f, R_g) ≠ 1` or `R_f` even) or the reduced
/// solution does not fit `i64`.
///
/// The widths are sized for key generation's distribution of `f, g` at each
/// depth; a degree-`n` call treats its inputs as the field norms of such a
/// pair, so smaller inputs are always safe.
pub(crate) fn solve(f: &[i64], g: &[i64], q: u32) -> Option<(Vec<i64>, Vec<i64>)> {
    if f.len() != g.len() {
        return None;
    }
    match f.len() {
        1024 => solve_level::<L1024>(f, g, q),
        512 => solve_level::<L512>(f, g, q),
        256 => solve_level::<L256>(f, g, q),
        128 => solve_level::<L128>(f, g, q),
        64 => solve_level::<L64>(f, g, q),
        32 => solve_level::<L32>(f, g, q),
        16 => solve_level::<L16>(f, g, q),
        8 => solve_level::<L8>(f, g, q),
        4 => solve_level::<L4>(f, g, q),
        2 => solve_level::<L2>(f, g, q),
        1 => solve_level::<L1>(f, g, q),
        _ => None,
    }
}

/// [`solve`] at a given level: widen the inputs, solve, and narrow the
/// result to `i64`.
fn solve_level<L: Level>(f: &[i64], g: &[i64], q: u32) -> Option<(Vec<i64>, Vec<i64>)> {
    let widen = |p: &[i64]| p.iter().map(|&c| L::Small::from_i64(c)).collect::<Vec<_>>();
    let (big_f, big_g) = solve_in::<L>(&widen(f), &widen(g), q)?;
    let narrow = |p: &[L::Large]| {
        let mut fits = Choice::TRUE;
        let out: Vec<i64> = p
            .iter()
            .map(|c| {
                let (v, ok) = c.to_i64();
                fits = fits.and(ok);
                v
            })
            .collect();
        fits.to_bool().then_some(out)
    };
    Some((narrow(&big_f)?, narrow(&big_g)?))
}

/// The recursion: `(F, G)` in the level's large width.
fn solve_in<L: Level>(f: &[L::Small], g: &[L::Small], q: u32) -> Solution<L> {
    if L::LOG_N == 0 {
        return base_case::<L>(f.first()?, g.first()?, q);
    }
    let (fp, gp) = solve_in::<L::Next>(&field_norm::<L>(f), &field_norm::<L>(g), q)?;
    let mut big_f = lift_times_conjugate::<L>(&fp, g);
    let mut big_g = lift_times_conjugate::<L>(&gp, f);
    reduce::<L>(f, g, &mut big_f, &mut big_g)?;
    Some((big_f, big_g))
}

/// Degree 1: with `u·f0 + v·g0 = 1`, `F = −q·v` and `G = q·u` satisfy
/// `f0·G − g0·F = q`.
fn base_case<L: Level>(f0: &L::Small, g0: &L::Small, q: u32) -> Solution<L> {
    let a = L::Large::resize_from(f0);
    let b = L::Large::resize_from(g0);
    let Bezout { u, v } = L::Large::bezout(&a, &b).into_option()?;
    let q = i64::from(q);
    Some((std::vec![v.mul_i64(-q)], std::vec![u.mul_i64(q)]))
}

/// The halves `(f0, f1)` of `f = f0(x²) + x·f1(x²)`, converted to `T`.
fn halves<S: FixedInt, T: FixedInt>(f: &[S]) -> (Vec<T>, Vec<T>) {
    let even = f.iter().step_by(2).map(T::resize_from).collect();
    let odd = f.iter().skip(1).step_by(2).map(T::resize_from).collect();
    (even, odd)
}

/// `N(f) = f0² − x·f1²` in `Z[x]/(x^(n/2) + 1)`, where
/// `f = f0(x²) + x·f1(x²)`, in the next level's small width.
fn field_norm<L: Level>(f: &[L::Small]) -> Vec<<L::Next as Level>::Small> {
    let (even, odd) = halves::<_, <L::Next as Level>::Small>(f);
    let even_sq = negacyclic_mul(&even, &even);
    let mut shifted = negacyclic_mul(&odd, &odd);
    // x·p wraps the top coefficient to the bottom with a sign flip.
    shifted.rotate_right(1);
    if let Some(bottom) = shifted.first_mut() {
        *bottom = bottom.neg();
    }
    even_sq
        .into_iter()
        .zip(shifted)
        .map(|(mut e, s)| {
            e.sub_assign_ref(&s);
            e
        })
        .collect()
}

/// `p(x²)·q(−x)` in `Z[x]/(x^n + 1)`, for `p` the reduced solution of the
/// next level and `q` in this level's ring, in this level's large width.
///
/// With `q = q0(x²) + x·q1(x²)`, `q(−x) = q0(x²) − x·q1(x²)`, so the
/// product is `(p·q0)(x²) − x·(p·q1)(x²)`: two half-size products, and the
/// odd part never wraps.
fn lift_times_conjugate<L: Level>(
    p: &[<L::Next as Level>::Large],
    q: &[L::Small],
) -> Vec<L::Large> {
    let p: Vec<L::Large> = p.iter().map(L::Large::resize_from).collect();
    let (q0, q1) = halves::<_, L::Large>(q);
    negacyclic_mul(&p, &q0)
        .into_iter()
        .zip(negacyclic_mul(&p, &q1))
        .flat_map(|(even, odd)| [even, odd.neg()])
        .collect()
}

/// `max(a, b)` in constant time.
fn ct_max(a: u32, b: u32) -> u32 {
    Choice::from_u32_lt(a, b).select_u32(a, b)
}

/// `min(a, b)` in constant time.
fn ct_min(a: u32, b: u32) -> u32 {
    Choice::from_u32_lt(a, b).select_u32(b, a)
}

/// The largest bit length of `|c|` over `p`, in constant time.
fn max_magnitude_bits<W: FixedInt>(p: &[W]) -> u32 {
    p.iter().fold(0, |m, c| ct_max(m, c.magnitude_bits()))
}

/// Each coefficient as `(c >> shift)` in floating point.
fn shifted_to_f64<W: FixedInt>(p: &[W], shift: u32) -> Vec<f64> {
    p.iter().map(|c| c.shifted_to_f64(shift)).collect()
}

/// `2^e` as a float for `e < 1024`, built from its bit pattern.
fn pow2(e: u32) -> f64 {
    f64::from_bits(u64::from(1023 + e) << 52)
}

/// `acc −= (f·k) << scale` in `Z[x]/(x^n + 1)`, schoolbook with a small
/// multiplier: `n²` word-by-limb products rather than wide ones.
fn sub_scaled<W: FixedInt>(acc: &mut [W], f: &[W], k: &[i64], scale: u32) {
    let n = f.len();
    let mut product = std::vec![W::zero(); n];
    for (j, fj) in f.iter().enumerate() {
        let (plain, wrapped) = k.split_at(n - j);
        for (t, &ki) in product[j..].iter_mut().zip(plain) {
            t.add_assign_ref(&fj.mul_i64(ki));
        }
        for (t, &ki) in product[..j].iter_mut().zip(wrapped) {
            t.sub_assign_ref(&fj.mul_i64(ki));
        }
    }
    for (a, p) in acc.iter_mut().zip(&product) {
        a.sub_assign_ref(&p.shl(scale));
    }
}

/// `⌊log₂ x⌉`-style exponent of a float: `floor(log2(x))` for normal
/// positive `x`, read from the bit pattern so no comparison is needed.
/// Zero and subnormals give `−1023`, infinities and NaN give `1024`.
fn exponent(x: f64) -> i32 {
    ((x.to_bits() >> 52) & 0x7ff) as i32 - 1023
}

/// Babai round-off: subtract `k·(f, g)` from `(F, G)` with
/// `k = ⌊(F·f* + G·g*) / (f·f* + g·g*)⌉`, a fixed number of times.
///
/// Each pass takes the top 53 bits of `(F, G)` and of `(f, g)` and forms the
/// quotient in the FFT domain. The quotient is scaled by `2^boost` so that
/// it carries as many bits as the `f64 → i64` conversion allows: a
/// coefficient of `k` is at most `max_ζ |k̂(ζ)|`, so with
/// `e = ⌊log₂ max_ζ |k̂(ζ)|⌋` any `boost ≤ 60 − e` keeps `|k_i| < 2^61`
/// before rounding. The integer `k·2^scale` is then subtracted with
/// `scale = gap − boost`, where `gap` is the difference of the two top-bit
/// shifts, so `boost ≤ gap` too. Once `(F, G)` is no longer than `(f, g)`,
/// the quotient rounds to zero and the remaining passes are no-ops.
fn reduce<L: Level>(
    f: &[L::Small],
    g: &[L::Small],
    big_f: &mut [L::Large],
    big_g: &mut [L::Large],
) -> Option<()> {
    let size = ct_max(max_magnitude_bits(f), max_magnitude_bits(g));
    let small_shift = ct_max(size, PRECISION) - PRECISION;
    let fa = fft(&shifted_to_f64(f, small_shift)).ok()?;
    let ga = fft(&shifted_to_f64(g, small_shift)).ok()?;
    let den = pair_norm_sq(&fa, &ga);
    let f_large: Vec<L::Large> = f.iter().map(L::Large::resize_from).collect();
    let g_large: Vec<L::Large> = g.iter().map(L::Large::resize_from).collect();

    for _ in 0..L::REDUCE_ITERATIONS {
        let big_size = ct_max(max_magnitude_bits(big_f), max_magnitude_bits(big_g));
        let big_shift = ct_max(ct_max(big_size, size), PRECISION) - PRECISION;
        let gap = big_shift - small_shift;
        let big_fa = fft(&shifted_to_f64(big_f, big_shift)).ok()?;
        let big_ga = fft(&shifted_to_f64(big_g, big_shift)).ok()?;
        let quotient: Vec<Complex> = big_fa
            .iter()
            .zip(&big_ga)
            .zip(fa.iter().zip(&ga))
            .zip(&den)
            .map(|(((&bf, &bg), (sf, sg)), d)| (bf * sf.conj() + bg * sg.conj()).scale(1.0 / d))
            .collect();
        // |k̂| ≤ |re| + |im|; `max` and `clamp` compile to selects.
        let largest = quotient
            .iter()
            .fold(0.0_f64, |m, c| m.max(c.re.abs() + c.im.abs()));
        let boost = (QUOTIENT_LIMIT - exponent(largest)).clamp(0, i32::MAX) as u32;
        let boost = ct_min(gap, boost);
        let scale = gap - boost;
        let mult = pow2(boost);
        // Saturating conversion: a non-finite quotient clamps instead of
        // branching and surfaces in the final check.
        let k: Vec<i64> = ifft(&quotient)
            .ok()?
            .into_iter()
            .map(|c| (c * mult).round().clamp(-MAX_ROUNDOFF, MAX_ROUNDOFF) as i64)
            .collect();
        sub_scaled(big_f, &f_large, &k, scale);
        sub_scaled(big_g, &g_large, &k, scale);
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lattice::poly::checked_mul_i128;
    use crate::lattice::{GS_NORM_BOUND, gram_schmidt_norm, sample_poly};
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    type W128 = Wide<{ nlimbs(128) }>;
    type W256 = Wide<{ nlimbs(256) }>;

    fn w128(v: i128) -> W128 {
        Wide(Int::from_i128(v))
    }

    fn to_i128(w: &W128) -> i128 {
        let limbs = w.limbs();
        let low = u128::from(low_u64(&Uint::<{ nlimbs(128) }>::new(
            core::array::from_fn(|i| limbs[i]),
        )));
        let high: Vec<Limb> = limbs.iter().skip(I64_LIMBS).copied().collect();
        let high = u128::from(low_u64(&Uint::<{ nlimbs(128) }>::new(
            core::array::from_fn(|i| high.get(i).copied().unwrap_or(Limb::ZERO)),
        )));
        ((high << 64) | low) as i128
    }

    /// `f·G − g·F` over `i128`.
    fn residual(f: &[i64], g: &[i64], big_f: &[i64], big_g: &[i64]) -> Vec<i128> {
        let wide = |p: &[i64]| p.iter().map(|&c| i128::from(c)).collect::<Vec<_>>();
        let fg = checked_mul_i128(&wide(f), &wide(big_g)).expect("small");
        let gf = checked_mul_i128(&wide(g), &wide(big_f)).expect("small");
        fg.iter().zip(&gf).map(|(a, b)| a - b).collect()
    }

    /// The textbook extended Euclidean algorithm over `i128`.
    fn reference_xgcd(a: i128, b: i128) -> (i128, i128, i128) {
        let (mut r0, mut r1) = (a, b);
        let (mut s0, mut s1) = (1i128, 0i128);
        let (mut t0, mut t1) = (0i128, 1i128);
        while r1 != 0 {
            let quot = r0 / r1;
            (r0, r1) = (r1, r0 - quot * r1);
            (s0, s1) = (s1, s0 - quot * s1);
            (t0, t1) = (t1, t0 - quot * t1);
        }
        (r0, s0, t0)
    }

    #[test]
    fn width_table_is_consistent() {
        for log_n in 0..11 {
            assert_eq!(small_bits(log_n) % 64, 0);
            assert_eq!(large_bits(log_n) % 64, 0);
            assert!(reduced_bits(log_n) < large_bits(log_n));
            if log_n > 0 {
                assert!(small_bits(log_n) <= small_bits(log_n - 1));
                assert!(reduced_bits(log_n - 1) + small_bits(log_n) < large_bits(log_n));
            }
        }
        // The measured maxima from the module docs, with room to spare.
        let measured = [14_244, 7_122, 3_570, 1_795, 900, 455, 229, 113, 56, 26, 12];
        for (log_n, m) in measured.into_iter().enumerate() {
            assert!(small_bits(log_n) >= m + 52, "degree 2^{log_n}");
        }
        assert_eq!(large_bits(0), 14_592);
        assert_eq!(large_bits(1), 21_952);
        assert_eq!(large_bits(10), 256);
    }

    #[test]
    fn bezout_matches_the_reference_on_random_and_edge_inputs() {
        let mut rng = StdRng::from_seed([21u8; 32]);
        let check = |a: i128, b: i128| {
            let (gcd, _, _) = reference_xgcd(a, b);
            let result = W128::bezout(&w128(a), &w128(b));
            let expected = a % 2 == 1 && gcd == 1 && b != 0;
            assert_eq!(result.is_some().to_bool(), expected, "a = {a}, b = {b}");
            if expected {
                let Bezout { u, v } = result.into_option().expect("some");
                let (u, v) = (to_i128(&u), to_i128(&v));
                assert_eq!(u * a + v * b, 1, "a = {a}, b = {b}");
                assert!(v >= 0 && v < a);
            }
        };
        // Up to 62 bits each so the check `u·a + v·b` stays within i128.
        for _ in 0..200 {
            let a = i128::from(rng.random::<u64>() >> 2) | 1;
            let b = i128::from(rng.random::<u64>() >> (2 + rng.random_range(0..40)));
            check(a, b);
        }
        // Edge cases: b > a, b even, gcd ≠ 1, even a, tiny values, b = 0.
        for (a, b) in [
            (7, 100),
            (15, 6),
            (9, 3),
            (1, 5),
            (3, 1),
            (12, 7),
            (1, 0),
            (5, 0),
            (99_991, 2),
            ((1i128 << 60) + 1, 1i128 << 61),
            ((1i128 << 60) + 1, (1i128 << 60) + 1),
        ] {
            check(a, b);
        }
    }

    #[test]
    fn fixed_int_helpers_match_their_definitions() {
        let minus_five = W128::from_i64(-5);
        assert_eq!(to_i128(&minus_five), -5);
        assert!(minus_five.is_negative().to_bool());
        assert_eq!(minus_five.neg(), w128(5));
        assert_eq!(minus_five.magnitude_bits(), 3);
        assert_eq!(W128::zero().magnitude_bits(), 0);
        assert_eq!(minus_five.mul_i64(-7), w128(35));
        assert_eq!(w128(1 << 70).mul_i64(3), w128(3 << 70));
        assert_eq!(minus_five.shl(70), w128(-5 << 70));
        assert_eq!(w128(-(1 << 70)).shifted_to_f64(60), -1024.0);
        assert_eq!(w128(3 << 20).shifted_to_f64(10), 3072.0);
        assert_eq!(w128(3).shifted_to_f64(10), 0.0);

        // Sign-extending resize both ways.
        let wide = W256::resize_from(&minus_five);
        assert!(wide.is_negative().to_bool());
        assert_eq!(wide.mul_i64(1), W256::from_i64(-5));
        assert_eq!(W128::resize_from(&wide), minus_five);
        let big = w128(1 << 100);
        assert_eq!(W128::resize_from(&W256::resize_from(&big)), big);

        // i64 conversion reports what fits.
        let (v, ok) = w128(i128::from(i64::MIN)).to_i64();
        assert_eq!((v, ok.to_bool()), (i64::MIN, true));
        let (_, ok) = w128(i128::from(i64::MAX) + 1).to_i64();
        assert!(!ok.to_bool());
        let (_, ok) = w128(i128::from(i64::MIN) - 1).to_i64();
        assert!(!ok.to_bool());

        assert_eq!(pow2(0), 1.0);
        assert_eq!(pow2(62), MAX_ROUNDOFF);
        assert_eq!(
            (ct_max(3, 9), ct_max(9, 3), ct_min(3, 9), ct_min(9, 3)),
            (9, 9, 3, 3)
        );
        assert_eq!(max_magnitude_bits(&[w128(0), w128(-9), w128(3)]), 4);
        assert_eq!(
            shifted_to_f64(&[w128(1 << 20), w128(-(1 << 21))], 10),
            [1024.0, -2048.0]
        );
    }

    /// `p(x) ↦ p(x²)`, doubling the degree.
    fn lift(p: &[W256]) -> Vec<W256> {
        p.iter().flat_map(|&c| [c, W256::zero()]).collect()
    }

    /// `p(x) ↦ p(−x)`.
    fn conjugate(p: &[W256]) -> Vec<W256> {
        p.iter()
            .enumerate()
            .map(|(i, c)| if i.is_multiple_of(2) { *c } else { c.neg() })
            .collect()
    }

    fn to_w256(p: &[i64]) -> Vec<W256> {
        p.iter().map(|&c| W256::from_i64(c)).collect()
    }

    #[test]
    fn lift_times_conjugate_matches_the_full_product() {
        // L4 → L2: p lives in L2's large width, q in L4's small width.
        let p: Vec<<L2 as Level>::Large> = [3, -1]
            .iter()
            .map(|&c| <L2 as Level>::Large::from_i64(c))
            .collect();
        let q: Vec<<L4 as Level>::Small> = [2, 7, -1, 8]
            .iter()
            .map(|&c| <L4 as Level>::Small::from_i64(c))
            .collect();
        let got: Vec<W256> = lift_times_conjugate::<L4>(&p, &q)
            .iter()
            .map(W256::resize_from)
            .collect();
        let expected = negacyclic_mul(
            &lift(&to_w256(&[3, -1])),
            &conjugate(&to_w256(&[2, 7, -1, 8])),
        );
        assert_eq!(got, expected);
    }

    #[test]
    fn field_norm_satisfies_its_defining_identity() {
        // N(f)(x²) = f(x)·f(−x), at L8 → L4.
        let coeffs = [3, -1, 4, 1, -5, 9, 2, -6];
        let f: Vec<<L8 as Level>::Small> = coeffs
            .iter()
            .map(|&c| <L8 as Level>::Small::from_i64(c))
            .collect();
        let norm: Vec<W256> = field_norm::<L8>(&f).iter().map(W256::resize_from).collect();
        let rhs = negacyclic_mul(&to_w256(&coeffs), &conjugate(&to_w256(&coeffs)));
        assert_eq!(lift(&norm), rhs);
        let (even, odd) = halves::<_, W256>(&f);
        assert_eq!(
            (even, odd),
            (to_w256(&[3, 4, -5, 2]), to_w256(&[-1, 1, 9, -6]))
        );
    }

    #[test]
    fn sub_scaled_matches_the_negacyclic_product() {
        let f = to_w256(&[3, -1, 4, 1]);
        let k = [2i64, -7, 5, 11];
        let mut acc = to_w256(&[100, 200, 300, 400]);
        sub_scaled(&mut acc, &f, &k, 3);
        let kw: Vec<W256> = k.iter().map(|&v| W256::from_i64(v)).collect();
        let expected: Vec<W256> = to_w256(&[100, 200, 300, 400])
            .iter()
            .zip(negacyclic_mul(&f, &kw))
            .map(|(a, p)| {
                let mut a = *a;
                a.sub_assign_ref(&p.shl(3));
                a
            })
            .collect();
        assert_eq!(acc, expected);
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
                let mut expected = std::vec![0i128; 64];
                expected[0] = i128::from(q);
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
    fn solve_rejects_a_common_factor_or_a_bad_shape() {
        // f = g = 2: Res = 2^n for both, so gcd ≠ 1 (and R_f is even).
        let mut f = std::vec![0i64; 8];
        f[0] = 2;
        assert!(solve(&f, &f, 12_289).is_none());
        // f = 3, g = 6 at degree 1: odd R_f but gcd ≠ 1.
        assert!(solve(&[3], &[6], 12_289).is_none());
        assert_eq!(solve(&[3], &[2], 7), Some((std::vec![-14], std::vec![-7])));
        // Not a power of two, mismatched lengths, too long.
        assert!(solve(&f[..3], &f[..3], 12_289).is_none());
        assert!(solve(&f[..4], &f[..2], 12_289).is_none());
        assert!(solve(&[1; 2048], &[1; 2048], 12_289).is_none());
    }

    /// A keygen-grade `(f, g)`: Gaussian, `f(1)` odd, within the norm bound.
    fn keygen_pair(rng: &mut StdRng) -> (Vec<i64>, Vec<i64>) {
        loop {
            let f = sample_poly(&mut *rng).expect("sample");
            let g = sample_poly(&mut *rng).expect("sample");
            if f.eval_at_one() % 2 != 0
                && gram_schmidt_norm(&f, &g).expect("finite") <= GS_NORM_BOUND
            {
                return (f.coeffs().to_vec(), g.coeffs().to_vec());
            }
        }
    }

    /// Every level's output stays within its reduced-width bound: the
    /// field norms of a keygen-grade pair are solved from each depth and the
    /// result's bit length checked against [`reduced_bits`].
    #[test]
    fn every_level_reduces_within_its_width_budget() {
        fn descend<L: Level>(f: &[L::Small], g: &[L::Small]) -> usize {
            let Some((big_f, big_g)) = solve_in::<L>(f, g, 1 << LOG_Q) else {
                return 0;
            };
            let bits = ct_max(max_magnitude_bits(&big_f), max_magnitude_bits(&big_g));
            assert!(
                bits <= reduced_bits(L::LOG_N),
                "degree 2^{}: {bits} bits > {}",
                L::LOG_N,
                reduced_bits(L::LOG_N)
            );
            let solved = if L::LOG_N == 0 {
                0
            } else {
                descend::<L::Next>(&field_norm::<L>(f), &field_norm::<L>(g))
            };
            solved + 1
        }
        let mut rng = StdRng::from_seed([33u8; 32]);
        let mut solved = 0;
        while solved == 0 {
            let (f, g) = keygen_pair(&mut rng);
            let widen = |p: &[i64]| {
                p.iter()
                    .map(|&c| <L1024 as Level>::Small::from_i64(c))
                    .collect::<Vec<_>>()
            };
            solved = descend::<L1024>(&widen(&f), &widen(&g));
        }
        assert_eq!(solved, 11);
    }

    /// Welch's t-test between a fixed and a random input class, as in
    /// dudect. Run with `--ignored --nocapture`; `|t| < 4.5` passes.
    #[test]
    #[ignore = "timing measurement; run with --ignored --nocapture"]
    fn bezout_timing_is_input_independent() {
        type Base = <L1 as Level>::Large;
        const SAMPLES: usize = 400;
        let mut rng = StdRng::from_seed([51u8; 32]);
        // A random non-negative value of `small_bits(0)` bits in the base width.
        let random_small = |rng: &mut StdRng| {
            let limbs: [Limb; nlimbs(large_bits(0))] = core::array::from_fn(|i| {
                if i < nlimbs(small_bits(0)) {
                    Limb(rng.random::<crypto_bigint::Word>())
                } else {
                    Limb::ZERO
                }
            });
            Base::resize_from(&Wide(*Uint::new(limbs).as_int()))
        };
        let random_input = |rng: &mut StdRng| {
            let a = random_small(rng).mul_i64(2).add_ref(&Base::from_i64(1));
            (a, random_small(rng))
        };
        let fixed = random_input(&mut rng);
        let mut timings: [Vec<f64>; 2] = [Vec::new(), Vec::new()];
        for _ in 0..2 * SAMPLES {
            let class = usize::from(rng.random::<bool>());
            let (a, b) = if class == 0 {
                fixed
            } else {
                random_input(&mut rng)
            };
            let start = std::time::Instant::now();
            let out = Base::bezout(&a, &b);
            let elapsed = start.elapsed().as_nanos() as f64;
            core::hint::black_box(out);
            timings[class].push(elapsed);
        }
        let stats = |xs: &[f64]| {
            let n = xs.len() as f64;
            let mean = xs.iter().sum::<f64>() / n;
            let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
            (mean, var / n)
        };
        let (m0, v0) = stats(&timings[0]);
        let (m1, v1) = stats(&timings[1]);
        let t = (m0 - m1) / (v0 + v1).sqrt();
        std::eprintln!(
            "bezout Welch t = {t:.3} (fixed {:.0} ns over {}, random {:.0} ns over {})",
            m0,
            timings[0].len(),
            m1,
            timings[1].len()
        );
        assert!(t.abs() < 4.5, "|t| = {}", t.abs());
    }
}
