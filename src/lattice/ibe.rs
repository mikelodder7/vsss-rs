/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! The modified Ducas–Lyubashevsky–Prest identity-based encryption
//! (App. B.3 of ePrint 2026/813): `Extract`, `VerKey`, `Enc`, and `Dec`.
//!
//! With `VerKey` passing, decryption of every honestly generated ciphertext
//! is correct (Thm. B.1): `|r·s1 − e1·s2| ≤ B_x·Γ_key`, plus `|e2| ≤ 1` and
//! the rounding error `2^(ℓ−1)`, stays below `q/4`.
use super::hash::{hash_to_mask, hash_to_ring};
use super::keygen::{MasterPublicKey, MasterSecretKey};
use super::ring::PolyQ;
use super::{B_X, GAMMA_KEY, N, Q, ROUNDING_BITS};
use crate::secret::Secret;
use crate::{Error, VsssResult};
use core::fmt::{self, Debug, Formatter};
use ctutils::{Choice, CtEq, CtGt, CtLt};
use digest::Digest;
use rand_core::CryptoRng;
use std::vec::Vec;

/// Extraction attempts before giving up. A sample exceeds `Γ_key` only if
/// its norm is 27% above its mean `σ·√(2N)`, which essentially never
/// happens, so even one retry is rare.
const MAX_EXTRACT_ATTEMPTS: usize = 64;
/// Encryption resampling rounds for `(r, e1)`. `wt(r) + wt(e1)` has mean
/// `4N/3 ≈ 1365` and standard deviation about 21, so the bound `B_x² = 1600`
/// is eleven deviations out.
const MAX_ENCRYPT_ATTEMPTS: usize = 64;
/// Bytes in the packed `N`-bit key `k`.
const KEY_BYTES: usize = N / 8;

/// An identity secret key `sk_ID = s2`, with `s1 = t − s2·h` short for
/// `t = H(ID)`.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct IdentitySecretKey {
    s2: PolyQ,
}

impl Debug for IdentitySecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("IdentitySecretKey { .. }")
    }
}

impl IdentitySecretKey {
    /// Wrap `s2`. Whether it is a valid key for an identity is up to
    /// [`verify_key`].
    pub fn new(s2: PolyQ) -> Self {
        Self { s2 }
    }

    /// The key polynomial `s2`.
    pub fn s2(&self) -> &PolyQ {
        &self.s2
    }

    /// `p·s2`, guarded so the product is wiped on drop.
    pub(crate) fn mul_s2(&self, p: &PolyQ) -> Secret<PolyQ> {
        Secret::new(p * &self.s2)
    }

    /// The `4·N`-byte encoding of `s2`.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.s2.to_bytes()
    }

    /// Decode [`Self::to_bytes`], rejecting anything that is not an element
    /// of `R_q`.
    pub fn from_bytes(bytes: &[u8]) -> VsssResult<Self> {
        PolyQ::from_bytes(bytes).map(Self::new)
    }
}

/// An IBE ciphertext `(u, v, c')` in `R_q × R_q × {0,1}^m`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Ciphertext {
    u: PolyQ,
    v: PolyQ,
    masked: Vec<u8>,
}

impl Ciphertext {
    /// `u = r·h + e1`.
    pub fn u(&self) -> &PolyQ {
        &self.u
    }

    /// `v = r·t + e2 + ⌊q/2⌉·k`, rounded to a multiple of `2^ℓ`.
    pub fn v(&self) -> &PolyQ {
        &self.v
    }

    /// `c' = m ⊕ H'(k)`.
    pub fn masked(&self) -> &[u8] {
        &self.masked
    }

    /// Encode as `u ‖ v ‖ c'`, the ring elements as in [`PolyQ::to_bytes`].
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.u.to_bytes();
        out.extend_from_slice(&self.v.to_bytes());
        out.extend_from_slice(&self.masked);
        out
    }

    /// Decode [`Self::to_bytes`]. This is the paper's `⊥` check: input that
    /// is not in `R_q² × {0,1}^*` is rejected.
    pub fn from_bytes(bytes: &[u8]) -> VsssResult<Self> {
        let ring_bytes = 4 * N;
        let (u, rest) = bytes
            .split_at_checked(ring_bytes)
            .ok_or(Error::Lattice("ciphertext is too short"))?;
        let (v, masked) = rest
            .split_at_checked(ring_bytes)
            .ok_or(Error::Lattice("ciphertext is too short"))?;
        Ok(Self {
            u: PolyQ::from_bytes(u)?,
            v: PolyQ::from_bytes(v)?,
            masked: masked.to_vec(),
        })
    }
}

/// `Extract(B, ID)`: sample `(s1, s2) = (t, 0) − GaussianSampler(B, σ, (t, 0))`
/// with `t = H(ID)` and `σ = 2·1.17·√q`, repeating until [`verify_key`]
/// accepts `s2`.
///
/// Extraction is randomized. Callers should extract each identity once and
/// keep the key, as the paper's local cache does.
///
/// # Security
///
/// About 110-bit classical security, below 128; see the
/// [module docs](crate::lattice#security-level).
pub fn extract<D: Digest>(
    msk: &MasterSecretKey,
    mpk: &MasterPublicKey,
    id: &[u8],
    mut rng: impl CryptoRng,
) -> VsssResult<IdentitySecretKey> {
    let sampler = msk.sampler();
    let t = hash_to_ring::<D>(id);
    for _ in 0..MAX_EXTRACT_ATTEMPTS {
        let s2 = Secret::new(sampler.sample_key(&t, &mut rng)?);
        let key = IdentitySecretKey::new(PolyQ::from(&*s2));
        if verify_key_with_t(mpk, &t, &key) {
            return Ok(key);
        }
    }
    Err(Error::Lattice("key extraction exhausted its attempts"))
}

/// `VerKey(h, ID, sk)`: accept when `s1 = [t − s2·h]_q` and `[s2]_q` satisfy
/// `‖(s1, s2)‖₂ ≤ Γ_key` over the integers.
pub fn verify_key<D: Digest>(mpk: &MasterPublicKey, id: &[u8], key: &IdentitySecretKey) -> bool {
    verify_key_with_t(mpk, &hash_to_ring::<D>(id), key)
}

/// [`verify_key`] for an identity already hashed to `t = H(ID)`. Each norm
/// is below `2^68`, so their sum cannot overflow.
fn verify_key_with_t(mpk: &MasterPublicKey, t: &PolyQ, key: &IdentitySecretKey) -> bool {
    let s1 = Secret::new(t - &*key.mul_s2(mpk.h()));
    let norm_sq = s1.centered_norm_sq() + key.s2().centered_norm_sq();
    (!norm_sq.ct_gt(&u128::from(GAMMA_KEY).pow(2))).to_bool()
}

/// `Enc(h, ID, m)` for a message `m` of any length.
///
/// # Security
///
/// About 110-bit classical security, below 128; see the
/// [module docs](crate::lattice#security-level).
pub fn encrypt<D: Digest>(
    mpk: &MasterPublicKey,
    id: &[u8],
    message: &[u8],
    mut rng: impl CryptoRng,
) -> VsssResult<Ciphertext> {
    let (r, e1) = (0..MAX_ENCRYPT_ATTEMPTS)
        .map(|_| (ternary(&mut rng), ternary(&mut rng)))
        .find(|(r, e1)| weight(r) + weight(e1) <= B_X * B_X)
        .ok_or(Error::Lattice(
            "encryption randomness exhausted its attempts",
        ))?;
    let (r, e1) = (Secret::new(r), Secret::new(e1));
    let e2 = Secret::new(ternary(&mut rng));
    let mut k = Secret::new([0u8; KEY_BYTES]);
    rng.fill_bytes(&mut *k);

    let t = hash_to_ring::<D>(id);
    let r_q = Secret::new(PolyQ::from_signed(&r)?);
    let u = &(&*r_q * mpk.h()) + &*Secret::new(PolyQ::from_signed(&e1)?);
    let half_q_k = Secret::new(PolyQ::from_reduced(
        key_bits(&*k).map(|b| b * (Q / 2)).collect(),
    ));
    let e2_q = Secret::new(PolyQ::from_signed(&e2)?);
    let unrounded = Secret::new(&(&(&*r_q * &t) + &*e2_q) + &*half_q_k);
    let v = round_low_bits(&unrounded);
    let masked = xor(message, &hash_to_mask::<D>(&*k, message.len() * 8));
    Ok(Ciphertext { u, v, masked })
}

/// `Dec(sk_ID, (u, v, c'))`: `k_i = 0` when `|[v − u·s2]_q|_i < q/4` and `1`
/// otherwise, then `m = c' ⊕ H'(k)`. A malformed ciphertext cannot reach
/// this point: [`Ciphertext::from_bytes`] and deserialization reject it.
pub fn decrypt<D: Digest>(key: &IdentitySecretKey, ciphertext: &Ciphertext) -> Vec<u8> {
    let w = Secret::new(ciphertext.v() - &*key.mul_s2(ciphertext.u()));
    let k = Secret::new(
        w.coeffs()
            .chunks(8)
            .map(|bits| {
                bits.iter()
                    .enumerate()
                    .fold(0u8, |byte, (j, &c)| byte | (key_bit(c).to_u8() << j))
            })
            .collect::<Vec<u8>>(),
    );
    xor(
        ciphertext.masked(),
        &hash_to_mask::<D>(&k, ciphertext.masked().len() * 8),
    )
}

/// The key bit `|[w]_q| ≥ q/4` for a coefficient `w ∈ [0, q)`.
///
/// With `q = 2^29` that is `q/4 ≤ w ≤ 3q/4`, decided by two constant-time
/// comparisons so the time does not depend on the secret `w`.
fn key_bit(w: u32) -> Choice {
    const QUARTER: u32 = Q / 4;
    !(w.ct_lt(&QUARTER) | w.ct_gt(&(Q - QUARTER)))
}

/// `N` coefficients drawn uniformly from `{−1, 0, 1}`, two random bits at a
/// time with the pattern `11` rejected.
fn ternary<R: CryptoRng + ?Sized>(rng: &mut R) -> Vec<i64> {
    core::iter::repeat_with(|| rng.next_u64())
        .flat_map(|word| (0..32).map(move |i| (word >> (2 * i)) & 3))
        .filter(|&pair| pair != 3)
        .map(|pair| pair as i64 - 1)
        .take(N)
        .collect()
}

/// `wt(x)`, the number of non-zero coefficients.
fn weight(x: &[i64]) -> usize {
    x.iter().map(|c| usize::from(c.ct_ne(&0).to_u8())).sum()
}

/// The `N` bits of the packed key, least-significant bit first.
fn key_bits(k: &[u8]) -> impl Iterator<Item = u32> + '_ {
    k.iter()
        .flat_map(|byte| (0..8).map(move |j| u32::from((byte >> j) & 1)))
}

/// `v := 2^ℓ·⌊v / 2^ℓ⌉ mod q`, rounding halves up.
fn round_low_bits(v: &PolyQ) -> PolyQ {
    let half = 1u32 << (ROUNDING_BITS - 1);
    PolyQ::from_reduced(
        v.coeffs()
            .iter()
            .map(|&c| (((c + half) >> ROUNDING_BITS) << ROUNDING_BITS) & (Q - 1))
            .collect(),
    )
}

/// `a ⊕ b` over the shorter length; callers pass equal lengths.
fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lattice::test_support::keys;
    use rand::{SeedableRng, rngs::StdRng};
    use sha2::Sha256;

    #[test]
    fn extracted_keys_pass_verification_for_several_identities() {
        let (msk, mpk) = &keys()[0];
        let mut rng = StdRng::from_seed([71u8; 32]);
        for id in [b"dealer-1/1".as_slice(), b"dealer-1/2", b"", b"x"] {
            let key = extract::<Sha256>(msk, mpk, id, &mut rng).expect("extract");
            assert!(verify_key::<Sha256>(mpk, id, &key));
            // s1 = [t − s2·h]_q is short, so s1 + s2·h ≡ t with small s1.
            let t = hash_to_ring::<Sha256>(id);
            let s1 = &t - &(key.s2() * mpk.h());
            assert_eq!(&s1 + &(key.s2() * mpk.h()), t);
            assert!(s1.centered_norm_sq() < u128::from(GAMMA_KEY).pow(2));
            // The key is for this identity only.
            assert!(!verify_key::<Sha256>(mpk, b"someone else", &key));
            assert_eq!(std::format!("{key:?}"), "IdentitySecretKey { .. }");
        }
    }

    #[test]
    fn verify_key_with_t_matches_verify_key() {
        let (msk, mpk) = &keys()[1];
        let mut rng = StdRng::from_seed([77u8; 32]);
        let key = extract::<Sha256>(msk, mpk, b"hashed", &mut rng).expect("extract");
        let t = hash_to_ring::<Sha256>(b"hashed");
        assert!(verify_key_with_t(mpk, &t, &key));
        let other = hash_to_ring::<Sha256>(b"other");
        assert!(!verify_key_with_t(mpk, &other, &key));
    }

    #[test]
    fn verify_key_rejects_forged_and_foreign_keys() {
        let (msk, mpk) = &keys()[0];
        let (_, other_mpk) = &keys()[1];
        let mut rng = StdRng::from_seed([72u8; 32]);
        let id = b"dealer/3";
        let key = extract::<Sha256>(msk, mpk, id, &mut rng).expect("extract");
        assert!(!verify_key::<Sha256>(other_mpk, id, &key));
        assert!(!verify_key::<Sha256>(
            mpk,
            id,
            &IdentitySecretKey::new(PolyQ::zero())
        ));
        let mut tweaked = key.s2().coeffs().to_vec();
        tweaked[0] ^= 1 << 27;
        let forged = IdentitySecretKey::new(PolyQ::from_coeffs(&tweaked).expect("length N"));
        assert!(!verify_key::<Sha256>(mpk, id, &forged));
    }

    #[test]
    fn encryption_round_trips_for_several_message_lengths() {
        let (msk, mpk) = &keys()[2];
        let mut rng = StdRng::from_seed([73u8; 32]);
        let id = b"receiver";
        let key = extract::<Sha256>(msk, mpk, id, &mut rng).expect("extract");
        let other = extract::<Sha256>(msk, mpk, b"another receiver", &mut rng).expect("extract");
        for len in [0usize, 1, 31, 96, 128, 1000] {
            let message: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            let ct = encrypt::<Sha256>(mpk, id, &message, &mut rng).expect("encrypt");
            assert_eq!(ct.masked().len(), len);
            assert!(
                ct.v()
                    .coeffs()
                    .iter()
                    .all(|c| c.trailing_zeros() >= ROUNDING_BITS)
            );
            assert_eq!(decrypt::<Sha256>(&key, &ct), message);
            if len >= 16 {
                assert_ne!(decrypt::<Sha256>(&other, &ct), message);
            }
            let bytes = ct.to_bytes();
            assert_eq!(bytes.len(), 8 * N + len);
            assert_eq!(Ciphertext::from_bytes(&bytes).expect("well formed"), ct);
        }
    }

    #[test]
    fn malformed_ciphertexts_and_keys_are_rejected() {
        let (_, mpk) = &keys()[2];
        let mut rng = StdRng::from_seed([74u8; 32]);
        let ct = encrypt::<Sha256>(mpk, b"id", b"message", &mut rng).expect("encrypt");
        let bytes = ct.to_bytes();
        assert!(Ciphertext::from_bytes(&bytes[..8 * N - 1]).is_err());
        assert!(Ciphertext::from_bytes(&bytes[..4 * N]).is_err());
        assert!(Ciphertext::from_bytes(&[]).is_err());
        let mut out_of_range = bytes.clone();
        out_of_range[4 * N + 3] = 0xFF; // first coefficient of v ≥ q
        assert!(Ciphertext::from_bytes(&out_of_range).is_err());
        let mut u_out_of_range = bytes;
        u_out_of_range[7] = 0x20;
        assert!(Ciphertext::from_bytes(&u_out_of_range).is_err());

        let key = IdentitySecretKey::new(PolyQ::one());
        assert_eq!(
            IdentitySecretKey::from_bytes(&key.to_bytes()).expect("valid"),
            key
        );
        assert!(IdentitySecretKey::from_bytes(&[0u8; 4 * N - 4]).is_err());
        assert!(IdentitySecretKey::from_bytes(&[0xFFu8; 4 * N]).is_err());
    }

    #[test]
    fn helpers_match_their_definitions() {
        let mut rng = StdRng::from_seed([75u8; 32]);
        let x = ternary(&mut rng);
        assert_eq!(x.len(), N);
        assert!(x.iter().all(|c| (-1..=1).contains(c)));
        // Each value has probability 1/3: about 341 of each.
        for v in -1..=1 {
            let count = x.iter().filter(|&&c| c == v).count();
            assert!((250..440).contains(&count), "{v}: {count}");
        }
        assert_eq!(weight(&[0, 1, -1, 0, 1]), 3);
        assert_eq!(
            key_bits(&[0b1000_0101]).collect::<Vec<_>>(),
            [1, 0, 1, 0, 0, 0, 0, 1]
        );
        assert_eq!(xor(&[0xF0, 0x0F], &[0xFF, 0xFF]), [0x0F, 0xF0]);

        let mut c = std::vec![0u32; N];
        c[0] = (1 << 24) - 1; // rounds up
        c[1] = (1 << 23) - 1; // rounds down
        c[2] = 1 << 23; // half rounds up
        c[3] = Q - 1; // wraps to 0
        let rounded = round_low_bits(&PolyQ::from_coeffs(&c).expect("length N"));
        assert_eq!(&rounded.coeffs()[..4], &[1 << 24, 0, 1 << 24, 0]);
    }

    #[test]
    fn key_bit_matches_the_centered_definition_at_the_boundaries() {
        // The definition `decrypt` used before: center `w` into
        // `(−q/2, q/2]` with a branch and compare `|w| ≥ q/4`.
        let reference = |w: u32| {
            let w = i64::from(w);
            let half = i64::from(Q / 2);
            let centered = if w > half { w - i64::from(Q) } else { w };
            u8::from(centered.abs() >= i64::from(Q / 4))
        };
        let quarter = i64::from(Q / 4);
        let half = i64::from(Q / 2);
        let cases = [
            (quarter - 1, 0),
            (quarter, 1),
            (-quarter, 1),
            (-quarter + 1, 0),
            (0, 0),
            (half, 1),
            (-half, 1),
        ];
        for (centered, bit) in cases {
            let w = PolyQ::from_signed(&[centered; N])
                .expect("length N")
                .coeffs()[0];
            assert_eq!(key_bit(w).to_u8(), bit, "{centered}");
            assert_eq!(key_bit(w).to_u8(), reference(w), "{centered}");
        }
        for w in (0..Q).step_by(4093).chain([1, Q - 1, 3 * (Q / 4) + 1]) {
            assert_eq!(key_bit(w).to_u8(), reference(w), "{w}");
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn ibe_types_serde_round_trip() {
        use crate::tests::utils::assert_serde_round_trip;
        let (msk, mpk) = &keys()[3];
        let mut rng = StdRng::from_seed([76u8; 32]);
        assert_serde_round_trip(mpk);
        let key = extract::<Sha256>(msk, mpk, b"serde", &mut rng).expect("extract");
        assert_serde_round_trip(&key);
        let ct = encrypt::<Sha256>(mpk, b"serde", b"payload", &mut rng).expect("encrypt");
        assert_serde_round_trip(&ct);
    }

    #[test]
    fn ciphertext_u_survives_encoding_and_is_fresh_per_encryption() {
        let (_, mpk) = &keys()[0];
        let mut rng = StdRng::from_seed([76u8; 32]);
        let ct = encrypt::<Sha256>(mpk, b"id", b"message", &mut rng).expect("encrypt");
        let decoded = Ciphertext::from_bytes(&ct.to_bytes()).expect("decode");
        assert_eq!(decoded.u(), ct.u());
        let again = encrypt::<Sha256>(mpk, b"id", b"message", &mut rng).expect("encrypt");
        assert_ne!(again.u(), ct.u());
    }
}
