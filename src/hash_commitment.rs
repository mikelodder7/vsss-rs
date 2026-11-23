/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Hash commitments over any [`digest::Digest`].
//!
//! A commitment to `message` under a domain tag is
//!
//! ```text
//! H(len(domain) ‖ domain ‖ len(message) ‖ message ‖ randomness)
//! ```
//!
//! where each length is a `u64` in little-endian order. The length prefixes
//! make the encoding unambiguous for any inputs, so no two different
//! `(domain, message)` pairs hash the same bytes.
//!
//! - **Hiding** holds when the randomness is uniform and at least 256 bits
//!   long. [`HashCommitment::commit`] samples a fresh [`HashOpening`] of
//!   that size. [`HashCommitment::commit_with_randomness`] is for schemes
//!   that derive their randomness, such as from a field element, and the
//!   caller must make sure it meets the same bar.
//! - **Binding** rests on the collision resistance of `H`. Use a digest of
//!   at least 256 bits, such as SHA-256, SHA3-256, BLAKE2, or BLAKE3.
//!
//! Both properties rely only on the hash, so the scheme is post-quantum.
//! The commitments are not homomorphic.
use crate::*;
use digest::Digest;
use rand_core::CryptoRng;

/// Bytes of randomness in a [`HashOpening`] (`λ = 256` bits).
pub const HASH_OPENING_BYTES: usize = 32;

/// A hash commitment: the opaque digest of a domain tag, a message, and
/// randomness.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "Vec<u8>"))]
pub struct HashCommitment(Vec<u8>);

/// The random opening of a [`HashCommitment`] made by
/// [`HashCommitment::commit`]. Keep it secret until the commitment is
/// opened.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct HashOpening([u8; HASH_OPENING_BYTES]);

impl HashCommitment {
    /// Commit to `message` under `domain` with fresh randomness from `rng`.
    /// Returns the commitment and the opening that verifies it.
    pub fn commit<D: Digest>(
        domain: &[u8],
        message: &[u8],
        mut rng: impl CryptoRng,
    ) -> (Self, HashOpening) {
        let mut opening = HashOpening([0u8; HASH_OPENING_BYTES]);
        rng.fill_bytes(&mut opening.0);
        (
            Self::commit_with_randomness::<D>(domain, message, &opening.0),
            opening,
        )
    }

    /// Commit to `message` under `domain` with caller-supplied
    /// `randomness`, for schemes that derive it. Hiding needs `randomness`
    /// to be uniform and at least 256 bits long.
    pub fn commit_with_randomness<D: Digest>(
        domain: &[u8],
        message: &[u8],
        randomness: &[u8],
    ) -> Self {
        Self::commit_parts::<D>(domain, &[message], randomness)
    }

    /// Commit to the message `parts[0] ‖ parts[1] ‖ …` without building it:
    /// the bytes hashed are exactly those of [`Self::commit_with_randomness`]
    /// on the concatenation, so secret parts are never copied into a buffer.
    pub(crate) fn commit_parts<D: Digest>(
        domain: &[u8],
        parts: &[&[u8]],
        randomness: &[u8],
    ) -> Self {
        let message_len: usize = parts.iter().map(|p| p.len()).sum();
        let hasher = D::new()
            .chain_update((domain.len() as u64).to_le_bytes())
            .chain_update(domain)
            .chain_update((message_len as u64).to_le_bytes());
        Self(
            parts
                .iter()
                .fold(hasher, |h, part| h.chain_update(part))
                .chain_update(randomness)
                .finalize()
                .to_vec(),
        )
    }

    /// Check that this commits to `message` under `domain` with `opening`.
    /// Fails with [`Error::InvalidShare`] on any mismatch.
    pub fn verify<D: Digest>(
        &self,
        domain: &[u8],
        message: &[u8],
        opening: &HashOpening,
    ) -> VsssResult<()> {
        self.verify_with_randomness::<D>(domain, message, &opening.0)
    }

    /// Check that this commits to `message` under `domain` with
    /// `randomness`, in constant time. Fails with [`Error::InvalidShare`]
    /// on any mismatch, including a digest of the wrong length.
    pub fn verify_with_randomness<D: Digest>(
        &self,
        domain: &[u8],
        message: &[u8],
        randomness: &[u8],
    ) -> VsssResult<()> {
        self.verify_parts::<D>(domain, &[message], randomness)
    }

    /// Check, in constant time, that this is [`Self::commit_parts`] of
    /// `parts` under `domain` with `randomness`. Fails with
    /// [`Error::InvalidShare`] on any mismatch.
    pub(crate) fn verify_parts<D: Digest>(
        &self,
        domain: &[u8],
        parts: &[&[u8]],
        randomness: &[u8],
    ) -> VsssResult<()> {
        let expected = Self::commit_parts::<D>(domain, parts, randomness);
        if bool::from(expected.0.as_slice().ct_eq(self.0.as_slice())) {
            Ok(())
        } else {
            Err(Error::InvalidShare)
        }
    }

    /// The digest bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Read a commitment from its digest bytes. Fails with
    /// [`Error::InvalidShare`] on empty input.
    pub fn from_bytes(bytes: &[u8]) -> VsssResult<Self> {
        Self::try_from(bytes.to_vec())
    }
}

impl TryFrom<Vec<u8>> for HashCommitment {
    type Error = Error;

    /// Take ownership of digest bytes. Fails with [`Error::InvalidShare`]
    /// on empty input.
    fn try_from(bytes: Vec<u8>) -> VsssResult<Self> {
        if bytes.is_empty() {
            Err(Error::InvalidShare)
        } else {
            Ok(Self(bytes))
        }
    }
}

impl HashOpening {
    /// Wrap `bytes` received from the committer.
    pub fn from_bytes(bytes: [u8; HASH_OPENING_BYTES]) -> Self {
        Self(bytes)
    }

    /// The randomness bytes, for sending to a verifier.
    pub fn as_bytes(&self) -> &[u8; HASH_OPENING_BYTES] {
        &self.0
    }
}

impl ConstantTimeEq for HashOpening {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for HashOpening {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for HashOpening {}

impl Debug for HashOpening {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HashOpening(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use sha2::{Sha256, Sha512};
    use std::format;

    const DOMAIN: &[u8] = b"vsss-rs-hash-commitment-test";
    const MESSAGE: &[u8] = b"attack at dawn";

    fn rng() -> ChaCha8Rng {
        ChaCha8Rng::from_seed([1; 32])
    }

    #[test]
    fn commit_then_verify_succeeds_with_sha256() {
        let (c, o) = HashCommitment::commit::<Sha256>(DOMAIN, MESSAGE, rng());
        assert_eq!(c.as_bytes().len(), 32);
        assert_eq!(c.verify::<Sha256>(DOMAIN, MESSAGE, &o), Ok(()));
        assert_eq!(
            c.verify_with_randomness::<Sha256>(DOMAIN, MESSAGE, o.as_bytes()),
            Ok(())
        );
    }

    #[cfg(feature = "random-participant-ids")]
    #[test]
    fn commit_then_verify_succeeds_with_sha3_256() {
        let (c, o) = HashCommitment::commit::<sha3::Sha3_256>(DOMAIN, MESSAGE, rng());
        assert_eq!(c.verify::<sha3::Sha3_256>(DOMAIN, MESSAGE, &o), Ok(()));
        // Same digest length, different hash.
        assert_eq!(
            c.verify::<Sha256>(DOMAIN, MESSAGE, &o),
            Err(Error::InvalidShare)
        );
    }

    #[test]
    fn mismatches_are_rejected() {
        let (c, o) = HashCommitment::commit::<Sha256>(DOMAIN, MESSAGE, rng());
        let bad = Err(Error::InvalidShare);
        assert_eq!(c.verify::<Sha256>(DOMAIN, b"attack at dusk", &o), bad);
        assert_eq!(c.verify::<Sha256>(b"other-domain", MESSAGE, &o), bad);
        let mut other = *o.as_bytes();
        other[0] ^= 1;
        let wrong = HashOpening::from_bytes(other);
        assert_eq!(c.verify::<Sha256>(DOMAIN, MESSAGE, &wrong), bad);
        assert_eq!(c.verify::<Sha512>(DOMAIN, MESSAGE, &o), bad);
        let bytes = c.as_bytes();
        let truncated = HashCommitment::from_bytes(&bytes[..bytes.len() - 1]).unwrap();
        assert_eq!(truncated.verify::<Sha256>(DOMAIN, MESSAGE, &o), bad);
    }

    #[test]
    fn commitments_to_the_same_message_differ() {
        let mut rng = rng();
        let (a, oa) = HashCommitment::commit::<Sha256>(DOMAIN, MESSAGE, &mut rng);
        let (b, ob) = HashCommitment::commit::<Sha256>(DOMAIN, MESSAGE, &mut rng);
        assert_ne!(a, b);
        assert_ne!(oa, ob);
    }

    #[test]
    fn length_prefixes_prevent_splicing() {
        let r = [7u8; HASH_OPENING_BYTES];
        let left = HashCommitment::commit_with_randomness::<Sha256>(b"ab", b"c", &r);
        let right = HashCommitment::commit_with_randomness::<Sha256>(b"a", b"bc", &r);
        assert_ne!(left, right);
        // The message length also separates message bytes from randomness.
        let short = HashCommitment::commit_with_randomness::<Sha256>(DOMAIN, b"x", b"yz");
        let long = HashCommitment::commit_with_randomness::<Sha256>(DOMAIN, b"xy", b"z");
        assert_ne!(short, long);
    }

    #[test]
    fn commit_with_randomness_matches_the_definition() {
        let expected = Sha256::new()
            .chain_update(2u64.to_le_bytes())
            .chain_update(b"dt")
            .chain_update(3u64.to_le_bytes())
            .chain_update(b"msg")
            .chain_update(b"rnd")
            .finalize();
        let c = HashCommitment::commit_with_randomness::<Sha256>(b"dt", b"msg", b"rnd");
        assert_eq!(c.as_bytes(), expected.as_slice());
        assert_eq!(
            c.verify_with_randomness::<Sha256>(b"dt", b"msg", b"rnd"),
            Ok(())
        );
        assert_eq!(
            c.verify_with_randomness::<Sha256>(b"dt", b"msg", b"rne"),
            Err(Error::InvalidShare)
        );
    }

    #[test]
    fn parts_hash_like_their_concatenation() {
        let whole = HashCommitment::commit_with_randomness::<Sha256>(b"dt", b"message", b"rnd");
        let parts = HashCommitment::commit_parts::<Sha256>(b"dt", &[b"mes", b"", b"sage"], b"rnd");
        assert_eq!(parts, whole);
        assert_eq!(
            whole.verify_parts::<Sha256>(b"dt", &[b"me", b"ssage"], b"rnd"),
            Ok(())
        );
        assert_eq!(
            whole.verify_parts::<Sha256>(b"dt", &[b"me", b"ssagE"], b"rnd"),
            Err(Error::InvalidShare)
        );
    }

    #[test]
    fn from_bytes_rejects_empty_input() {
        assert_eq!(HashCommitment::from_bytes(&[]), Err(Error::InvalidShare));
        assert_eq!(
            HashCommitment::try_from(Vec::new()),
            Err(Error::InvalidShare)
        );
        let c = HashCommitment::from_bytes(&[1, 2, 3]).unwrap();
        assert_eq!(c.as_bytes(), &[1, 2, 3]);
        assert_eq!(HashCommitment::try_from(std::vec![1, 2, 3]), Ok(c));
    }

    #[test]
    fn opening_bytes_round_trip_and_debug_is_redacted() {
        let o = HashOpening::from_bytes([0xAB; HASH_OPENING_BYTES]);
        assert_eq!(o.as_bytes(), &[0xAB; HASH_OPENING_BYTES]);
        assert_eq!(format!("{o:?}"), "HashOpening(<redacted>)");
        assert!(bool::from(o.ct_eq(&o.clone())));
        assert!(!bool::from(
            o.ct_eq(&HashOpening::from_bytes([0; HASH_OPENING_BYTES]))
        ));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trips() {
        use crate::tests::utils::assert_serde_round_trip;
        let (c, o) = HashCommitment::commit::<Sha256>(DOMAIN, MESSAGE, rng());
        assert_serde_round_trip(&c);
        assert_serde_round_trip(&o);
        // Deserialization enforces the same invariant as `from_bytes`.
        assert!(serde_json::from_str::<HashCommitment>("[]").is_err());
    }
}
