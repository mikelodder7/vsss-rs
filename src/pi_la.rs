/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Π_LA hash-based verifiable secret sharing.
//!
//! A post-quantum alternative to [`Feldman`] and
//! [`Pedersen`]. It needs only Shamir sharing over a prime
//! field and a collision-resistant hash, so its security does not rest on
//! discrete logarithms. See Baghery, "Π: A Unified Framework for
//! Computational Verifiable Secret Sharing", PKC 2025,
//! <https://eprint.iacr.org/2023/1669>.
//!
//! The dealer shares the secret with a polynomial `f`, samples a masking
//! polynomial `r` of the same degree, and publishes:
//!
//! - one hash commitment `c_i = H(id_i ‖ f(id_i) ‖ r(id_i))` per participant,
//! - the polynomial `z = r + d·f`, where the challenge `d` is a hash of every
//!   commitment.
//!
//! A participant holding `f(id_i)` checks that `z` has the agreed degree and
//! that `H(id_i ‖ f(id_i) ‖ z(id_i) − d·f(id_i))` equals `c_i`.
//!
//! The hash is any [`digest::Digest`], such as SHA-2, SHA-3, BLAKE2, or BLAKE3
//! (with its `traits-preview` feature). Pick an output of at least 256 bits.
//!
//! Limits the caller must handle:
//!
//! - Shares must travel over private channels that are themselves
//!   post-quantum (for example ML-KEM) for the whole flow to be post-quantum.
//! - The scheme assumes an honest majority, `limit >= 2 * threshold - 1`, and
//!   a broadcast channel for the proof. Complaint rounds are left to the
//!   application, as with Feldman.
//! - The commitments are not homomorphic, so this cannot replace Feldman in
//!   protocols that add commitments together, such as most DKGs.
use crate::*;
use digest::Digest;
use elliptic_curve::PrimeField;
use rand_core::CryptoRng;

/// Domain separator for per-participant commitments.
const COMMITMENT_DST: &[u8] = b"vsss-rs-pi-la-v1-commitment";
/// Domain separator for the challenge transcript.
const CHALLENGE_DST: &[u8] = b"vsss-rs-pi-la-v1-challenge";
/// Domain separator for expanding the transcript into a field element.
const EXPAND_DST: &[u8] = b"vsss-rs-pi-la-v1-expand";
/// Attempts before challenge sampling gives up. Each attempt succeeds with
/// probability at least 1/2, so failure is below 2^-128.
const MAX_CHALLENGE_ATTEMPTS: u32 = 128;

/// One participant's hash commitment in a [`PiLaProof`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "IdentifierPrimeField<F>: serde::Serialize",
        deserialize = "IdentifierPrimeField<F>: serde::Deserialize<'de>"
    ))
)]
pub struct PiLaCommitment<F: PrimeField> {
    /// The participant identifier the commitment belongs to.
    pub identifier: IdentifierPrimeField<F>,
    /// The digest `H(id ‖ f(id) ‖ r(id))`.
    pub digest: Vec<u8>,
}

/// The public proof a dealer broadcasts alongside the shares.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "IdentifierPrimeField<F>: serde::Serialize",
        deserialize = "IdentifierPrimeField<F>: serde::Deserialize<'de>"
    ))
)]
pub struct PiLaProof<F: PrimeField> {
    /// One commitment per participant, in dealing order.
    pub commitments: Vec<PiLaCommitment<F>>,
    /// Coefficients of `z = r + d·f`, constant term first.
    pub z: Vec<IdentifierPrimeField<F>>,
}

/// Shares and the proof that lets each participant verify its own share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiLaResult<S, F: PrimeField> {
    /// One share per participant, in the same order as the commitments.
    pub shares: Vec<S>,
    /// The public proof.
    pub proof: PiLaProof<F>,
}

/// Split `secret` into `limit` shares with sequential identifiers `1..=limit`
/// and build the Π_LA proof using hash `D`.
pub fn split_secret<D, S, F>(
    threshold: usize,
    limit: usize,
    secret: &IdentifierPrimeField<F>,
    rng: impl CryptoRng,
) -> VsssResult<PiLaResult<S, F>>
where
    D: Digest,
    F: PrimeField,
    S: Share<Identifier = IdentifierPrimeField<F>, Value = IdentifierPrimeField<F>>,
{
    let mut id = IdentifierPrimeField::<F>::zero();
    let one = IdentifierPrimeField::<F>::one();
    let ids = (0..limit).map(|_| {
        id.inc(&one);
        id
    });
    split_secret_with_participant_ids::<D, S, F>(threshold, secret, rng, ids)
}

/// Split `secret` into one share per identifier in `participant_ids` and
/// build the Π_LA proof using hash `D`.
///
/// Identifiers must be non-zero and distinct.
pub fn split_secret_with_participant_ids<D, S, F>(
    threshold: usize,
    secret: &IdentifierPrimeField<F>,
    mut rng: impl CryptoRng,
    participant_ids: impl IntoIterator<Item = IdentifierPrimeField<F>>,
) -> VsssResult<PiLaResult<S, F>>
where
    D: Digest,
    F: PrimeField,
    S: Share<Identifier = IdentifierPrimeField<F>, Value = IdentifierPrimeField<F>>,
{
    let ids: Vec<IdentifierPrimeField<F>> = participant_ids.into_iter().collect();
    check_params(threshold, ids.len())?;
    validate_identifiers(ids.iter())?;

    // Both polynomials reveal the secret: `f` directly, and `r` through
    // `z = r + d·f`. Keep them in guards that wipe them on every exit.
    let mut f = ZeroizingPolynomial::<S, Vec<S>>::create(threshold);
    f.fill(secret, &mut rng, threshold)?;
    let mask = IdentifierPrimeField::<F>::random(&mut rng);
    let mut r = ZeroizingPolynomial::<S, Vec<S>>::create(threshold);
    r.fill(&mask, &mut rng, threshold)?;

    let mut shares = Vec::with_capacity(ids.len());
    let mut commitments = Vec::with_capacity(ids.len());
    for id in ids {
        let f_i = f.evaluate(&id, threshold);
        let r_i = r.evaluate(&id, threshold);
        commitments.push(PiLaCommitment {
            identifier: id,
            digest: commit::<D, F>(&id, &f_i, &r_i),
        });
        shares.push(S::with_identifier_and_value(id, f_i));
    }

    let d = challenge::<D, F>(threshold, &commitments)?;
    let z = f
        .coefficients()
        .iter()
        .zip(r.coefficients())
        .enumerate()
        .map(|(k, (f_k, r_k))| {
            IdentifierPrimeField(coefficient(r_k, k).0 + d.0 * coefficient(f_k, k).0)
        })
        .collect();

    Ok(PiLaResult {
        shares,
        proof: PiLaProof { commitments, z },
    })
}

impl<F: PrimeField> PiLaProof<F> {
    /// Check `share` against this proof using hash `D`.
    ///
    /// `threshold` is the number of shares the caller expects to need for
    /// reconstruction. It must come from the caller, not the proof, or a
    /// dealer could hide a higher-degree polynomial.
    pub fn verify_share<D, S>(&self, threshold: usize, share: &S) -> VsssResult<()>
    where
        D: Digest,
        S: Share<Identifier = IdentifierPrimeField<F>, Value = IdentifierPrimeField<F>>,
    {
        check_params(threshold, self.commitments.len())?;
        if self.z.len() != threshold {
            return Err(Error::InvalidShare);
        }
        let digest_len = <D as Digest>::output_size();
        if self
            .commitments
            .iter()
            .any(|c| c.digest.len() != digest_len)
        {
            return Err(Error::InvalidShare);
        }
        validate_identifiers(self.commitments.iter().map(|c| &c.identifier))?;
        let commitment = self
            .commitments
            .iter()
            .find(|c| c.identifier == *share.identifier())
            .ok_or(Error::SharingInvalidIdentifier)?;

        let d = challenge::<D, F>(threshold, &self.commitments)?;
        let f_i = share.value();
        let r_i = IdentifierPrimeField(evaluate(&self.z, share.identifier()) - d.0 * f_i.0);
        let expected = commit::<D, F>(share.identifier(), f_i, &r_i);
        if bool::from(expected.as_slice().ct_eq(commitment.digest.as_slice())) {
            Ok(())
        } else {
            Err(Error::InvalidShare)
        }
    }
}

/// The `k`-th coefficient of a polynomial stored the crate's way: the
/// constant term in the value, every other coefficient in the identifier.
fn coefficient<S, F>(share: &S, k: usize) -> &IdentifierPrimeField<F>
where
    F: PrimeField,
    S: Share<Identifier = IdentifierPrimeField<F>, Value = IdentifierPrimeField<F>>,
{
    if k == 0 {
        share.value()
    } else {
        share.identifier()
    }
}

/// Evaluate `z` at `x` with Horner's method.
fn evaluate<F: PrimeField>(z: &[IdentifierPrimeField<F>], x: &IdentifierPrimeField<F>) -> F {
    z.iter().rev().fold(F::ZERO, |acc, c| acc * x.0 + c.0)
}

/// Reject zero identifiers, which would expose the secret, and duplicates.
fn validate_identifiers<'a, F: PrimeField + 'a>(
    ids: impl Iterator<Item = &'a IdentifierPrimeField<F>> + Clone,
) -> VsssResult<()> {
    for (i, id) in ids.clone().enumerate() {
        if bool::from(id.is_zero()) {
            return Err(Error::SharingInvalidIdentifier);
        }
        if ids.clone().skip(i + 1).any(|other| other == id) {
            return Err(Error::SharingDuplicateIdentifier);
        }
    }
    Ok(())
}

/// `H(DST ‖ id ‖ f(id) ‖ r(id))`.
fn commit<D: Digest, F: PrimeField>(
    id: &IdentifierPrimeField<F>,
    f_i: &IdentifierPrimeField<F>,
    r_i: &IdentifierPrimeField<F>,
) -> Vec<u8> {
    D::new()
        .chain_update(COMMITMENT_DST)
        .chain_update(id.0.to_repr())
        .chain_update(f_i.0.to_repr())
        .chain_update(r_i.0.to_repr())
        .finalize()
        .to_vec()
}

/// Derive the non-zero challenge `d` from the threshold and every
/// commitment, by rejection sampling into `F`.
fn challenge<D: Digest, F: PrimeField>(
    threshold: usize,
    commitments: &[PiLaCommitment<F>],
) -> VsssResult<IdentifierPrimeField<F>> {
    let transcript = commitments
        .iter()
        .fold(
            D::new()
                .chain_update(CHALLENGE_DST)
                .chain_update((threshold as u64).to_le_bytes())
                .chain_update((commitments.len() as u64).to_le_bytes()),
            |h, c| {
                h.chain_update(c.identifier.0.to_repr())
                    .chain_update(&c.digest)
            },
        )
        .finalize();

    for attempt in 0..MAX_CHALLENGE_ATTEMPTS {
        let mut repr = F::Repr::default();
        expand::<D>(&transcript, attempt, repr.as_mut());
        clear_excess_bits::<F>(repr.as_mut());
        let candidate = Option::<F>::from(F::from_repr(repr));
        if let Some(d) = candidate.filter(|d| !bool::from(d.is_zero())) {
            return Ok(IdentifierPrimeField(d));
        }
    }
    Err(Error::InvalidShare)
}

/// Fill `out` with `H(DST ‖ transcript ‖ attempt ‖ block)` for block 0, 1, …
fn expand<D: Digest>(transcript: &[u8], attempt: u32, out: &mut [u8]) {
    let block_len = <D as Digest>::output_size();
    for (block, chunk) in out.chunks_mut(block_len).enumerate() {
        let bytes = D::new()
            .chain_update(EXPAND_DST)
            .chain_update(transcript)
            .chain_update(attempt.to_le_bytes())
            .chain_update((block as u32).to_le_bytes())
            .finalize();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}

/// Zero the bits of `repr` above `F::NUM_BITS`, so each sample is accepted
/// with probability at least 1/2. The byte order is read from `F::ONE`.
fn clear_excess_bits<F: PrimeField>(repr: &mut [u8]) {
    let one = F::ONE.to_repr();
    let little_endian = match (one.as_ref().first(), one.as_ref().last()) {
        (Some(1), _) => true,
        (_, Some(1)) => false,
        _ => return,
    };
    let mut excess = (repr.len() * 8).saturating_sub(F::NUM_BITS as usize);
    let len = repr.len();
    for i in 0..len {
        if excess == 0 {
            break;
        }
        let bits = excess.min(8);
        let byte = if little_endian { len - 1 - i } else { i };
        repr[byte] &= 0xFFu8.checked_shr(bits as u32).unwrap_or(0);
        excess -= bits;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use sha2::Sha256;

    type K256Share = PrimeFieldShare<k256::Scalar>;

    fn deal(
        seed: u8,
    ) -> (
        IdentifierPrimeField<k256::Scalar>,
        PiLaResult<K256Share, k256::Scalar>,
    ) {
        let mut rng = ChaCha8Rng::from_seed([seed; 32]);
        let secret = IdentifierPrimeField(k256::Scalar::from(0x0102_0304_0506_0708u64));
        let result = split_secret::<Sha256, K256Share, _>(3, 5, &secret, &mut rng).unwrap();
        (secret, result)
    }

    #[test]
    fn honest_dealer_shares_all_verify_and_reconstruct() {
        let (secret, result) = deal(1);
        assert_eq!(result.shares.len(), 5);
        assert_eq!(result.proof.z.len(), 3);
        for share in &result.shares {
            assert_eq!(result.proof.verify_share::<Sha256, _>(3, share), Ok(()));
        }
        assert_eq!((&result.shares[1..4]).combine(), Ok(secret));
    }

    #[cfg(feature = "random-participant-ids")]
    #[test]
    fn works_with_sha3() {
        let mut rng = ChaCha8Rng::from_seed([2; 32]);
        let secret = IdentifierPrimeField(k256::Scalar::from(7u64));
        let result = split_secret::<sha3::Sha3_256, K256Share, _>(2, 3, &secret, &mut rng).unwrap();
        for share in &result.shares {
            assert_eq!(
                result.proof.verify_share::<sha3::Sha3_256, _>(2, share),
                Ok(())
            );
        }
        // A proof built with one hash does not verify under another.
        assert_eq!(
            result.proof.verify_share::<Sha256, _>(2, &result.shares[0]),
            Err(Error::InvalidShare)
        );
    }

    #[test]
    fn works_across_curves() {
        type Dalek = PrimeFieldShare<curve25519_dalek::Scalar>;
        let mut rng = ChaCha8Rng::from_seed([3; 32]);
        let secret = IdentifierPrimeField::<curve25519_dalek::Scalar>::random(&mut rng);
        let result = split_secret::<Sha256, Dalek, _>(3, 5, &secret, &mut rng).unwrap();
        for share in &result.shares {
            assert_eq!(result.proof.verify_share::<Sha256, _>(3, share), Ok(()));
        }
        assert_eq!((&result.shares[..3]).combine(), Ok(secret));

        type Bls = PrimeFieldShare<bls12_381_plus::Scalar>;
        let secret = IdentifierPrimeField::<bls12_381_plus::Scalar>::random(&mut rng);
        let result = split_secret::<sha2::Sha512, Bls, _>(4, 7, &secret, &mut rng).unwrap();
        for share in &result.shares {
            assert_eq!(
                result.proof.verify_share::<sha2::Sha512, _>(4, share),
                Ok(())
            );
        }
    }

    #[test]
    fn tampered_share_value_is_rejected() {
        let (_, result) = deal(4);
        let mut share = result.shares[0];
        share.value_mut().0 += k256::Scalar::ONE;
        assert_eq!(
            result.proof.verify_share::<Sha256, _>(3, &share),
            Err(Error::InvalidShare)
        );
    }

    #[test]
    fn tampered_commitment_is_rejected() {
        let (_, mut result) = deal(5);
        result.proof.commitments[2].digest[0] ^= 1;
        // Every share fails: the challenge binds all commitments.
        for share in &result.shares {
            assert_eq!(
                result.proof.verify_share::<Sha256, _>(3, share),
                Err(Error::InvalidShare)
            );
        }
    }

    #[test]
    fn tampered_z_is_rejected() {
        let (_, mut result) = deal(6);
        result.proof.z[1].0 += k256::Scalar::ONE;
        assert_eq!(
            result.proof.verify_share::<Sha256, _>(3, &result.shares[0]),
            Err(Error::InvalidShare)
        );
    }

    #[test]
    fn wrong_degree_is_rejected() {
        let (_, result) = deal(7);
        // The verifier expects threshold 2, the dealer used 3.
        assert_eq!(
            result.proof.verify_share::<Sha256, _>(2, &result.shares[0]),
            Err(Error::InvalidShare)
        );
        let mut longer = result.proof.clone();
        longer.z.push(IdentifierPrimeField::zero());
        assert_eq!(
            longer.verify_share::<Sha256, _>(3, &result.shares[0]),
            Err(Error::InvalidShare)
        );
    }

    #[test]
    fn unknown_and_bad_identifiers_are_rejected() {
        let (_, result) = deal(8);
        let stranger = K256Share::with_identifier_and_value(
            IdentifierPrimeField(k256::Scalar::from(99u64)),
            IdentifierPrimeField::one(),
        );
        assert_eq!(
            result.proof.verify_share::<Sha256, _>(3, &stranger),
            Err(Error::SharingInvalidIdentifier)
        );

        let mut duplicated = result.proof.clone();
        duplicated.commitments[1].identifier = duplicated.commitments[0].identifier;
        assert_eq!(
            duplicated.verify_share::<Sha256, _>(3, &result.shares[0]),
            Err(Error::SharingDuplicateIdentifier)
        );

        let mut short = result.proof.clone();
        short.commitments[0].digest.pop();
        assert_eq!(
            short.verify_share::<Sha256, _>(3, &result.shares[0]),
            Err(Error::InvalidShare)
        );
    }

    #[test]
    fn dealing_rejects_bad_identifiers_and_params() {
        let mut rng = ChaCha8Rng::from_seed([9; 32]);
        let secret = IdentifierPrimeField(k256::Scalar::from(5u64));
        let id = |n: u64| IdentifierPrimeField(k256::Scalar::from(n));

        let zero = split_secret_with_participant_ids::<Sha256, K256Share, _>(
            2,
            &secret,
            &mut rng,
            [id(0), id(1), id(2)],
        );
        assert_eq!(zero, Err(Error::SharingInvalidIdentifier));

        let dup = split_secret_with_participant_ids::<Sha256, K256Share, _>(
            2,
            &secret,
            &mut rng,
            [id(1), id(1), id(2)],
        );
        assert_eq!(dup, Err(Error::SharingDuplicateIdentifier));

        assert_eq!(
            split_secret::<Sha256, K256Share, _>(1, 3, &secret, &mut rng),
            Err(Error::SharingMinThreshold)
        );
        assert_eq!(
            split_secret::<Sha256, K256Share, _>(4, 3, &secret, &mut rng),
            Err(Error::SharingLimitLessThanThreshold)
        );
    }

    #[test]
    fn challenge_binds_identifiers_and_threshold() {
        let (_, result) = deal(10);
        let d = challenge::<Sha256, _>(3, &result.proof.commitments).unwrap();
        assert_ne!(
            challenge::<Sha256, _>(4, &result.proof.commitments).unwrap(),
            d
        );
        let mut renamed = result.proof.commitments.clone();
        renamed[0].identifier = IdentifierPrimeField(k256::Scalar::from(42u64));
        assert_ne!(challenge::<Sha256, _>(3, &renamed).unwrap(), d);
    }

    #[test]
    fn clear_excess_bits_handles_both_byte_orders() {
        // k256 is big-endian with 256 bits: nothing to clear.
        let mut be = [0xFFu8; 32];
        clear_excess_bits::<k256::Scalar>(&mut be);
        assert_eq!(be, [0xFF; 32]);

        // BLS12-381 is little-endian with 255 bits: clear the top bit.
        let mut le = [0xFFu8; 32];
        clear_excess_bits::<bls12_381_plus::Scalar>(&mut le);
        assert_eq!(le[31], 0x7F);
        assert!(le[..31].iter().all(|b| *b == 0xFF));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn proof_serde_round_trips() {
        let (_, result) = deal(11);
        let proof = result.proof;

        let json = serde_json::to_string(&proof).unwrap();
        assert_eq!(serde_json::from_str::<PiLaProof<_>>(&json).unwrap(), proof);

        let bytes = postcard::to_stdvec(&proof).unwrap();
        assert_eq!(postcard::from_bytes::<PiLaProof<_>>(&bytes).unwrap(), proof);

        let mut cbor = Vec::new();
        ciborium::into_writer(&proof, &mut cbor).unwrap();
        assert_eq!(
            ciborium::from_reader::<PiLaProof<_>, _>(cbor.as_slice()).unwrap(),
            proof
        );

        let bare = serde_bare::to_vec(&proof).unwrap();
        assert_eq!(
            serde_bare::from_slice::<PiLaProof<_>>(&bare).unwrap(),
            proof
        );
    }
}
