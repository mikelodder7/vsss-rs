/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Post-quantum publicly verifiable secret sharing (Sec. 5 of ePrint
//! 2026/813).
//!
//! **Experimental and unaudited. Not constant-time.** Soundness rests on
//! hash commitments in the random-oracle model and the lattice IBE of this
//! module's parent, whose concrete parameters give about 110 bits of
//! classical security. The share field must have more than `2^128` elements
//! (`F::NUM_BITS ≥ 129`) for the `Q_H / |F|` soundness term; smaller fields
//! are rejected. The scheme assumes a static adversary corrupting fewer than
//! half of the receivers, `threshold − 1 < n / 2`, which the caller must
//! choose.
//!
//! Roles and the paper's names (`threshold` is the crate's convention, the
//! number of shares needed, so the paper's degree is `t = threshold − 1`):
//!
//! - **Setup**: every receiver runs [`keygen`](super::keygen) and posts its
//!   [`MasterPublicKey`]. Receiver `i` (1-based) owns slot `i`.
//! - **Share**: [`share`] Shamir-shares `s` with `f`, shares a random value
//!   with `r`, commits `csh_i = H(⟦s⟧_i, ⟦r⟧_i)` and
//!   `cpt_i = H(B(i), q_i)` for a random padding polynomial `B` and random
//!   `q_i`, derives `ch = H({csh_i, cpt_i})`, publishes `W = B − ch·f`, and
//!   encrypts `(⟦s⟧_i, ⟦r⟧_i, q_i)` to identity `(dealer, i)`.
//! - **Decrypt**: receiver `i` runs [`decrypt`], which extracts its identity
//!   key, decrypts, and checks both commitments. On failure it returns a
//!   [`Complaint`] carrying the identity key.
//! - **PubVer**: anyone runs [`verify`] to check the degree of `W` and
//!   adjudicate complaints.
//! - **Recon**: [`reconstruct`] discards openings that fail the commitment
//!   checks and interpolates `s` from `threshold` good ones.
//!
//! Every hash is domain separated and binds the receiver index.
use super::{
    Ciphertext, IdentitySecretKey, MasterPublicKey, MasterSecretKey, decrypt as ibe_decrypt,
    encrypt, extract, hash::expand, lattice_error, verify_key, wipe,
};
use crate::pi_la::{coefficient, evaluate};
use crate::*;
use digest::Digest;
use elliptic_curve::PrimeField;
use rand_core::CryptoRng;
use std::collections::BTreeSet;

/// Domain separator for receiver identities `(dealer, i)`.
const IDENTITY_DST: &[u8] = b"vsss-rs-lattice-pvss-v1-identity";
/// Domain separator for the share commitments `csh_i`.
const SHARE_COMMITMENT_DST: &[u8] = b"vsss-rs-lattice-pvss-v1-share-commitment";
/// Domain separator for the padding commitments `cpt_i`.
const PADDING_COMMITMENT_DST: &[u8] = b"vsss-rs-lattice-pvss-v1-padding-commitment";
/// Domain separator for the challenge transcript.
const CHALLENGE_DST: &[u8] = b"vsss-rs-lattice-pvss-v1-challenge";
/// Domain separator for expanding the transcript into a field element.
const CHALLENGE_EXPAND_DST: &[u8] = b"vsss-rs-lattice-pvss-v1-challenge-expand";
/// Bytes of the random padding `q_i` (`λ = 256` bits).
pub const PAD_BYTES: usize = 32;
/// Smallest accepted `F::NUM_BITS`: a 129-bit modulus exceeds `2^128`.
pub const MIN_FIELD_BITS: u32 = 129;
/// Extra bytes of hash output when reducing the challenge into the field,
/// so its bias is below `2^-128`.
const CHALLENGE_EXTRA_BYTES: usize = 16;

/// The two hash commitments a dealer posts for one receiver.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PvssCommitment {
    /// `csh_i = H(i ‖ ⟦s⟧_i ‖ ⟦r⟧_i)`.
    pub share: Vec<u8>,
    /// `cpt_i = H(i ‖ B(i) ‖ q_i)`.
    pub padding: Vec<u8>,
}

/// The public proof `π = (W, {csh_i, cpt_i})`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "IdentifierPrimeField<F>: serde::Serialize",
        deserialize = "IdentifierPrimeField<F>: serde::Deserialize<'de>"
    ))
)]
pub struct PvssProof<F: PrimeField> {
    /// Coefficients of `W = B − ch·f`, constant term first.
    pub w: Vec<IdentifierPrimeField<F>>,
    /// One pair of commitments per receiver, receiver 1 first.
    pub commitments: Vec<PvssCommitment>,
}

/// Everything a dealer posts: the encrypted shares and the proof.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "IdentifierPrimeField<F>: serde::Serialize",
        deserialize = "IdentifierPrimeField<F>: serde::Deserialize<'de>"
    ))
)]
pub struct PvssDeal<F: PrimeField> {
    /// The dealer's identifier, part of every receiver identity.
    pub dealer: Vec<u8>,
    /// `E_i`, the encrypted opening of receiver `i`, receiver 1 first.
    pub ciphertexts: Vec<Ciphertext>,
    /// The proof `π`.
    pub proof: PvssProof<F>,
}

/// What receiver `i` decrypts: `(⟦s⟧_i, ⟦r⟧_i, q_i)`. Reconstruction takes
/// these.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "IdentifierPrimeField<F>: serde::Serialize",
        deserialize = "IdentifierPrimeField<F>: serde::Deserialize<'de>"
    ))
)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct PvssOpening<F: PrimeField> {
    /// The receiver index `i`, starting at 1.
    pub index: usize,
    /// `⟦s⟧_i = f(i)`.
    pub share: IdentifierPrimeField<F>,
    /// `⟦r⟧_i = r(i)`.
    pub randomness: IdentifierPrimeField<F>,
    /// The padding `q_i`.
    pub pad: [u8; PAD_BYTES],
}

/// `(COMPLAINT, i, ID, sk_ID)`: receiver `i` claims its opening fails the
/// commitment checks and reveals its identity key so anyone can check.
/// The identity is recomputed from the deal, so it is not carried.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Complaint {
    /// The complaining receiver's index, starting at 1.
    pub index: usize,
    /// `sk_ID` for `ID = (dealer, index)`.
    pub key: IdentitySecretKey,
}

/// A receiver's result from [`decrypt`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decrypted<F: PrimeField> {
    /// Both commitment checks passed.
    Share(PvssOpening<F>),
    /// A check failed; post this complaint.
    Complaint(Complaint),
}

/// `Share(s, n, t)`: deal `secret` to one receiver per public key, with
/// `threshold` openings needed to reconstruct.
pub fn share<D, F>(
    dealer: &[u8],
    threshold: usize,
    secret: &IdentifierPrimeField<F>,
    receivers: &[MasterPublicKey],
    mut rng: impl CryptoRng,
) -> VsssResult<PvssDeal<F>>
where
    D: Digest,
    F: PrimeField,
{
    check_field_bits(F::NUM_BITS)?;
    check_params(threshold, receivers.len())?;
    // `f` holds the secret, `r` the commitment randomness, and `B` masks
    // `f` in `W`: wipe all three on every exit.
    let mut f = ZeroizingPolynomial::<PrimeFieldShare<F>, Vec<_>>::create(threshold);
    f.fill(secret, &mut rng, threshold)?;
    let mut r = ZeroizingPolynomial::<PrimeFieldShare<F>, Vec<_>>::create(threshold);
    r.fill(&IdentifierPrimeField::random(&mut rng), &mut rng, threshold)?;
    let mut b = ZeroizingPolynomial::<PrimeFieldShare<F>, Vec<_>>::create(threshold);
    b.fill(&IdentifierPrimeField::random(&mut rng), &mut rng, threshold)?;

    let mut openings = Vec::with_capacity(receivers.len());
    let mut commitments = Vec::with_capacity(receivers.len());
    for index in 1..=receivers.len() {
        let x = index_identifier::<F>(index);
        let mut pad = [0u8; PAD_BYTES];
        rng.fill_bytes(&mut pad);
        let opening = PvssOpening {
            index,
            share: f.evaluate(&x, threshold),
            randomness: r.evaluate(&x, threshold),
            pad,
        };
        wipe(&mut pad);
        commitments.push(PvssCommitment {
            share: share_commitment::<D, F>(&opening),
            padding: padding_commitment::<D, F>(index, &b.evaluate(&x, threshold), &opening.pad),
        });
        openings.push(opening);
    }

    let ch = challenge::<D, F>(dealer, threshold, &commitments);
    let w = b
        .coefficients()
        .iter()
        .zip(f.coefficients())
        .enumerate()
        .map(|(k, (b_k, f_k))| {
            IdentifierPrimeField(coefficient(b_k, k).0 - ch * coefficient(f_k, k).0)
        })
        .collect();

    let ciphertexts = openings
        .iter()
        .zip(receivers)
        .map(|(opening, mpk)| {
            let mut plaintext = encode_opening(opening);
            let ct = encrypt::<D>(mpk, &identity(dealer, opening.index), &plaintext, &mut rng);
            wipe(&mut plaintext);
            ct
        })
        .collect::<VsssResult<Vec<_>>>()?;

    Ok(PvssDeal {
        dealer: dealer.to_vec(),
        ciphertexts,
        proof: PvssProof { w, commitments },
    })
}

/// `Decrypt(E_i, msk_i)` for receiver `index`: extract the identity key for
/// `(dealer, index)`, decrypt, and check
/// `H(⟦s⟧_i, ⟦r⟧_i) = csh_i` and `H(W(i) + ch·⟦s⟧_i, q_i) = cpt_i`.
///
/// Fails only if the deal does not have a ciphertext and commitment for
/// `index` or extraction fails; a bad opening yields a complaint.
pub fn decrypt<D, F>(
    deal: &PvssDeal<F>,
    threshold: usize,
    index: usize,
    msk: &MasterSecretKey,
    mpk: &MasterPublicKey,
    rng: impl CryptoRng,
) -> VsssResult<Decrypted<F>>
where
    D: Digest,
    F: PrimeField,
{
    check_field_bits(F::NUM_BITS)?;
    let receivers = deal.ciphertexts.len();
    if deal.proof.commitments.len() != receivers {
        return Err(Error::InvalidShare);
    }
    let ciphertext = index
        .checked_sub(1)
        .and_then(|slot| deal.ciphertexts.get(slot))
        .ok_or(Error::SharingInvalidIdentifier)?;
    let key = extract::<D>(msk, mpk, &identity(&deal.dealer, index), rng)?;
    let ch = challenge::<D, F>(&deal.dealer, threshold, &deal.proof.commitments);
    match open::<D, F>(&key, ciphertext, index).filter(|o| opening_is_valid::<D, F>(deal, &ch, o)) {
        Some(opening) => Ok(Decrypted::Share(opening)),
        None => Ok(Decrypted::Complaint(Complaint { index, key })),
    }
}

/// `PubVer(st, E, π, n, t)`: `Ok(false)` if the deal is malformed (in
/// particular if `W` does not have exactly `threshold` coefficients) or any
/// complaint is valid, `Ok(true)` otherwise.
///
/// A complaint is rejected when its key fails [`verify_key`] for
/// `(dealer, index)` or when the opening it decrypts passes both
/// commitment checks. Complaints for unknown indices are ignored.
pub fn verify<D, F>(
    deal: &PvssDeal<F>,
    threshold: usize,
    receivers: &[MasterPublicKey],
    complaints: &[Complaint],
) -> VsssResult<bool>
where
    D: Digest,
    F: PrimeField,
{
    check_field_bits(F::NUM_BITS)?;
    check_params(threshold, receivers.len())?;
    if !is_well_formed::<D, F>(deal, threshold, receivers.len()) {
        return Ok(false);
    }
    let ch = challenge::<D, F>(&deal.dealer, threshold, &deal.proof.commitments);
    let valid_complaint = |c: &Complaint| {
        let Some((mpk, ciphertext)) = c
            .index
            .checked_sub(1)
            .and_then(|slot| receivers.get(slot).zip(deal.ciphertexts.get(slot)))
        else {
            return false;
        };
        verify_key::<D>(mpk, &identity(&deal.dealer, c.index), &c.key)
            && !open::<D, F>(&c.key, ciphertext, c.index)
                .is_some_and(|o| opening_is_valid::<D, F>(deal, &ch, &o))
    };
    Ok(!complaints.iter().any(valid_complaint))
}

/// `Recon`: drop openings that fail either commitment check or repeat an
/// index, then interpolate `s` from the first `threshold` that remain.
pub fn reconstruct<D, F>(
    deal: &PvssDeal<F>,
    threshold: usize,
    openings: &[PvssOpening<F>],
) -> VsssResult<IdentifierPrimeField<F>>
where
    D: Digest,
    F: PrimeField,
{
    check_field_bits(F::NUM_BITS)?;
    let receivers = deal.ciphertexts.len();
    check_params(threshold, receivers)?;
    if !is_well_formed::<D, F>(deal, threshold, receivers) {
        return Err(Error::InvalidShare);
    }
    let ch = challenge::<D, F>(&deal.dealer, threshold, &deal.proof.commitments);
    let mut seen = BTreeSet::new();
    let shares: Vec<PrimeFieldShare<F>> = openings
        .iter()
        .filter(|o| opening_is_valid::<D, F>(deal, &ch, o) && seen.insert(o.index))
        .take(threshold)
        .map(|o| PrimeFieldShare::with_identifier_and_value(index_identifier(o.index), o.share))
        .collect();
    if shares.len() < threshold {
        return Err(Error::NotEnoughShares);
    }
    shares.combine()
}

/// Reject fields too small for the `Q_H / |F|` soundness bound.
fn check_field_bits(bits: u32) -> VsssResult<()> {
    if bits >= MIN_FIELD_BITS {
        Ok(())
    } else {
        Err(lattice_error(
            "lattice: PVSS field must have more than 2^128 elements",
        ))
    }
}

/// Whether `deal` has `n` ciphertexts and commitments of digest length and
/// `W` has exactly `threshold` coefficients (degree `threshold − 1`).
fn is_well_formed<D: Digest, F: PrimeField>(
    deal: &PvssDeal<F>,
    threshold: usize,
    n: usize,
) -> bool {
    let digest_len = <D as Digest>::output_size();
    deal.proof.w.len() == threshold
        && deal.ciphertexts.len() == n
        && deal.proof.commitments.len() == n
        && deal
            .proof
            .commitments
            .iter()
            .all(|c| c.share.len() == digest_len && c.padding.len() == digest_len)
}

/// Both commitment checks for `opening` against `deal`.
fn opening_is_valid<D: Digest, F: PrimeField>(
    deal: &PvssDeal<F>,
    ch: &F,
    opening: &PvssOpening<F>,
) -> bool {
    let Some(commitment) = opening
        .index
        .checked_sub(1)
        .and_then(|slot| deal.proof.commitments.get(slot))
    else {
        return false;
    };
    let x = index_identifier::<F>(opening.index);
    let b_i = IdentifierPrimeField(evaluate(&deal.proof.w, &x) + *ch * opening.share.0);
    let share_ok = share_commitment::<D, F>(opening).ct_eq(&commitment.share);
    let padding_ok =
        padding_commitment::<D, F>(opening.index, &b_i, &opening.pad).ct_eq(&commitment.padding);
    bool::from(share_ok & padding_ok)
}

/// Decrypt `ciphertext` and parse it as receiver `index`'s opening.
fn open<D: Digest, F: PrimeField>(
    key: &IdentitySecretKey,
    ciphertext: &Ciphertext,
    index: usize,
) -> Option<PvssOpening<F>> {
    let mut plaintext = ibe_decrypt::<D>(key, ciphertext);
    let opening = decode_opening(index, &plaintext);
    wipe(&mut plaintext);
    opening
}

/// `⟦s⟧_i ‖ ⟦r⟧_i ‖ q_i`, the field elements in their canonical encoding.
fn encode_opening<F: PrimeField>(opening: &PvssOpening<F>) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 * repr_len::<F>() + PAD_BYTES);
    out.extend_from_slice(opening.share.0.to_repr().as_ref());
    out.extend_from_slice(opening.randomness.0.to_repr().as_ref());
    out.extend_from_slice(&opening.pad);
    out
}

/// Invert [`encode_opening`]; `None` on a wrong length or a non-canonical
/// field element.
fn decode_opening<F: PrimeField>(index: usize, bytes: &[u8]) -> Option<PvssOpening<F>> {
    let len = repr_len::<F>();
    let (share, rest) = bytes.split_at_checked(len)?;
    let (randomness, pad) = rest.split_at_checked(len)?;
    let field = |b: &[u8]| {
        let mut repr = F::Repr::default();
        repr.as_mut().copy_from_slice(b);
        Option::<F>::from(F::from_repr(repr)).map(IdentifierPrimeField)
    };
    Some(PvssOpening {
        index,
        share: field(share)?,
        randomness: field(randomness)?,
        pad: pad.try_into().ok()?,
    })
}

/// Bytes in `F::Repr`.
fn repr_len<F: PrimeField>() -> usize {
    F::Repr::default().as_ref().len()
}

/// The receiver identity `ID_i = DST ‖ len(dealer) ‖ dealer ‖ i`.
fn identity(dealer: &[u8], index: usize) -> Vec<u8> {
    let mut id = Vec::with_capacity(IDENTITY_DST.len() + dealer.len() + 16);
    id.extend_from_slice(IDENTITY_DST);
    id.extend_from_slice(&(dealer.len() as u64).to_le_bytes());
    id.extend_from_slice(dealer);
    id.extend_from_slice(&(index as u64).to_le_bytes());
    id
}

/// Receiver `index` as a field element, the Shamir evaluation point.
fn index_identifier<F: PrimeField>(index: usize) -> IdentifierPrimeField<F> {
    IdentifierPrimeField(F::from(index as u64))
}

/// `csh_i = H(DST ‖ i ‖ ⟦s⟧_i ‖ ⟦r⟧_i)`.
fn share_commitment<D: Digest, F: PrimeField>(opening: &PvssOpening<F>) -> Vec<u8> {
    D::new()
        .chain_update(SHARE_COMMITMENT_DST)
        .chain_update((opening.index as u64).to_le_bytes())
        .chain_update(opening.share.0.to_repr())
        .chain_update(opening.randomness.0.to_repr())
        .finalize()
        .to_vec()
}

/// `cpt_i = H(DST ‖ i ‖ B(i) ‖ q_i)`.
fn padding_commitment<D: Digest, F: PrimeField>(
    index: usize,
    b_i: &IdentifierPrimeField<F>,
    pad: &[u8; PAD_BYTES],
) -> Vec<u8> {
    D::new()
        .chain_update(PADDING_COMMITMENT_DST)
        .chain_update((index as u64).to_le_bytes())
        .chain_update(b_i.0.to_repr())
        .chain_update(pad)
        .finalize()
        .to_vec()
}

/// `ch = H(DST ‖ dealer ‖ threshold ‖ n ‖ {csh_i, cpt_i})`, expanded and
/// reduced into `F` with bias below `2^-128`.
fn challenge<D: Digest, F: PrimeField>(
    dealer: &[u8],
    threshold: usize,
    commitments: &[PvssCommitment],
) -> F {
    let transcript = commitments
        .iter()
        .fold(
            D::new()
                .chain_update(CHALLENGE_DST)
                .chain_update((dealer.len() as u64).to_le_bytes())
                .chain_update(dealer)
                .chain_update((threshold as u64).to_le_bytes())
                .chain_update((commitments.len() as u64).to_le_bytes()),
            |h, c| h.chain_update(&c.share).chain_update(&c.padding),
        )
        .finalize();
    let mut wide = std::vec![0u8; repr_len::<F>() + CHALLENGE_EXTRA_BYTES];
    expand::<D>(CHALLENGE_EXPAND_DST, &transcript, &mut wide);
    let radix = F::from(256u64);
    wide.iter()
        .fold(F::ZERO, |acc, &byte| acc * radix + F::from(u64::from(byte)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lattice::PolyQ;
    use crate::lattice::test_support::{RECEIVERS, keys};
    use k256::Scalar;
    use rand::{SeedableRng, rngs::StdRng};
    use sha2::Sha256;

    const THRESHOLD: usize = 2;
    const DEALER: &[u8] = b"dealer-7";

    fn public_keys() -> Vec<MasterPublicKey> {
        keys().iter().map(|(_, mpk)| mpk.clone()).collect()
    }

    fn deal(seed: u8) -> (IdentifierPrimeField<Scalar>, PvssDeal<Scalar>) {
        let mut rng = StdRng::from_seed([seed; 32]);
        let secret = IdentifierPrimeField(Scalar::from(0xDEAD_BEEF_u64));
        let deal = share::<Sha256, Scalar>(DEALER, THRESHOLD, &secret, &public_keys(), &mut rng)
            .expect("share");
        (secret, deal)
    }

    /// Every receiver's result, in index order.
    fn decrypt_all(deal: &PvssDeal<Scalar>, seed: u8) -> Vec<Decrypted<Scalar>> {
        let mut rng = StdRng::from_seed([seed; 32]);
        keys()
            .iter()
            .enumerate()
            .map(|(slot, (msk, mpk))| {
                decrypt::<Sha256, Scalar>(deal, THRESHOLD, slot + 1, msk, mpk, &mut rng)
                    .expect("decrypt")
            })
            .collect()
    }

    fn opening(result: &Decrypted<Scalar>) -> &PvssOpening<Scalar> {
        match result {
            Decrypted::Share(o) => o,
            Decrypted::Complaint(c) => panic!("unexpected complaint from {}", c.index),
        }
    }

    #[test]
    fn honest_deal_decrypts_verifies_and_reconstructs() {
        let (secret, deal) = deal(81);
        assert_eq!(deal.ciphertexts.len(), RECEIVERS);
        assert_eq!(deal.proof.w.len(), THRESHOLD);
        let results = decrypt_all(&deal, 82);
        let openings: Vec<PvssOpening<Scalar>> =
            results.iter().map(|r| opening(r).clone()).collect();
        assert!(
            openings
                .iter()
                .enumerate()
                .all(|(slot, o)| o.index == slot + 1)
        );
        assert_eq!(
            verify::<Sha256, Scalar>(&deal, THRESHOLD, &public_keys(), &[]),
            Ok(true)
        );
        for window in openings.windows(THRESHOLD) {
            assert_eq!(
                reconstruct::<Sha256, Scalar>(&deal, THRESHOLD, window),
                Ok(secret)
            );
        }
    }

    #[test]
    fn dealer_encrypting_a_wrong_share_is_caught() {
        let (_, mut deal) = deal(83);
        let (_, victim_mpk) = &keys()[2];
        let mut rng = StdRng::from_seed([84u8; 32]);
        let wrong = PvssOpening {
            index: 3,
            share: IdentifierPrimeField(Scalar::from(1u64)),
            randomness: IdentifierPrimeField(Scalar::from(2u64)),
            pad: [3u8; PAD_BYTES],
        };
        deal.ciphertexts[2] = encrypt::<Sha256>(
            victim_mpk,
            &identity(DEALER, 3),
            &encode_opening(&wrong),
            &mut rng,
        )
        .expect("encrypt");
        let results = decrypt_all(&deal, 85);
        let complaints: Vec<Complaint> = results
            .iter()
            .filter_map(|r| match r {
                Decrypted::Complaint(c) => Some(c.clone()),
                Decrypted::Share(_) => None,
            })
            .collect();
        assert_eq!(complaints.len(), 1);
        assert_eq!(complaints[0].index, 3);
        assert_eq!(
            verify::<Sha256, Scalar>(&deal, THRESHOLD, &public_keys(), &complaints),
            Ok(false)
        );

        // Garbage that does not parse as an opening is caught the same way.
        deal.ciphertexts[2] =
            encrypt::<Sha256>(victim_mpk, &identity(DEALER, 3), b"short", &mut rng)
                .expect("encrypt");
        let results = decrypt_all(&deal, 86);
        let Decrypted::Complaint(complaint) = &results[2] else {
            panic!("receiver 3 should complain");
        };
        assert_eq!(
            verify::<Sha256, Scalar>(
                &deal,
                THRESHOLD,
                &public_keys(),
                core::slice::from_ref(complaint)
            ),
            Ok(false)
        );
    }

    #[test]
    fn false_complaints_are_rejected() {
        let (_, deal) = deal(87);
        let mut rng = StdRng::from_seed([88u8; 32]);
        let mpks = public_keys();
        let (msk, mpk) = &keys()[0];
        let honest_key =
            extract::<Sha256>(msk, mpk, &identity(DEALER, 1), &mut rng).expect("extract");
        let foreign_key =
            extract::<Sha256>(msk, mpk, &identity(b"other dealer", 1), &mut rng).expect("extract");
        let complaints = [
            // A real key, but the share it opens is honest.
            Complaint {
                index: 1,
                key: honest_key.clone(),
            },
            // A forged key.
            Complaint {
                index: 2,
                key: IdentitySecretKey::new(PolyQ::one()),
            },
            // A real key for a different identity.
            Complaint {
                index: 1,
                key: foreign_key,
            },
            // Receiver 1's key presented as receiver 2's.
            Complaint {
                index: 2,
                key: honest_key.clone(),
            },
            // No such receiver.
            Complaint {
                index: 0,
                key: honest_key.clone(),
            },
            Complaint {
                index: RECEIVERS + 1,
                key: honest_key,
            },
        ];
        assert_eq!(
            verify::<Sha256, Scalar>(&deal, THRESHOLD, &mpks, &complaints),
            Ok(true)
        );
    }

    #[test]
    fn w_of_the_wrong_degree_is_rejected() {
        let (_, deal) = deal(89);
        let mpks = public_keys();
        let mut longer = deal.clone();
        longer.proof.w.push(IdentifierPrimeField::one());
        assert_eq!(
            verify::<Sha256, Scalar>(&longer, THRESHOLD, &mpks, &[]),
            Ok(false)
        );
        let mut shorter = deal.clone();
        shorter.proof.w.pop();
        assert_eq!(
            verify::<Sha256, Scalar>(&shorter, THRESHOLD, &mpks, &[]),
            Ok(false)
        );
        // The verifier's threshold, not the dealer's, sets the degree.
        assert_eq!(
            verify::<Sha256, Scalar>(&deal, THRESHOLD + 1, &mpks, &[]),
            Ok(false)
        );
        let mut truncated = deal.clone();
        truncated.proof.commitments[0].share.pop();
        assert_eq!(
            verify::<Sha256, Scalar>(&truncated, THRESHOLD, &mpks, &[]),
            Ok(false)
        );
        let mut missing = deal;
        missing.ciphertexts.pop();
        assert_eq!(
            verify::<Sha256, Scalar>(&missing, THRESHOLD, &mpks, &[]),
            Ok(false)
        );
        assert_eq!(
            reconstruct::<Sha256, Scalar>(&missing, THRESHOLD, &[]),
            Err(Error::InvalidShare)
        );
    }

    #[test]
    fn reconstruction_discards_tampered_and_repeated_openings() {
        let (secret, deal) = deal(90);
        let mut openings: Vec<PvssOpening<Scalar>> = decrypt_all(&deal, 91)
            .iter()
            .map(|r| opening(r).clone())
            .collect();
        openings[0].share.0 += Scalar::ONE;
        openings[1].pad[0] ^= 1;
        let repeated = openings[2].clone();
        openings.insert(3, repeated);
        // Openings 1 and 2 fail their checks and opening 3 repeats; 3 and 4
        // remain.
        assert_eq!(
            reconstruct::<Sha256, Scalar>(&deal, THRESHOLD, &openings),
            Ok(secret)
        );
        assert_eq!(
            reconstruct::<Sha256, Scalar>(&deal, THRESHOLD, &openings[..4]),
            Err(Error::NotEnoughShares)
        );
        let mut stranger = openings[4].clone();
        stranger.index = RECEIVERS + 1;
        assert_eq!(
            reconstruct::<Sha256, Scalar>(&deal, THRESHOLD, &[openings[2].clone(), stranger]),
            Err(Error::NotEnoughShares)
        );
    }

    #[test]
    fn bad_parameters_are_rejected() {
        let mut rng = StdRng::from_seed([92u8; 32]);
        let secret = IdentifierPrimeField(Scalar::from(5u64));
        let mpks = public_keys();
        assert_eq!(
            share::<Sha256, Scalar>(DEALER, 1, &secret, &mpks, &mut rng),
            Err(Error::SharingMinThreshold)
        );
        assert_eq!(
            share::<Sha256, Scalar>(DEALER, RECEIVERS + 1, &secret, &mpks, &mut rng),
            Err(Error::SharingLimitLessThanThreshold)
        );
        assert!(check_field_bits(128).is_err());
        assert!(check_field_bits(MIN_FIELD_BITS).is_ok());

        let (_, deal) = deal(93);
        let (msk, mpk) = &keys()[0];
        for index in [0, RECEIVERS + 1] {
            assert_eq!(
                decrypt::<Sha256, Scalar>(&deal, THRESHOLD, index, msk, mpk, &mut rng),
                Err(Error::SharingInvalidIdentifier)
            );
        }
        let mut uneven = deal;
        uneven.proof.commitments.pop();
        assert_eq!(
            decrypt::<Sha256, Scalar>(&uneven, THRESHOLD, 1, msk, mpk, &mut rng),
            Err(Error::InvalidShare)
        );
    }

    #[test]
    fn helpers_match_their_definitions() {
        let o = PvssOpening {
            index: 2,
            share: IdentifierPrimeField(Scalar::from(11u64)),
            randomness: IdentifierPrimeField(Scalar::from(12u64)),
            pad: [9u8; PAD_BYTES],
        };
        let bytes = encode_opening(&o);
        assert_eq!(bytes.len(), 2 * repr_len::<Scalar>() + PAD_BYTES);
        assert_eq!(decode_opening::<Scalar>(2, &bytes), Some(o.clone()));
        assert_eq!(decode_opening::<Scalar>(2, &bytes[1..]), None);
        let mut too_big = bytes;
        too_big[..32].fill(0xFF); // ≥ the k256 group order
        assert_eq!(decode_opening::<Scalar>(2, &too_big), None);

        assert_ne!(identity(b"ab", 1), identity(b"a", 1));
        assert_ne!(identity(b"a", 1), identity(b"a", 2));
        assert_eq!(index_identifier::<Scalar>(3).0, Scalar::from(3u64));
        let w = [
            IdentifierPrimeField(Scalar::from(1u64)),
            IdentifierPrimeField(Scalar::from(2u64)),
            IdentifierPrimeField(Scalar::from(3u64)),
        ];
        // 1 + 2·5 + 3·25 = 86.
        assert_eq!(evaluate(&w, &index_identifier(5)), Scalar::from(86u64));
        let poly = [
            PrimeFieldShare::with_identifier_and_value(w[0], w[1]),
            PrimeFieldShare::with_identifier_and_value(w[2], w[0]),
        ];
        assert_eq!(coefficient(&poly[0], 0).0, Scalar::from(2u64));
        assert_eq!(coefficient(&poly[1], 1).0, Scalar::from(3u64));

        let commitments = std::vec![PvssCommitment {
            share: std::vec![1u8; 32],
            padding: std::vec![2u8; 32],
        }];
        let ch = challenge::<Sha256, Scalar>(DEALER, 2, &commitments);
        assert_ne!(ch, challenge::<Sha256, Scalar>(DEALER, 3, &commitments));
        assert_ne!(
            ch,
            challenge::<Sha256, Scalar>(b"dealer-8", 2, &commitments)
        );
        assert_ne!(
            share_commitment::<Sha256, Scalar>(&o),
            padding_commitment::<Sha256, Scalar>(2, &o.share, &o.pad)
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn pvss_types_serde_round_trip() {
        use crate::tests::utils::assert_serde_round_trip;
        let (_, deal) = deal(94);
        assert_serde_round_trip(&deal);
        assert_serde_round_trip(&deal.proof);
        assert_serde_round_trip(&deal.proof.commitments[0]);
        assert_serde_round_trip(&deal.ciphertexts[0]);
        let results = decrypt_all(&deal, 95);
        assert_serde_round_trip(opening(&results[0]));
        let (msk, mpk) = &keys()[0];
        let mut rng = StdRng::from_seed([96u8; 32]);
        let key = extract::<Sha256>(msk, mpk, &identity(DEALER, 1), &mut rng).expect("extract");
        assert_serde_round_trip(&Complaint { index: 1, key });
    }
}
