/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Byte-for-byte regression fingerprints of seeded outputs.
//!
//! Each test hashes a seeded output with SHA-256 and compares the digest to
//! a recorded constant, so any change to RNG draw order, encodings, or the
//! floating-point sampler shows up as a mismatch.
use crate::lattice::test_support::keys;
use crate::lattice::{PolyZ, decrypt, encrypt, extract, pvss};
use crate::*;
use k256::{ProjectivePoint, Scalar};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};
use std::vec::Vec;

type K256Share = PrimeFieldShare<Scalar>;

/// The SHA-256 of every chunk in order, as lowercase hex.
fn fingerprint<'a>(chunks: impl IntoIterator<Item = &'a [u8]>) -> std::string::String {
    let digest = chunks
        .into_iter()
        .fold(Sha256::new(), |h, c| {
            h.chain_update((c.len() as u64).to_le_bytes())
                .chain_update(c)
        })
        .finalize();
    hex::encode(digest)
}

fn poly_z_bytes(p: &PolyZ) -> Vec<u8> {
    p.coeffs().iter().flat_map(|c| c.to_le_bytes()).collect()
}

fn share_bytes<S: Share>(shares: &[S]) -> Vec<Vec<u8>> {
    shares
        .iter()
        .flat_map(|s| [s.identifier().to_vec(), s.value().to_vec()])
        .collect()
}

fn check(name: &str, chunks: &[Vec<u8>], expected: &str) {
    let got = fingerprint(chunks.iter().map(Vec::as_slice));
    assert_eq!(got, expected, "{name} fingerprint changed");
}

const PI_LA: &str = "d2a1eb3a48282c2ae36cf3f8d65d71c6d2e0c8ab935a3a30a609ac1c35e23528";
const HASH_COMMITMENT: &str = "1215b300d7509a8957b432a2fbc28d6b36a15758b61a1bcb05260c3c4b2e33d6";
const SHAMIR_FELDMAN_PEDERSEN: &str =
    "39d0c74ecfdfae82d54adc1f7cb081677e04ff3ea969b8343a29dcbe9b13f25b";
const KEYGEN: &str = "49c8e5d1047b780bd332cd395b54df2510dd011b2ba16aba9a02e60f09f4e1be";
const EXTRACT: &str = "607f18fff1a9c6a8b2cd90192c8b574f7785420d5f33e2443b0bcf99439be96c";
const ENCRYPT: &str = "4030d9d41e217e14782d376fbe0ef5a9ec1e7e841f04efacbeaea0b150cee3b4";
const DECRYPT: &str = "02e83d6fa03af3d466a4fec9b23a26d41b2b87620c0c10074aaac3281555e81b";
const PVSS: &str = "f8e13f825f2ecf696ef7c5205c529c41fcaca51739af959d00de10028341ff45";

#[test]
fn pi_la_split_is_unchanged() {
    let mut rng = ChaCha8Rng::from_seed([0xA1; 32]);
    let secret = IdentifierPrimeField(Scalar::from(0x0102_0304_0506_0708u64));
    let result =
        pi_la::split_secret::<Sha256, K256Share, _>(3, 5, &secret, &mut rng).expect("split");
    let mut chunks = share_bytes(&result.shares);
    for c in &result.proof.commitments {
        chunks.push(c.identifier.to_vec());
        chunks.push(c.digest.as_bytes().to_vec());
    }
    chunks.extend(result.proof.z.iter().map(ShareElement::to_vec));
    check("pi_la", &chunks, PI_LA);
}

#[test]
fn hash_commitment_is_unchanged() {
    let rng = ChaCha8Rng::from_seed([0xA2; 32]);
    let (c, o) = HashCommitment::commit::<Sha256>(b"golden-domain", b"golden message", rng);
    let fixed = HashCommitment::commit_with_randomness::<Sha256>(b"d", b"m", b"r");
    check(
        "hash commitment",
        &[
            c.as_bytes().to_vec(),
            o.as_bytes().to_vec(),
            fixed.as_bytes().to_vec(),
        ],
        HASH_COMMITMENT,
    );
}

#[test]
fn shamir_feldman_pedersen_splits_are_unchanged() {
    let mut rng = ChaCha8Rng::from_seed([0xA3; 32]);
    let secret = IdentifierPrimeField(Scalar::from(77u64));
    let shamir = shamir::split_secret::<K256Share>(3, 5, &secret, &mut rng).expect("shamir");
    let (feldman, verifiers) = feldman::split_secret::<K256Share, ValueGroup<ProjectivePoint>>(
        3, 5, &secret, None, &mut rng,
    )
    .expect("feldman");
    let pedersen = pedersen::split_secret::<K256Share, ValueGroup<ProjectivePoint>>(
        3, 5, &secret, None, None, None, &mut rng,
    )
    .expect("pedersen");
    let mut chunks = share_bytes(&shamir);
    chunks.extend(share_bytes(&feldman));
    chunks.extend(verifiers.iter().map(ShareElement::to_vec));
    chunks.extend(share_bytes(pedersen.secret_shares()));
    chunks.extend(share_bytes(pedersen.blinder_shares()));
    chunks.push(pedersen.blinder().to_vec());
    chunks.extend(
        pedersen
            .pedersen_verifier_set()
            .iter()
            .map(ShareElement::to_vec),
    );
    check("shamir/feldman/pedersen", &chunks, SHAMIR_FELDMAN_PEDERSEN);
}

#[test]
fn lattice_keygen_is_unchanged() {
    let mut chunks = Vec::new();
    for (msk, mpk) in keys() {
        for p in [msk.f(), msk.g(), msk.big_f(), msk.big_g()] {
            chunks.push(poly_z_bytes(p));
        }
        chunks.push(mpk.h().to_bytes());
    }
    check("keygen", &chunks, KEYGEN);
}

#[test]
fn lattice_extract_encrypt_decrypt_are_unchanged() {
    let (msk, mpk) = &keys()[0];
    let mut rng = ChaCha8Rng::from_seed([0xA4; 32]);
    let k1 = extract::<Sha256>(msk, mpk, b"golden-1", &mut rng).expect("extract");
    let k2 = extract::<Sha256>(msk, mpk, b"golden-2", &mut rng).expect("extract");
    check("extract", &[k1.to_bytes(), k2.to_bytes()], EXTRACT);

    let message: Vec<u8> = (0..100u8).collect();
    let ct = encrypt::<Sha256>(mpk, b"golden-1", &message, &mut rng).expect("encrypt");
    check("encrypt", &[ct.to_bytes()], ENCRYPT);

    let plain = decrypt::<Sha256>(&k1, &ct);
    assert_eq!(plain, message);
    let wrong = decrypt::<Sha256>(&k2, &ct);
    check("decrypt", &[plain, wrong], DECRYPT);
}

#[test]
fn pvss_deal_is_unchanged() {
    let mut rng = ChaCha8Rng::from_seed([0xA5; 32]);
    let receivers: Vec<_> = keys().iter().map(|(_, mpk)| mpk.clone()).collect();
    let secret = IdentifierPrimeField(Scalar::from(0xDEAD_BEEFu64));
    let deal = pvss::share::<Sha256, Scalar>(b"golden-dealer", 2, &secret, &receivers, &mut rng)
        .expect("share");
    let mut chunks: Vec<Vec<u8>> = deal.proof.w.iter().map(ShareElement::to_vec).collect();
    for c in &deal.proof.commitments {
        chunks.push(c.share.as_bytes().to_vec());
        chunks.push(c.padding.as_bytes().to_vec());
    }
    chunks.extend(deal.ciphertexts.iter().map(|ct| ct.to_bytes()));
    check("pvss", &chunks, PVSS);
}
