/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! The hashes `H: {0,1}* → Z_q^N` and `H': {0,1}^* → {0,1}^m`.
//!
//! Both expand any [`Digest`] in counter mode. Block `j` is
//! `D(DST ‖ len(input) ‖ input ‖ len(output) ‖ j)` with lengths and the
//! counter as little-endian `u64`, so the two hashes, and different output
//! lengths of `H'`, never share a preimage.
use super::ring::PolyQ;
use super::{N, Q};
use digest::Digest;
use std::vec::Vec;

/// Domain separator for `H`.
const H_DST: &[u8] = b"vsss-rs-lattice-pvss-v1-H";
/// Domain separator for `H'`.
const H_PRIME_DST: &[u8] = b"vsss-rs-lattice-pvss-v1-H-prime";

/// Fill `out` with counter-mode output of `D` over `dst` and `input`.
pub(crate) fn expand<D: Digest>(dst: &[u8], input: &[u8], out: &mut [u8]) {
    let block_len = <D as Digest>::output_size().max(1);
    let out_len = out.len() as u64;
    for (block, chunk) in out.chunks_mut(block_len).enumerate() {
        let bytes = D::new()
            .chain_update(dst)
            .chain_update((input.len() as u64).to_le_bytes())
            .chain_update(input)
            .chain_update(out_len.to_le_bytes())
            .chain_update((block as u64).to_le_bytes())
            .finalize();
        chunk
            .iter_mut()
            .zip(bytes.iter())
            .for_each(|(o, b)| *o = *b);
    }
}

/// `H(input) ∈ R_q`: each coefficient is the low 29 bits of a little-endian
/// 32-bit word of the expansion. Because `q` is a power of two, the
/// coefficients are exactly uniform if `D` behaves as a random oracle.
pub fn hash_to_ring<D: Digest>(input: &[u8]) -> PolyQ {
    let mut bytes = std::vec![0u8; 4 * N];
    expand::<D>(H_DST, input, &mut bytes);
    let (words, _) = bytes.as_chunks::<4>();
    PolyQ::from_reduced(
        words
            .iter()
            .map(|w| u32::from_le_bytes(*w) & (Q - 1))
            .collect(),
    )
}

/// `H'(bits)`, an `m_bits`-bit mask packed least-significant bit first into
/// `⌈m_bits / 8⌉` bytes. Unused high bits of the last byte are zero.
///
/// `bits` is the packed input, such as the `N`-bit key `k` of the IBE
/// encryption, least-significant bit first.
pub fn hash_to_mask<D: Digest>(bits: &[u8], m_bits: usize) -> Vec<u8> {
    let mut out = std::vec![0u8; m_bits.div_ceil(8)];
    // The bit length, not just the byte length, selects the output.
    let mut input = Vec::with_capacity(bits.len() + 8);
    input.extend_from_slice(&(m_bits as u64).to_le_bytes());
    input.extend_from_slice(bits);
    expand::<D>(H_PRIME_DST, &input, &mut out);
    let excess = out.len() * 8 - m_bits;
    if let Some(last) = out.last_mut() {
        *last &= 0xFF >> excess;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Sha256, Sha512};

    #[test]
    fn hash_to_ring_is_deterministic_in_range_and_input_sensitive() {
        let a = hash_to_ring::<Sha256>(b"dealer-1/party-3");
        assert_eq!(a, hash_to_ring::<Sha256>(b"dealer-1/party-3"));
        assert_ne!(a, hash_to_ring::<Sha256>(b"dealer-1/party-4"));
        assert_ne!(a, hash_to_ring::<Sha512>(b"dealer-1/party-3"));
        assert_eq!(a.coeffs().len(), N);
        assert!(a.coeffs().iter().all(|&c| c < Q));
        // 1024 uniform 29-bit values: the top bit should be set about half
        // the time, so the expansion really covers all 29 bits.
        let top = a.coeffs().iter().filter(|&&c| c >> 28 == 1).count();
        assert!((400..624).contains(&top), "top bit set {top} times");
    }

    #[test]
    fn hash_to_mask_has_requested_length_and_is_domain_separated() {
        let k = [0xA5u8; N / 8];
        let m = hash_to_mask::<Sha256>(&k, 1000);
        assert_eq!(m.len(), 125);
        assert_eq!(m, hash_to_mask::<Sha256>(&k, 1000));
        let odd = hash_to_mask::<Sha256>(&k, 13);
        assert_eq!(odd.len(), 2);
        assert_eq!(odd[1] & 0xE0, 0);
        assert_ne!(&hash_to_mask::<Sha256>(&k, 16)[..1], &odd[..1]);
        let mut k2 = k;
        k2[0] ^= 1;
        assert_ne!(hash_to_mask::<Sha256>(&k2, 1000), m);
        assert!(hash_to_mask::<Sha256>(&k, 0).is_empty());
        // H and H' disagree on the same input.
        let ring_bytes: Vec<u8> = hash_to_ring::<Sha256>(&k)
            .coeffs()
            .iter()
            .flat_map(|c| c.to_le_bytes())
            .take(4)
            .collect();
        assert_ne!(&hash_to_mask::<Sha256>(&k, 32)[..], &ring_bytes[..]);
    }
}
