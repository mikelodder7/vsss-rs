/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use crate::Share;
use core::marker::PhantomData;
use ff::PrimeField;
use group::{Group, GroupEncoding, ScalarMul};

/// A Feldman verifier is used to provide integrity checking of shamir shares
/// `T` commitments are made to be used for verification.
#[derive(Copy, Clone, Debug)]
pub struct FeldmanVerifier<F: PrimeField, G: Group + GroupEncoding + ScalarMul<F>, const T: usize> {
    /// The generator for the share polynomial coefficients
    pub generator: G,
    /// The commitments to the polynomial
    pub commitments: [G; T],
    /// Marker
    pub marker: PhantomData<F>,
}

impl<F: PrimeField, G: Group + GroupEncoding + ScalarMul<F>, const T: usize>
    FeldmanVerifier<F, G, T>
{
    /// Check whether the share is valid according this verifier set
    pub fn verify<const S: usize>(&self, share: &Share<S>) -> bool {
        let mut s_repr = F::Repr::default();
        s_repr.as_mut().copy_from_slice(&share.0[1..]);

        let s = F::from_repr(s_repr);
        if s.is_none() {
            return false;
        }

        let s = s.unwrap();
        let x = F::from(share.0[0] as u64);
        let mut i = F::one();

        // FUTURE: execute this sum of products
        // c_0 * c_1^i * c_2^{i^2} ... c_t^{i^t}
        // as a constant time operation using <https://cr.yp.to/papers/pippenger.pdf>
        // or Guide to Elliptic Curve Cryptography book,
        // "Algorithm 3.48 Simultaneous multiple point multiplication"
        // without precomputing the addition but still reduces doublings

        // c_0
        let mut rhs = self.commitments[0];
        for v in &self.commitments {
            i *= x;

            // c_0 * c_1^i * c_2^{i^2} ... c_t^{i^t}
            rhs += *v * i;
        }

        let lhs: G = -self.generator * s;

        let res: G = lhs + rhs;

        res.is_identity().unwrap_u8() == 1
    }
}

/// A Pedersen verifier is used to provide integrity checking of shamir shares
/// `T` commitments are made to be used for verification.
#[derive(Copy, Clone, Debug)]
pub struct PedersenVerifier<F: PrimeField, G: Group + GroupEncoding + ScalarMul<F>, const T: usize>
{
    /// The generator for the blinding factor
    pub generator: G,
    /// The feldman verifier containing the share generator and commitments
    pub feldman_verifier: FeldmanVerifier<F, G, T>,
    /// The blinded commitments to the polynomial
    pub commitments: [G; T],
}

impl<F: PrimeField, G: Group + GroupEncoding + ScalarMul<F>, const T: usize>
    PedersenVerifier<F, G, T>
{
    /// Check whether the share is valid according this verifier set
    pub fn verify<const S: usize>(&self, share: &Share<S>, blind_share: &Share<S>) -> bool {
        let mut s_repr = F::Repr::default();
        s_repr.as_mut().copy_from_slice(&share.0[1..]);

        let s = F::from_repr(s_repr);

        let mut t_repr = F::Repr::default();
        t_repr.as_mut().copy_from_slice(&blind_share.0[1..]);

        let t = F::from_repr(t_repr);
        if s.is_none() || t.is_none() {
            return false;
        }

        let s = s.unwrap();
        let t = t.unwrap();

        let x = F::from(share.0[0] as u64);
        let mut i = F::one();

        // FUTURE: execute this sum of products
        // c_0 * c_1^i * c_2^{i^2} ... c_t^{i^t}
        // as a constant time operation using <https://cr.yp.to/papers/pippenger.pdf>
        // or Guide to Elliptic Curve Cryptography book,
        // "Algorithm 3.48 Simultaneous multiple point multiplication"
        // without precomputing the addition but still reduces doublings

        // c_0
        let mut rhs = self.commitments[0];
        for v in &self.commitments {
            i *= x;

            // c_0 * c_1^i * c_2^{i^2} ... c_t^{i^t}
            rhs += *v * i;
        }

        let g: G = -self.feldman_verifier.generator * s;
        let h: G = -self.generator * t;

        let res: G = rhs + g + h;

        res.is_identity().unwrap_u8() == 1
    }
}
