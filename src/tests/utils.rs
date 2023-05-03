/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use crate::*;
use elliptic_curve::{
    Group,
    group::GroupEncoding,
};
use rand_core::SeedableRng;

pub struct MockRng(rand_xorshift::XorShiftRng);

impl Default for MockRng {
    fn default() -> Self {
        Self::from_seed([7u8; 16])
    }
}

impl SeedableRng for MockRng {
    type Seed = [u8; 16];

    fn from_seed(seed: Self::Seed) -> Self {
        Self(rand_xorshift::XorShiftRng::from_seed(seed))
    }
}

impl rand_core::CryptoRng for MockRng {}

impl rand_core::RngCore for MockRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}

pub(crate) struct TestPedersenResult<G, I, S>
    where G: Group,
          I: ShareIdentifier,
          S: Share<Identifier = I>,
{
    blinder: G::Scalar,
    secret_shares: [S; 16],
    blinder_shares: [S; 16],
    feldman_verifier_set: [G; 16],
    pedersen_verifier_set: [G; 16],
}

impl<G: Group, I: ShareIdentifier, S: Share<Identifier = I>> PedersenResult<G, I, S> for TestPedersenResult<G, I, S> {
    type ShareSet = [S; 16];
    type FeldmanVerifierSet = [G; 16];
    type PedersenVerifierSet = [G; 16];

    fn new(blinder: G::Scalar, secret_shares: Self::ShareSet, blinder_shares: Self::ShareSet, feldman_verifier_set: Self::FeldmanVerifierSet, pedersen_verifier_set: Self::PedersenVerifierSet) -> Self {
        Self {
            blinder,
            secret_shares,
            blinder_shares,
            feldman_verifier_set,
            pedersen_verifier_set,
        }
    }

    fn blinder(&self) -> G::Scalar {
        self.blinder
    }

    fn secret_shares(&self) -> &Self::ShareSet {
        &self.secret_shares
    }

    fn blinder_shares(&self) -> &Self::ShareSet {
        &self.blinder_shares
    }

    fn feldman_verifier_set(&self) -> &Self::FeldmanVerifierSet {
        &self.feldman_verifier_set
    }

    fn pedersen_verifier_set(&self) -> &Self::PedersenVerifierSet {
        &self.pedersen_verifier_set
    }
}