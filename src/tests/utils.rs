/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use rand_core::{Infallible, SeedableRng, TryCryptoRng, TryRng};

#[cfg(feature = "stream")]
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};
#[cfg(feature = "stream")]
use futures_core::Stream;

#[cfg(feature = "stream")]
pub fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = core::pin::pin!(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
    }
}

#[cfg(feature = "stream")]
pub struct TestStream<I> {
    iter: I,
    pending: bool,
}

#[cfg(feature = "stream")]
impl<I> TestStream<I> {
    pub fn new(iter: I) -> Self {
        Self {
            iter,
            pending: true,
        }
    }
}

#[cfg(feature = "stream")]
impl<I> Stream for TestStream<I>
where
    I: Iterator + Unpin,
{
    type Item = I::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.pending {
            self.pending = false;
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            self.pending = true;
            Poll::Ready(self.iter.next())
        }
    }
}

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

impl TryCryptoRng for MockRng {}

impl TryRng for MockRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.0.try_next_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0.try_next_u64()
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.0.try_fill_bytes(dest)
    }
}
