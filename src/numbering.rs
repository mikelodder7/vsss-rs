use core::num::{NonZeroU64, NonZeroUsize};
use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};
use elliptic_curve::PrimeField;
use rand_core::{CryptoRng, RngCore};
use sha3::digest::ExtendableOutput;
use sha3::{
    digest::{Update, XofReader},
    Shake256,
};

/// A trait for generating participant numbers
pub trait ParticipantNumberGenerator<F: PrimeField>: Iterator<Item = F> + Clone {
    /// Get the participant id `index`
    fn get_participant_id(&self, index: usize) -> F;
}

#[derive(Debug, Clone, Copy)]
/// A generator that can create any number of secret shares
pub struct SequentialParticipantNumberGenerator<F: PrimeField> {
    index: usize,
    start: u64,
    increment: u64,
    limit: usize,
    _markers: PhantomData<F>,
}

impl<F: PrimeField> Default for SequentialParticipantNumberGenerator<F> {
    fn default() -> Self {
        Self {
            start: 1,
            increment: 1,
            index: 0,
            limit: u8::MAX as usize,
            _markers: PhantomData,
        }
    }
}

impl<F: PrimeField> Iterator for SequentialParticipantNumberGenerator<F> {
    type Item = F;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.limit {
            return None;
        }
        let f = self.get_participant_id(self.index);
        self.index += 1;
        Some(f)
    }
}

impl<F: PrimeField> ParticipantNumberGenerator<F> for SequentialParticipantNumberGenerator<F> {
    fn get_participant_id(&self, index: usize) -> F {
        let index = index as u64;
        F::from(index * self.increment + self.start)
    }
}

impl<F: PrimeField> SequentialParticipantNumberGenerator<F> {
    /// Create a new set generator
    pub fn new(
        start: Option<NonZeroU64>,
        increment: Option<NonZeroU64>,
        limit: NonZeroUsize,
    ) -> Self {
        Self {
            start: start.map(|s| s.get()).unwrap_or(1),
            increment: increment.map(|s| s.get()).unwrap_or(1),
            index: 0,
            limit: limit.get(),
            _markers: PhantomData,
        }
    }
}

#[derive(Debug, Clone, Copy)]
/// A generator that creates random participant identifiers
pub struct RandomParticipantNumberGenerator<F: PrimeField> {
    /// Domain separation tag
    dst: [u8; 32],
    index: usize,
    limit: usize,
    _markers: PhantomData<F>,
}

impl<F: PrimeField> Default for RandomParticipantNumberGenerator<F> {
    fn default() -> Self {
        Self {
            dst: [0u8; 32],
            index: 0,
            limit: u8::MAX as usize,
            _markers: PhantomData,
        }
    }
}

impl<F: PrimeField> Iterator for RandomParticipantNumberGenerator<F> {
    type Item = F;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.limit {
            return None;
        }
        self.index += 1;
        Some(F::random(self.get_rng(self.index)))
    }
}

impl<F: PrimeField> ParticipantNumberGenerator<F> for RandomParticipantNumberGenerator<F> {
    fn get_participant_id(&self, index: usize) -> F {
        F::random(self.get_rng(index + 1))
    }
}

impl<F: PrimeField> RandomParticipantNumberGenerator<F> {
    /// Create a new random participant number generator
    pub fn new(limit: NonZeroUsize, mut rng: impl RngCore + CryptoRng) -> Self {
        let mut dst = [0u8; 32];
        rng.fill_bytes(&mut dst);
        Self {
            dst,
            index: 0,
            limit: limit.get(),
            _markers: PhantomData,
        }
    }

    /// Get the domain separation tag
    pub fn dst(&self) -> [u8; 32] {
        self.dst
    }

    fn get_rng(&self, index: usize) -> XofRng {
        let mut hasher = Shake256::default();
        hasher.update(&self.dst);
        hasher.update(&index.to_be_bytes());
        hasher.update(&self.limit.to_be_bytes());
        XofRng(hasher.finalize_xof())
    }
}

#[derive(Debug, Clone)]
/// A generator that creates participant identifiers from a known list
pub struct ListParticipantNumberGenerator<'a, F: PrimeField> {
    list: &'a [F],
    index: usize,
}

impl<'a, F: PrimeField> Default for ListParticipantNumberGenerator<'a, F> {
    fn default() -> Self {
        Self {
            list: &[],
            index: 0,
        }
    }
}

impl<'a, F: PrimeField> Iterator for ListParticipantNumberGenerator<'a, F> {
    type Item = F;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.list.len() {
            return None;
        }
        let index = self.index;
        self.index += 1;
        Some(self.list[index])
    }
}

impl<'a, F: PrimeField> ParticipantNumberGenerator<F> for ListParticipantNumberGenerator<'a, F> {
    fn get_participant_id(&self, index: usize) -> F {
        self.list[index]
    }
}

impl<'a, F: PrimeField> ListParticipantNumberGenerator<'a, F> {
    /// Create a new list generator
    pub fn new(list: &'a [F]) -> Self {
        Self { list, index: 0 }
    }
}

#[derive(Debug, Clone)]
/// A generator that creates participant identifiers from a known list and then random numbers after
/// the list is exhausted
pub struct ListAndRandomParticipantNumberGenerator<'a, F: PrimeField> {
    list: ListParticipantNumberGenerator<'a, F>,
    rng: RandomParticipantNumberGenerator<F>,
}

impl<'a, F: PrimeField> Default for ListAndRandomParticipantNumberGenerator<'a, F> {
    fn default() -> Self {
        Self {
            list: ListParticipantNumberGenerator::default(),
            rng: RandomParticipantNumberGenerator::default(),
        }
    }
}

impl<'a, F: PrimeField> Iterator for ListAndRandomParticipantNumberGenerator<'a, F> {
    type Item = F;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(next) = self.list.next() {
            return Some(next);
        }
        self.rng.next()
    }
}

impl<'a, F: PrimeField> ParticipantNumberGenerator<F>
    for ListAndRandomParticipantNumberGenerator<'a, F>
{
    fn get_participant_id(&self, index: usize) -> F {
        if index < self.list.list.len() {
            self.list.list[index]
        } else {
            self.rng.get_participant_id(index)
        }
    }
}

impl<'a, F: PrimeField> ListAndRandomParticipantNumberGenerator<'a, F> {
    /// Create a new list and random generator
    pub fn new(list: &'a [F], limit: NonZeroUsize, rng: impl RngCore + CryptoRng) -> Self {
        let mut rng = RandomParticipantNumberGenerator::new(limit, rng);
        rng.index = list.len();
        Self {
            list: ListParticipantNumberGenerator::new(list),
            rng,
        }
    }
}

#[derive(Debug, Clone)]
/// A generator that creates participant identifiers from a known list and then sequential numbers
/// after the list is exhausted.
pub struct ListAndSequentialParticipantNumberGenerator<'a, F: PrimeField> {
    list: ListParticipantNumberGenerator<'a, F>,
    seq: SequentialParticipantNumberGenerator<F>,
}

impl<'a, F: PrimeField> Default for ListAndSequentialParticipantNumberGenerator<'a, F> {
    fn default() -> Self {
        Self {
            list: ListParticipantNumberGenerator::default(),
            seq: SequentialParticipantNumberGenerator::default(),
        }
    }
}

impl<'a, F: PrimeField> Iterator for ListAndSequentialParticipantNumberGenerator<'a, F> {
    type Item = F;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(next) = self.list.next() {
            return Some(next);
        }
        self.seq.next()
    }
}

impl<'a, F: PrimeField> ParticipantNumberGenerator<F>
    for ListAndSequentialParticipantNumberGenerator<'a, F>
{
    fn get_participant_id(&self, index: usize) -> F {
        if index < self.list.list.len() {
            self.list.list[index]
        } else {
            self.seq.get_participant_id(index)
        }
    }
}

impl<'a, F: PrimeField> ListAndSequentialParticipantNumberGenerator<'a, F> {
    /// Create a new list and sequential generator
    pub fn new(
        list: &'a [F],
        start: Option<NonZeroU64>,
        end: Option<NonZeroU64>,
        limit: NonZeroUsize,
    ) -> Self {
        Self {
            list: ListParticipantNumberGenerator::new(list),
            seq: SequentialParticipantNumberGenerator::new(start, end, limit),
        }
    }
}

#[derive(Clone)]
#[repr(transparent)]
struct XofRng(<Shake256 as ExtendableOutput>::Reader);

impl RngCore for XofRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.0.read(&mut buf);
        u32::from_be_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.0.read(&mut buf);
        u64::from_be_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.read(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.read(dest);
        Ok(())
    }
}

impl CryptoRng for XofRng {}

impl Debug for XofRng {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "XofRng")
    }
}

#[cfg(all(test, any(feature = "alloc", feature = "std")))]
mod tests {
    use super::*;
    use crate::*;
    use k256::{FieldBytes, Scalar};
    use rand_core::SeedableRng;

    #[cfg(any(feature = "alloc", feature = "std"))]
    #[test]
    fn test_sequential_participant_number_generator() {
        let gen = SequentialParticipantNumberGenerator::<Scalar>::new(
            None,
            None,
            NonZeroUsize::new(5).unwrap(),
        );
        let list: Vec<_> = gen.collect();
        assert_eq!(list.len(), 5);
        assert_eq!(list[0], Scalar::from(1u64));
        assert_eq!(list[1], Scalar::from(2u64));
        assert_eq!(list[2], Scalar::from(3u64));
        assert_eq!(list[3], Scalar::from(4u64));
        assert_eq!(list[4], Scalar::from(5u64));
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    #[test]
    fn test_random_participant_number_generator() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([1u8; 32]);
        let gen = RandomParticipantNumberGenerator::<Scalar>::new(
            NonZeroUsize::new(5).unwrap(),
            &mut rng,
        );
        let list: Vec<_> = gen.collect();
        assert_eq!(list.len(), 5);
        let mut repr = FieldBytes::default();
        for (i, s) in [
            "134de46908fd0867a9c14ed96e90cd34be47e2b052ca266499687adae4cfe445",
            "5b182d31afa277bcfb5d6316c31e231004d29f2c99e4dec0c384d7a46439c8ca",
            "cb15c36dfe7b15c253e3f9fde1fd9ccfbd75839ff6dccca49700cb831dc5802e",
            "bb3a92d716f6a8d94d82295fd120b23d42ec8543a405ecd82e519ab0fe4ef965",
            "a0fff4c9e992f0d1acc8bc90fe6ae31dee280a0175a028a6333dde56de2121ec",
        ]
        .iter()
        .enumerate()
        {
            repr.copy_from_slice(&hex::decode(s).unwrap());
            assert_eq!(list[i], Scalar::from_repr(repr).unwrap());
        }
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    #[test]
    fn test_list_participant_number_generator() {
        let list = [
            Scalar::from(10u64),
            Scalar::from(20u64),
            Scalar::from(30u64),
            Scalar::from(40u64),
            Scalar::from(50u64),
        ];
        let gen = ListParticipantNumberGenerator::new(&list);
        let list: Vec<_> = gen.collect();
        assert_eq!(list.len(), 5);
        assert_eq!(list[0], Scalar::from(10u64));
        assert_eq!(list[1], Scalar::from(20u64));
        assert_eq!(list[2], Scalar::from(30u64));
        assert_eq!(list[3], Scalar::from(40u64));
        assert_eq!(list[4], Scalar::from(50u64));
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    #[test]
    fn test_list_and_sequential_number_generator() {
        let list = [
            Scalar::from(10u64),
            Scalar::from(20u64),
            Scalar::from(30u64),
            Scalar::from(40u64),
            Scalar::from(50u64),
        ];
        let gen = ListAndSequentialParticipantNumberGenerator::new(
            &list,
            Some(NonZeroU64::new(51).unwrap()),
            None,
            NonZeroUsize::new(5).unwrap(),
        );
        let list: Vec<_> = gen.collect();
        assert_eq!(list.len(), 10);
        assert_eq!(list[0], Scalar::from(10u64));
        assert_eq!(list[1], Scalar::from(20u64));
        assert_eq!(list[2], Scalar::from(30u64));
        assert_eq!(list[3], Scalar::from(40u64));
        assert_eq!(list[4], Scalar::from(50u64));
        assert_eq!(list[5], Scalar::from(51u64));
        assert_eq!(list[6], Scalar::from(52u64));
        assert_eq!(list[7], Scalar::from(53u64));
        assert_eq!(list[8], Scalar::from(54u64));
        assert_eq!(list[9], Scalar::from(55u64));
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    #[test]
    fn test_list_and_random_number_generator() {
        let list = [
            Scalar::from(10u64),
            Scalar::from(20u64),
            Scalar::from(30u64),
            Scalar::from(40u64),
            Scalar::from(50u64),
        ];
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([1u8; 32]);
        let gen = ListAndRandomParticipantNumberGenerator::new(
            &list,
            NonZeroUsize::new(10).unwrap(),
            &mut rng,
        );
        let list: Vec<_> = gen.collect();
        assert_eq!(list.len(), 10);
        assert_eq!(list[0], Scalar::from(10u64));
        assert_eq!(list[1], Scalar::from(20u64));
        assert_eq!(list[2], Scalar::from(30u64));
        assert_eq!(list[3], Scalar::from(40u64));
        assert_eq!(list[4], Scalar::from(50u64));
        let mut repr = FieldBytes::default();
        for (i, s) in [
            "5d9936ecfa115f5a6b3f5d52ba3a3746ea228ee00909efd37765c6518e2ccf23",
            "bb8dac41d8863e1b62432ebb498135db386a9c87565204f424866b9425e3462f",
            "b5c783b3d7c5aabd815778ae5c384d52bbadfab862ce19fe595bb8a266620010",
            "060b9b0a6881ad4b9be3dbcb7fa28917e9c334340e769155ce6cd5960cc789f6",
            "693f774bf59d93f23bd873412863cc6988136fc815169c69059cabbfef563f73",
        ]
        .iter()
        .enumerate()
        {
            repr.copy_from_slice(&hex::decode(s).unwrap());
            assert_eq!(list[i + 5], Scalar::from_repr(repr).unwrap());
        }
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    #[test]
    fn test_empty_list_and_sequential_number_generator() {
        let mut gen = ListAndSequentialParticipantNumberGenerator::<Scalar>::default();
        gen.seq.start = 1;
        gen.seq.limit = 5;
        let list: Vec<_> = gen.collect();
        assert_eq!(list.len(), 5);
        assert_eq!(list[0], Scalar::from(1u64));
        assert_eq!(list[1], Scalar::from(2u64));
        assert_eq!(list[2], Scalar::from(3u64));
        assert_eq!(list[3], Scalar::from(4u64));
        assert_eq!(list[4], Scalar::from(5u64));
    }
}
