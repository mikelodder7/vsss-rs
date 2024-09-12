use core::num::NonZeroUsize;
use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};
use rand_core::{CryptoRng, RngCore};
use sha3::digest::ExtendableOutput;
use sha3::{
    digest::{Update, XofReader},
    Shake256,
};

use crate::{Error, ShareIdentifier, VsssResult};

/// The types of participant number generators
#[derive(Debug)]
pub enum ParticipantIdGeneratorType<'a, I: ShareIdentifier> {
    /// Generate participant numbers sequentially beginning at `start` and incrementing by `increment`
    /// until `count` is reached then this generator stops.
    Sequential {
        /// The starting identifier
        start: I,
        /// The amount to increment by each time a new id is needed
        increment: I,
        /// The total number of identifiers to generate
        count: usize,
    },
    /// Generate participant numbers randomly using the provided `seed`
    /// until `count` is reached then this generator stops.
    Random {
        /// The seed to use for the random number generator
        seed: [u8; 32],
        /// The total number of identifiers to generate
        count: usize,
    },
    /// Use the provided list of identifiers
    List {
        /// The list of identifiers to use. Once all have been used the generator will stop
        list: &'a [I],
    },
}

impl<I: ShareIdentifier> Default for ParticipantIdGeneratorType<'_, I> {
    fn default() -> Self {
        Self::Sequential {
            start: I::one(),
            increment: I::one(),
            count: u16::MAX as usize,
        }
    }
}

impl<'a, I: ShareIdentifier> ParticipantIdGeneratorType<'a, I> {
    /// Create a new sequential participant number generator
    pub fn sequential(start: Option<I>, increment: Option<I>, count: NonZeroUsize) -> Self {
        Self::Sequential {
            start: start.unwrap_or_else(I::one),
            increment: increment.unwrap_or_else(I::one),
            count: count.get(),
        }
    }

    /// Create a new random participant number generator
    pub fn random(seed: [u8; 32], count: NonZeroUsize) -> Self {
        Self::Random {
            seed,
            count: count.get(),
        }
    }

    /// Create a new list participant number generator
    pub fn list(list: &'a [I]) -> Self {
        Self::List { list }
    }

    pub(crate) fn try_into_generator(self) -> VsssResult<ParticipantIdGeneratorState<'a, I>> {
        match self {
            Self::Sequential {
                start,
                increment,
                count,
            } => {
                if count == 0 {
                    return Err(Error::InvalidGenerator("The count must be greater than zero"));
                }
                Ok(ParticipantIdGeneratorState::Sequential(
                    SequentialParticipantNumberGenerator {
                        start,
                        increment,
                        index: 0,
                        count,
                    },
                ))
            }
            Self::Random { seed, count } => {
                if count == 0 {
                    return Err(Error::InvalidGenerator("The count must be greater than zero"));
                }
                Ok(ParticipantIdGeneratorState::Random(
                    RandomParticipantNumberGenerator {
                        dst: seed,
                        index: 0,
                        count,
                        _markers: PhantomData,
                    },
                ))
            }
            Self::List { list } => {
                if list.is_empty() {
                    return Err(Error::InvalidGenerator("The list must not be empty"));
                }
                Ok(ParticipantIdGeneratorState::List(
                    ListParticipantNumberGenerator { list, index: 0 },
                ))
            }
        }
    }
}

pub(crate) struct ParticipantIdGeneratorCollection<'a, 'b, I: ShareIdentifier> {
    pub(crate) generators: &'a mut [ParticipantIdGeneratorState<'b, I>],
    pub(crate) index: usize,
}

impl<'a, 'b, I: ShareIdentifier> Iterator for ParticipantIdGeneratorCollection<'a, 'b, I> {
    type Item = I;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.index >= self.generators.len() {
                return None;
            }
            let generator = self.generators.get_mut(self.index)?;
            let opt_id = match generator {
                ParticipantIdGeneratorState::Sequential(gen) => gen.next(),
                ParticipantIdGeneratorState::Random(gen) => gen.next(),
                ParticipantIdGeneratorState::List(gen) => gen.next(),
            };
            match opt_id {
                Some(id) => {
                    return Some(id);
                }
                None => {
                    self.index += 1;
                }
            }
        }
    }
}

impl<'a, 'b, I: ShareIdentifier> From<&'a mut [ParticipantIdGeneratorState<'b, I>]>
    for ParticipantIdGeneratorCollection<'a, 'b, I>
{
    fn from(generators: &'a mut [ParticipantIdGeneratorState<'b, I>]) -> Self {
        Self {
            generators,
            index: 0,
        }
    }
}

pub(crate) enum ParticipantIdGeneratorState<'a, I: ShareIdentifier> {
    Sequential(SequentialParticipantNumberGenerator<I>),
    Random(RandomParticipantNumberGenerator<I>),
    List(ListParticipantNumberGenerator<'a, I>),
}

#[derive(Debug)]
/// A generator that can create any number of secret shares
struct SequentialParticipantNumberGenerator<I: ShareIdentifier> {
    start: I,
    increment: I,
    index: usize,
    count: usize,
}

impl<I: ShareIdentifier> Iterator for SequentialParticipantNumberGenerator<I> {
    type Item = I;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count {
            return None;
        }
        self.start += self.increment.clone();
        self.index += 1;
        Some(self.start.clone())
    }
}

/// A generator that creates random participant identifiers
#[derive(Debug)]
struct RandomParticipantNumberGenerator<I: ShareIdentifier> {
    /// Domain separation tag
    dst: [u8; 32],
    index: usize,
    count: usize,
    _markers: PhantomData<I>,
}

impl<I: ShareIdentifier> Iterator for RandomParticipantNumberGenerator<I> {
    type Item = I;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count {
            return None;
        }
        self.index += 1;
        Some(I::random(self.get_rng(self.index)))
    }
}

impl<I: ShareIdentifier> RandomParticipantNumberGenerator<I> {
    fn get_rng(&self, index: usize) -> XofRng {
        let mut hasher = Shake256::default();
        hasher.update(&self.dst);
        hasher.update(&index.to_be_bytes());
        hasher.update(&self.count.to_be_bytes());
        XofRng(hasher.finalize_xof())
    }
}

/// A generator that creates participant identifiers from a known list
#[derive(Debug)]
struct ListParticipantNumberGenerator<'a, I: ShareIdentifier> {
    list: &'a [I],
    index: usize,
}

impl<'a, I: ShareIdentifier> Iterator for ListParticipantNumberGenerator<'a, I> {
    type Item = I;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.list.len() {
            return None;
        }
        let index = self.index;
        self.index += 1;
        Some(self.list[index].clone())
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
        let gen = SequentialParticipantNumberGenerator::<Scalar> {
            start: Scalar::ONE,
            increment: Scalar::ONE,
            index: 0,
            count: 5,
        };
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
        let mut dst = [0u8; 32];
        rng.fill_bytes(&mut dst);
        let gen = RandomParticipantNumberGenerator::<Scalar> {
            dst,
            index: 0,
            count: 5,
            _markers: PhantomData,
        };
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
        let gen = ListParticipantNumberGenerator {
            list: &list,
            index: 0,
        };
        let list: Vec<_> = gen.collect();
        assert_eq!(list.len(), 5);
        assert_eq!(list[0], Scalar::from(10u64));
        assert_eq!(list[1], Scalar::from(20u64));
        assert_eq!(list[2], Scalar::from(30u64));
        assert_eq!(list[3], Scalar::from(40u64));
        assert_eq!(list[4], Scalar::from(50u64));
    }

    #[test]
    fn test_list_and_sequential_number_generator() {
        let list = [
            Scalar::from(10u64),
            Scalar::from(20u64),
            Scalar::from(30u64),
            Scalar::from(40u64),
            Scalar::from(50u64),
        ];
        let mut generators = [
            ParticipantIdGeneratorState::List(ListParticipantNumberGenerator {
                list: &list,
                index: 0,
            }),
            ParticipantIdGeneratorState::Sequential(SequentialParticipantNumberGenerator {
                start: Scalar::from(51u64),
                increment: Scalar::from(1u64),
                index: 0,
                count: 5,
            }),
        ];
        let mut collection = ParticipantIdGeneratorCollection::from(&mut generators);

        let list: Vec<_> = collection.collect();
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
        let mut dst = [0u8; 32];
        rng.fill_bytes(&mut dst);
        let mut generators = [
            ParticipantIdGeneratorState::List(ListParticipantNumberGenerator {
                list: &list,
                index: 0,
            }),
            ParticipantIdGeneratorState::Random(RandomParticipantNumberGenerator {
                dst,
                index: 0,
                count: 5,
                _markers: PhantomData,
            }),
        ];
        let mut collection = ParticipantIdGeneratorCollection::from(&mut generators);
        let list: Vec<_> = collection.collect();
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
        let list = [];
        let mut generators = [
            ParticipantIdGeneratorState::List(ListParticipantNumberGenerator {
                list: &list,
                index: 0,
            }),
            ParticipantIdGeneratorState::Sequential(SequentialParticipantNumberGenerator {
                start: Scalar::from(1u64),
                increment: Scalar::from(1u64),
                index: 0,
                count: 5,
            }),
        ];
        let mut collection = ParticipantIdGeneratorCollection::from(&mut generators);
        let list: Vec<_> = collection.collect();
        assert_eq!(list.len(), 5);
        assert_eq!(list[0], Scalar::from(1u64));
        assert_eq!(list[1], Scalar::from(2u64));
        assert_eq!(list[2], Scalar::from(3u64));
        assert_eq!(list[3], Scalar::from(4u64));
        assert_eq!(list[4], Scalar::from(5u64));
    }
}
