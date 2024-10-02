use core::fmt::Display;
use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    num::NonZeroUsize,
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

impl<I: ShareIdentifier + Display> Display for ParticipantIdGeneratorType<'_, I> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sequential {
                start,
                increment,
                count,
            } => write!(
                f,
                "Sequential {{ start: {}, increment: {}, count: {} }}",
                start, increment, count
            ),
            Self::Random { seed, count } => {
                write!(f, "Random {{ seed: ")?;
                for &b in seed {
                    write!(f, "{:02x}", b)?;
                }
                write!(f, ", count: {} }}", count)
            }
            Self::List { list } => {
                write!(f, "List {{ list: ")?;
                for id in list.iter() {
                    write!(f, "{}, ", id)?;
                }
                write!(f, "}}")
            }
        }
    }
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

    pub(crate) fn try_into_generator(&self) -> VsssResult<ParticipantIdGeneratorState<'a, I>> {
        match self {
            Self::Sequential {
                start,
                increment,
                count,
            } => {
                if *count == 0 {
                    return Err(Error::InvalidGenerator(
                        "The count must be greater than zero",
                    ));
                }
                Ok(ParticipantIdGeneratorState::Sequential(
                    SequentialParticipantNumberGenerator {
                        start: start.clone(),
                        increment: increment.clone(),
                        index: 0,
                        count: *count,
                    },
                ))
            }
            Self::Random { seed, count } => {
                if *count == 0 {
                    return Err(Error::InvalidGenerator(
                        "The count must be greater than zero",
                    ));
                }
                Ok(ParticipantIdGeneratorState::Random(
                    RandomParticipantNumberGenerator {
                        dst: *seed,
                        index: 0,
                        count: *count,
                        _markers: PhantomData,
                    },
                ))
            }
            Self::List { list } => Ok(ParticipantIdGeneratorState::List(
                ListParticipantNumberGenerator { list, index: 0 },
            )),
        }
    }
}

/// A collection of participant number generators
#[derive(Debug)]
pub struct ParticipantIdGeneratorCollection<'a, 'b, I: ShareIdentifier> {
    /// The collection of participant id generators
    pub generators: &'a [ParticipantIdGeneratorType<'b, I>],
}

impl<'a, 'b, I: ShareIdentifier> From<&'a [ParticipantIdGeneratorType<'b, I>]>
    for ParticipantIdGeneratorCollection<'a, 'b, I>
{
    fn from(generators: &'a [ParticipantIdGeneratorType<'b, I>]) -> Self {
        Self { generators }
    }
}

impl<'a, 'b, I: ShareIdentifier, const L: usize> From<&'a [ParticipantIdGeneratorType<'b, I>; L]>
    for ParticipantIdGeneratorCollection<'a, 'b, I>
{
    fn from(generators: &'a [ParticipantIdGeneratorType<'b, I>; L]) -> Self {
        Self { generators }
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<'a, 'b, I: ShareIdentifier> From<&'a crate::Vec<ParticipantIdGeneratorType<'b, I>>>
    for ParticipantIdGeneratorCollection<'a, 'b, I>
{
    fn from(generators: &'a crate::Vec<ParticipantIdGeneratorType<'b, I>>) -> Self {
        Self {
            generators: generators.as_slice(),
        }
    }
}

impl<'a, 'b, I: ShareIdentifier> ParticipantIdGeneratorCollection<'a, 'b, I> {
    /// Returns an iterator that generates participant identifiers.
    ///
    /// The iterator will halt if an internal error occurs or an identifier
    /// is generated that is the zero element.
    pub fn iter(&self) -> impl Iterator<Item = I> + '_ {
        let mut participant_id_iter = self.generators.iter().map(|g| g.try_into_generator());
        let mut current: Option<ParticipantIdGeneratorState<'a, I>> = None;
        core::iter::from_fn(move || {
            loop {
                if let Some(ref mut generator) = current {
                    match generator.next() {
                        Some(id) => {
                            if id.is_zero().into() {
                                current = None; // Move to next generator
                                continue;
                            }
                            return Some(id);
                        }
                        None => {
                            current = None; // Current generator exhausted, move to next
                        }
                    }
                }

                // If we're here, we need a new generator
                match participant_id_iter.next() {
                    Some(Ok(new_generator)) => {
                        current = Some(new_generator);
                        // Continue to next iteration to start using this generator
                    }
                    Some(Err(_)) => return None, // Errored generator
                    None => return None,         // All generators exhausted
                }
            }
        })
    }
}

pub(crate) enum ParticipantIdGeneratorState<'a, I: ShareIdentifier> {
    Sequential(SequentialParticipantNumberGenerator<I>),
    Random(RandomParticipantNumberGenerator<I>),
    List(ListParticipantNumberGenerator<'a, I>),
}

impl<'a, I: ShareIdentifier> Iterator for ParticipantIdGeneratorState<'a, I> {
    type Item = I;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Sequential(gen) => gen.next(),
            Self::Random(gen) => gen.next(),
            Self::List(gen) => gen.next(),
        }
    }
}

#[derive(Debug)]
/// A generator that can create any number of secret shares
pub(crate) struct SequentialParticipantNumberGenerator<I: ShareIdentifier> {
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
        let value = self.start.clone();
        self.start.inc(&self.increment);
        self.index += 1;
        Some(value)
    }
}

/// A generator that creates random participant identifiers
#[derive(Debug)]
pub(crate) struct RandomParticipantNumberGenerator<I: ShareIdentifier> {
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
pub(crate) struct ListParticipantNumberGenerator<'a, I: ShareIdentifier> {
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
    use elliptic_curve::PrimeField;
    use k256::{FieldBytes, Scalar};
    use rand_core::SeedableRng;

    #[cfg(any(feature = "alloc", feature = "std"))]
    #[test]
    fn test_sequential_participant_number_generator() {
        let gen = SequentialParticipantNumberGenerator::<IdentifierPrimeField<Scalar>> {
            start: IdentifierPrimeField::<Scalar>::ONE,
            increment: IdentifierPrimeField::<Scalar>::ONE,
            index: 0,
            count: 5,
        };
        let list: Vec<_> = gen.collect();
        assert_eq!(list.len(), 5);
        assert_eq!(list[0], IdentifierPrimeField::from(Scalar::from(1u64)));
        assert_eq!(list[1], IdentifierPrimeField::from(Scalar::from(2u64)));
        assert_eq!(list[2], IdentifierPrimeField::from(Scalar::from(3u64)));
        assert_eq!(list[3], IdentifierPrimeField::from(Scalar::from(4u64)));
        assert_eq!(list[4], IdentifierPrimeField::from(Scalar::from(5u64)));
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    #[test]
    fn test_random_participant_number_generator() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([1u8; 32]);
        let mut dst = [0u8; 32];
        rng.fill_bytes(&mut dst);
        let gen = RandomParticipantNumberGenerator::<IdentifierPrimeField<Scalar>> {
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
            assert_eq!(
                list[i],
                IdentifierPrimeField::from(Scalar::from_repr(repr).unwrap())
            );
        }
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    #[test]
    fn test_list_participant_number_generator() {
        let list = [
            IdentifierPrimeField::from(Scalar::from(10u64)),
            IdentifierPrimeField::from(Scalar::from(20u64)),
            IdentifierPrimeField::from(Scalar::from(30u64)),
            IdentifierPrimeField::from(Scalar::from(40u64)),
            IdentifierPrimeField::from(Scalar::from(50u64)),
        ];
        let gen = ListParticipantNumberGenerator {
            list: &list,
            index: 0,
        };
        let list: Vec<_> = gen.collect();
        assert_eq!(list.len(), 5);
        assert_eq!(list[0], IdentifierPrimeField::from(Scalar::from(10u64)));
        assert_eq!(list[1], IdentifierPrimeField::from(Scalar::from(20u64)));
        assert_eq!(list[2], IdentifierPrimeField::from(Scalar::from(30u64)));
        assert_eq!(list[3], IdentifierPrimeField::from(Scalar::from(40u64)));
        assert_eq!(list[4], IdentifierPrimeField::from(Scalar::from(50u64)));
    }

    #[test]
    fn test_list_and_sequential_number_generator() {
        let list = [
            IdentifierPrimeField::from(Scalar::from(10u64)),
            IdentifierPrimeField::from(Scalar::from(20u64)),
            IdentifierPrimeField::from(Scalar::from(30u64)),
            IdentifierPrimeField::from(Scalar::from(40u64)),
            IdentifierPrimeField::from(Scalar::from(50u64)),
        ];
        let set = [
            ParticipantIdGeneratorType::list(&list),
            ParticipantIdGeneratorType::sequential(
                Some(IdentifierPrimeField::from(Scalar::from(51u64))),
                Some(IdentifierPrimeField::<Scalar>::ONE),
                NonZeroUsize::new(5).unwrap(),
            ),
        ];
        let collection = ParticipantIdGeneratorCollection::from(&set[..]);

        let expected = [
            IdentifierPrimeField::from(Scalar::from(10u64)),
            IdentifierPrimeField::from(Scalar::from(20u64)),
            IdentifierPrimeField::from(Scalar::from(30u64)),
            IdentifierPrimeField::from(Scalar::from(40u64)),
            IdentifierPrimeField::from(Scalar::from(50u64)),
            IdentifierPrimeField::from(Scalar::from(51u64)),
            IdentifierPrimeField::from(Scalar::from(52u64)),
            IdentifierPrimeField::from(Scalar::from(53u64)),
            IdentifierPrimeField::from(Scalar::from(54u64)),
            IdentifierPrimeField::from(Scalar::from(55u64)),
        ];
        let mut last_i = 0;
        for (i, id) in collection.iter().enumerate() {
            assert_eq!(id, expected[i]);
            last_i = i;
        }
        assert_eq!(last_i, expected.len() - 1);
    }

    #[test]
    fn test_list_and_random_number_generator() {
        let list = [
            IdentifierPrimeField::from(Scalar::from(10u64)),
            IdentifierPrimeField::from(Scalar::from(20u64)),
            IdentifierPrimeField::from(Scalar::from(30u64)),
            IdentifierPrimeField::from(Scalar::from(40u64)),
            IdentifierPrimeField::from(Scalar::from(50u64)),
        ];
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([1u8; 32]);
        let mut dst = [0u8; 32];
        rng.fill_bytes(&mut dst);
        let set = [
            ParticipantIdGeneratorType::list(&list),
            ParticipantIdGeneratorType::random(dst, NonZeroUsize::new(5).unwrap()),
        ];
        let collection = ParticipantIdGeneratorCollection::from(&set);
        let expected = [
            IdentifierPrimeField::from(Scalar::from(10u64)),
            IdentifierPrimeField::from(Scalar::from(20u64)),
            IdentifierPrimeField::from(Scalar::from(30u64)),
            IdentifierPrimeField::from(Scalar::from(40u64)),
            IdentifierPrimeField::from(Scalar::from(50u64)),
            hex::decode("134de46908fd0867a9c14ed96e90cd34be47e2b052ca266499687adae4cfe445")
                .map(|b| {
                    IdentifierPrimeField::from(
                        Scalar::from_repr(FieldBytes::clone_from_slice(&b)).unwrap(),
                    )
                })
                .unwrap(),
            hex::decode("5b182d31afa277bcfb5d6316c31e231004d29f2c99e4dec0c384d7a46439c8ca")
                .map(|b| {
                    IdentifierPrimeField::from(
                        Scalar::from_repr(FieldBytes::clone_from_slice(&b)).unwrap(),
                    )
                })
                .unwrap(),
            hex::decode("cb15c36dfe7b15c253e3f9fde1fd9ccfbd75839ff6dccca49700cb831dc5802e")
                .map(|b| {
                    IdentifierPrimeField::from(
                        Scalar::from_repr(FieldBytes::clone_from_slice(&b)).unwrap(),
                    )
                })
                .unwrap(),
            hex::decode("bb3a92d716f6a8d94d82295fd120b23d42ec8543a405ecd82e519ab0fe4ef965")
                .map(|b| {
                    IdentifierPrimeField::from(
                        Scalar::from_repr(FieldBytes::clone_from_slice(&b)).unwrap(),
                    )
                })
                .unwrap(),
            hex::decode("a0fff4c9e992f0d1acc8bc90fe6ae31dee280a0175a028a6333dde56de2121ec")
                .map(|b| {
                    IdentifierPrimeField::from(
                        Scalar::from_repr(FieldBytes::clone_from_slice(&b)).unwrap(),
                    )
                })
                .unwrap(),
        ];
        let mut last_i = 0;
        for (i, id) in collection.iter().enumerate() {
            assert_eq!(id, expected[i]);
            last_i = i;
        }
        assert_eq!(last_i, expected.len() - 1);
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    #[test]
    fn test_empty_list_and_sequential_number_generator() {
        let list: [IdentifierPrimeField<Scalar>; 0] = [];
        let generators = [
            ParticipantIdGeneratorType::list(&list),
            ParticipantIdGeneratorType::sequential(None, None, NonZeroUsize::new(5).unwrap()),
        ];
        let collection = ParticipantIdGeneratorCollection::from(&generators);
        let list: Vec<_> = collection.iter().collect();
        assert_eq!(list.len(), 5);
        assert_eq!(list[0], IdentifierPrimeField::from(Scalar::from(1u64)));
        assert_eq!(list[1], IdentifierPrimeField::from(Scalar::from(2u64)));
        assert_eq!(list[2], IdentifierPrimeField::from(Scalar::from(3u64)));
        assert_eq!(list[3], IdentifierPrimeField::from(Scalar::from(4u64)));
        assert_eq!(list[4], IdentifierPrimeField::from(Scalar::from(5u64)));
    }
}
