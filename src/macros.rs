#[macro_export]
/// Implements all the VSSS traits for a fixed array
macro_rules! vsss_fixed_array_impl {
    ($name:ident, $pedersen_result:ident, $threshold:expr, $shares:expr) => {
        #[derive(Debug, Copy, Clone)]
        /// A Vsss implementation
        pub struct $name<S: Share, V: ShareVerifier<S>>(core::marker::PhantomData<(S, V)>);

        impl<S: Share, V: ShareVerifier<S>> Shamir<S> for $name<S, V> {
            type InnerPolynomial = [S; $threshold];
            type ShareSet = [S; $shares];
        }

        impl<S: Share, V: ShareVerifier<S>> Feldman<S, V> for $name<S, V> {
            type VerifierSet = [V; $threshold + 1];
        }

        impl<S: Share, V: ShareVerifier<S>> Pedersen<S, V> for $name<S, V> {
            type FeldmanVerifierSet = [V; $threshold + 1];
            type PedersenVerifierSet = [V; $threshold + 2];
            type PedersenResult = $pedersen_result<S, V>;
        }

        /// A pedersen result for static arrays
        #[derive(Debug, Copy, Clone)]
        pub struct $pedersen_result<S: Share, V: ShareVerifier<S>> {
            blinder: S::Value,
            secret_shares: [S; $shares],
            blinder_shares: [S; $shares],
            feldman_verifier_set: [V; $threshold + 1],
            pedersen_verifier_set: [V; $threshold + 2],
        }

        impl<S: Share, V: ShareVerifier<S>> PedersenResult<S, V> for $pedersen_result<S, V> {
            type ShareSet = [S; $shares];
            type FeldmanVerifierSet = [V; $threshold + 1];
            type PedersenVerifierSet = [V; $threshold + 2];

            fn new(
                blinder: S::Value,
                secret_shares: Self::ShareSet,
                blinder_shares: Self::ShareSet,
                feldman_verifier_set: Self::FeldmanVerifierSet,
                pedersen_verifier_set: Self::PedersenVerifierSet,
            ) -> Self {
                Self {
                    blinder,
                    secret_shares,
                    blinder_shares,
                    feldman_verifier_set,
                    pedersen_verifier_set,
                }
            }

            fn blinder(&self) -> &S::Value {
                &self.blinder
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
    };
}

#[cfg(test)]
mod tests {
    use crate::pedersen::PedersenOptions;
    use crate::{
        Feldman, IdentifierPrimeField, Pedersen, PedersenResult, PrimeFieldShare, ReadableShareSet,
        Shamir, Share, ShareVerifier, ValueGroup,
    };
    use k256::{ProjectivePoint, Scalar};
    use rand::{SeedableRng, rngs::StdRng};

    type TestShare = PrimeFieldShare<Scalar>;
    type TestVerifier = ValueGroup<ProjectivePoint>;

    vsss_fixed_array_impl!(FixedVsssForTest, FixedPedersenResultForTest, 2, 3);

    #[test]
    fn fixed_array_macro_generates_shamir_and_pedersen_result_impls() {
        let mut rng = StdRng::from_seed([0x61u8; 32]);
        let secret = IdentifierPrimeField(Scalar::from(77u64));
        let shares =
            FixedVsssForTest::<TestShare, TestVerifier>::split_secret(2, 3, &secret, &mut rng)
                .unwrap();
        assert_eq!(shares.combine(), Ok(secret));

        let blinder = IdentifierPrimeField(Scalar::from(12u64));
        let options = PedersenOptions {
            secret: &secret,
            blinder: Some(blinder),
            secret_generator: Some(TestVerifier::generator()),
            blinder_generator: Some(ValueGroup(ProjectivePoint::GENERATOR * Scalar::from(2u64))),
        };
        let result =
            FixedVsssForTest::<TestShare, TestVerifier>::split_secret_with_blind_verifiers(
                2, 3, &options, &mut rng,
            )
            .unwrap();

        assert_eq!(result.blinder(), &blinder);
        assert_eq!(result.secret_shares().combine(), Ok(secret));
        assert_eq!(result.blinder_shares().combine(), Ok(blinder));
        assert_eq!(result.feldman_verifier_set().len(), 3);
        assert_eq!(result.pedersen_verifier_set().len(), 4);
    }
}
