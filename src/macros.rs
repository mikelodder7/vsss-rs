#[macro_export]
/// Implements all the VSSS traits for a fixed array.
macro_rules! vsss_fixed_array_impl {
    ($name:ident, $pedersen_result:ident, $threshold:expr, $shares:expr) => {
        #[derive(Debug, Copy, Clone)]
        /// A VSSS implementation.
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

        /// A Pedersen result for static arrays.
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

/// The arithmetic shared by the binary fields `GF(2^K)` ([`Gf16`], [`Gf256`]),
/// generated from `K` and the field's constant-time multiplication `$mul`:
/// the inverse, exponentiation, the `ff::Field` impl, the four division
/// impls, and the `ctutils`/`subtle` constant-time traits. Every routine
/// runs a fixed number of multiplications, independent of the operands.
macro_rules! binary_field {
    ($name:ident, $mul:ident, $k:literal, $mask:literal) => {
        impl $name {
            /// The multiplicative inverse, or zero for zero: `a^(2^K − 2)` by
            /// the addition chain `z ← z²·a` repeated `K − 2` times from
            /// `z = a`, then one squaring. Runs in constant time;
            /// [`ff::Field::invert`] reports the zero case.
            fn inverse_or_zero(self) -> Self {
                let mut z = self.0;
                for _ in 0..$k - 2 {
                    z = $mul(z, z);
                    z = $mul(z, self.0);
                }
                Self($mul(z, z))
            }

            /// Raise the element to the power of `exp`, by square-and-multiply
            /// over all eight exponent bits, most significant first, in
            /// constant time.
            pub fn pow(&self, exp: u8) -> Self {
                let mut result = 1u8;
                for i in (0..8).rev() {
                    result = $mul(result, result);
                    let tmp = $mul(result, self.0);
                    let allow = ::ctutils::CtEq::ct_eq(&((exp >> i) & 1), &1);
                    ::ctutils::CtAssign::ct_assign(&mut result, &tmp, allow);
                }
                Self(result)
            }

            /// The square root `a^(2^(K−1))`, by `K − 1` squarings. Squaring is
            /// a bijection of `GF(2^K)`, so every element has exactly one.
            fn frobenius_root(self) -> Self {
                let mut r = self.0;
                for _ in 0..$k - 1 {
                    r = $mul(r, r);
                }
                Self(r)
            }
        }

        impl ::ff::Field for $name {
            const ZERO: Self = Self(0);
            const ONE: Self = Self(1);

            /// Uniform over the whole field, zero included. An earlier
            /// sampler forced the low bit, which leaked entropy out of the
            /// polynomial coefficients used by Shamir secret sharing (audit
            /// finding #1).
            fn try_random<R: ::rand_core::TryRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
                rng.try_next_u32().map(|v| Self(v as u8 & $mask))
            }

            fn square(&self) -> Self {
                self * self
            }

            fn double(&self) -> Self {
                self + self
            }

            fn invert(&self) -> ::subtle::CtOption<Self> {
                ::subtle::CtOption::new(
                    self.inverse_or_zero(),
                    $crate::util::CtIsNotZero::ct_is_not_zero(&self.0).into(),
                )
            }

            /// Every element of a binary field is a square; see
            /// `frobenius_root`. Defined unless `div = 0 ≠ num`.
            fn sqrt_ratio(num: &Self, div: &Self) -> (::subtle::Choice, Self) {
                let root = (*num / *div).frobenius_root();
                let defined = $crate::util::CtIsZero::ct_is_zero(&num.0)
                    | $crate::util::CtIsNotZero::ct_is_not_zero(&div.0);
                (defined.into(), root)
            }
        }

        /// Division by zero yields zero; use [`ff::Field::invert`] to detect
        /// a zero divisor.
        impl ::core::ops::Div for $name {
            type Output = Self;

            fn div(self, rhs: Self) -> Self {
                self * rhs.inverse_or_zero()
            }
        }

        /// See the by-value [`Div`](core::ops::Div) impl.
        impl ::core::ops::Div<&$name> for $name {
            type Output = $name;

            fn div(self, rhs: &$name) -> $name {
                self / *rhs
            }
        }

        /// See the by-value [`Div`](core::ops::Div) impl.
        impl ::core::ops::Div<$name> for &$name {
            type Output = $name;

            fn div(self, rhs: $name) -> $name {
                *self / rhs
            }
        }

        /// See the by-value [`Div`](core::ops::Div) impl.
        impl ::core::ops::Div<&$name> for &$name {
            type Output = $name;

            fn div(self, rhs: &$name) -> $name {
                *self / *rhs
            }
        }

        /// Division by zero yields zero.
        impl ::core::ops::DivAssign for $name {
            fn div_assign(&mut self, rhs: Self) {
                *self = *self / rhs;
            }
        }

        /// Division by zero yields zero.
        impl ::core::ops::DivAssign<&$name> for $name {
            fn div_assign(&mut self, rhs: &$name) {
                *self = *self / *rhs;
            }
        }

        impl ::ctutils::CtEq for $name {
            fn ct_eq(&self, other: &Self) -> ::ctutils::Choice {
                ::ctutils::CtEq::ct_eq(&self.0, &other.0)
            }
        }

        impl ::ctutils::CtSelect for $name {
            fn ct_select(&self, other: &Self, choice: ::ctutils::Choice) -> Self {
                Self(::ctutils::CtSelect::ct_select(&self.0, &other.0, choice))
            }
        }

        impl ::subtle::ConstantTimeEq for $name {
            fn ct_eq(&self, other: &Self) -> ::subtle::Choice {
                ::ctutils::CtEq::ct_eq(self, other).into()
            }
        }

        impl ::subtle::ConditionallySelectable for $name {
            fn conditional_select(a: &Self, b: &Self, choice: ::subtle::Choice) -> Self {
                ::ctutils::CtSelect::ct_select(a, b, choice.into())
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
