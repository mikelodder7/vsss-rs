/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! A guard for secret buffers.
//!
//! [`Secret`] wipes what it holds when it is dropped, on every exit path
//! including `?` early returns. Without the `zeroize` feature there is
//! nothing to wipe with, so it is a plain pass-through wrapper.

/// Wipes the wrapped value on drop.
#[cfg(feature = "zeroize")]
pub(crate) type Secret<T> = zeroize::Zeroizing<T>;

/// Holds a secret value. Without the `zeroize` feature it is not wiped.
#[cfg(not(feature = "zeroize"))]
pub(crate) struct Secret<T>(T);

#[cfg(not(feature = "zeroize"))]
impl<T> Secret<T> {
    /// Guard `value`.
    pub(crate) fn new(value: T) -> Self {
        Self(value)
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T> core::ops::Deref for Secret<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T> core::ops::DerefMut for Secret<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn secret_passes_reads_and_writes_through() {
        let mut secret = Secret::new([1u8, 2, 3]);
        assert_eq!(*secret, [1, 2, 3]);
        secret[1] = 9;
        assert_eq!(secret.as_slice(), &[1, 9, 3]);
    }

    #[cfg(feature = "zeroize")]
    #[test]
    fn secret_wipes_on_request_under_zeroize() {
        use zeroize::Zeroize;
        let mut secret = Secret::new(std::vec![7u8; 4]);
        secret.zeroize();
        assert!(secret.is_empty());
    }
}
