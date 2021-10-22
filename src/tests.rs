/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
#[cfg(all(not(feature = "alloc"), not(feature = "std")))]
mod no_std;
#[cfg(any(feature = "alloc", feature = "std"))]
mod standard;
pub mod utils;
