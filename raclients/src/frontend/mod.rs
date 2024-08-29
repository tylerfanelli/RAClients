// SPDX-License-Identifier: Apache-2.0

#[cfg(all(not(feature = "std"), feature = "alloc"))]
extern crate alloc;

pub(crate) mod lib {
    #[cfg(all(feature = "std", not(feature = "alloc")))]
    pub use std::*;

    #[cfg(all(not(feature = "std"), feature = "alloc"))]
    pub use super::alloc::*;
}

mod proxy;

pub use proxy::*;
