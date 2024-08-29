// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(all(not(feature = "std"), feature = "alloc"), no_std)]

#[cfg(feature = "frontend")]
pub mod frontend;
