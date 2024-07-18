// Support using this crate without the standard library
#![cfg_attr(not(feature = "std"), no_std)]
// To handle std/no_std we re-include some items already included by std.
// clippy (nightly) prints warnings about that, so let's silence them
// to not complicate the inclusion.
#![cfg_attr(feature = "std", allow(unused_imports))]
// As long as there is a memory allocator, we can still use this crate
// without the rest of the standard library by using the `alloc` crate
#[cfg(feature = "alloc")]
extern crate alloc;

/// A facade around all the types we need from the `std`, `core`, and `alloc`
/// crates. This avoids elaborate import wrangling having to happen in every
/// module.
mod lib {
    mod core {
        #[cfg(not(feature = "std"))]
        pub use core::*;
        #[cfg(feature = "std")]
        pub use std::*;
    }

    mod alloc {
        #[cfg(feature = "std")]
        pub use std::*;

        #[cfg(all(feature = "alloc", not(feature = "std")))]
        pub use ::alloc::*;
    }

    // alloc modules (re-exported by `std` when have the standard library)
    pub use self::alloc::{
        boxed::Box,
        string::{String, ToString},
        vec,
        vec::Vec,
    };
    // core modules (re-exported by `std` when have the standard library)
    pub use self::core::{
        fmt::{self, Debug, Display},
        num::TryFromIntError,
    };
}

pub mod client_proxy;
pub mod client_registration;
#[cfg(feature = "in_proxy")]
pub mod in_proxy;
#[cfg(feature = "in_svsm")]
pub mod in_svsm;

#[derive(Debug)]
pub enum Error {
    // Errors related to client_session
    #[cfg(feature = "in_svsm")]
    CPS(in_proxy::client_session::Error),
    // Errors related to client_session
    #[cfg(feature = "in_proxy")]
    CS(in_svsm::client_session::Error),
    // Errors related to client_proxy
    CP(client_proxy::Error),
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl lib::fmt::Display for Error {
    fn fmt(&self, f: &mut lib::fmt::Formatter<'_>) -> lib::fmt::Result {
        match self {
            #[cfg(feature = "in_svsm")]
            Self::CPS(e) => write!(f, "Session error: {e}"),
            #[cfg(feature = "in_proxy")]
            Self::CS(e) => write!(f, "Session error: {e}"),
            Self::CP(e) => write!(f, "Proxy error: {e}"),
        }
    }
}
