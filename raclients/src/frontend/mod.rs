// SPDX-License-Identifier: Apache-2.0

#[cfg(all(not(feature = "std"), feature = "alloc"))]
extern crate alloc;

pub(crate) mod lib {
    pub mod core {
        #[cfg(all(feature = "std", not(feature = "alloc")))]
        pub use std::*;

        #[cfg(all(not(feature = "std"), feature = "alloc"))]
        pub use core::*;
    }

    pub mod alloc {
        #[cfg(all(feature = "std", not(feature = "alloc")))]
        pub use std::*;

        #[cfg(all(not(feature = "std"), feature = "alloc"))]
        pub use super::super::alloc::*;
    }

    pub use self::alloc::{
        format,
        string::{String, ToString},
        vec,
        vec::Vec,
    };

    pub use self::core::num::TryFromIntError;
}

mod proxy;

pub use proxy::*;

use lib::*;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Deserialize, Serialize)]
pub enum NegotiationParam {
    RsaPubkeyN,
    RsaPubkeyE,
    Str(String),
}

pub trait FrontendClient: RacProxyConnection {
    fn negotiation(&mut self) -> Result<Vec<NegotiationParam>, Error> {
        let len: usize = {
            let mut bytes = [0u8; 4];
            self.read_exact(&mut bytes)?;

            u32::from_ne_bytes(bytes)
                .try_into()
                .map_err(|e: TryFromIntError| {
                    Error::Other(format!("unable to convert response length to usize: {}", e))
                })?
        };

        let mut buf = vec![0u8; len];
        self.read_exact(&mut buf)?;

        serde_json::from_slice(&buf).map_err(|e| Error::Other(e.to_string()))
    }
}

pub trait FrontendServer: RacProxyConnection {
    fn evidence(&mut self, params: Vec<NegotiationParam>) -> Result<Map<String, Value>, Error> {
        let buf = serde_json::to_vec(&params).map_err(|e| {
            Error::Other(format!(
                "unable to convert negotiation params to JSON (bytes): {}",
                e
            ))
        })?;

        let len_bytes = {
            let len: u32 = buf
                .len()
                .try_into()
                .map_err(|_| Error::Other("cannot convert param bytes to u32".to_string()))?;

            u32::to_ne_bytes(len)
        };

        self.write_all(&len_bytes)?;
        self.write_all(&buf)?;

        self.flush()?;

        let len: usize = {
            let mut bytes = [0u8; 4];
            self.read_exact(&mut bytes)?;

            u32::from_ne_bytes(bytes)
                .try_into()
                .map_err(|e: TryFromIntError| {
                    Error::Other(format!("unable to convert response length to usize: {}", e))
                })?
        };

        let mut buf = vec![0u8; len];
        self.read_exact(&mut buf)?;

        serde_json::from_slice(&buf).map_err(|e| Error::Other(e.to_string()))
    }
}
