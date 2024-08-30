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
        vec::Vec,
    };
}

#[cfg(all(feature = "std", not(feature = "alloc")))]
pub mod unix;

mod proxy;

pub use proxy::*;

use lib::*;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Deserialize, Serialize)]
pub enum NegotiationParam {
    RsaPubkeyN,
    RsaPubkeyE,
    Bytes(Vec<u8>),
}

pub trait FrontendClient: RacProxyConnection {
    fn negotiation(&mut self) -> Result<Vec<NegotiationParam>, Error> {
        let buf = self.read_vec()?;

        serde_json::from_slice(&buf).map_err(|e| Error::Other(e.to_string()))
    }

    fn evidence(&mut self, json: Map<String, Value>) -> Result<(), Error> {
        let buf = serde_json::to_vec(&json).map_err(|e| {
            Error::Other(format!(
                "unable to convert negotiation params to JSON (bytes): {}",
                e
            ))
        })?;

        self.write_vec(buf)
    }

    fn secret(&mut self) -> Result<Value, Error> {
        let buf = self.read_vec()?;

        serde_json::from_slice(&buf).map_err(|e| Error::Other(e.to_string()))
    }
}

pub trait FrontendServer: RacProxyConnection {
    fn negotiation(&mut self, params: Vec<NegotiationParam>) -> Result<(), Error> {
        let buf = serde_json::to_vec(&params).map_err(|e| {
            Error::Other(format!(
                "unable to convert negotiation params to JSON (bytes): {}",
                e
            ))
        })?;

        self.write_vec(buf)
    }

    fn evidence(&mut self) -> Result<Map<String, Value>, Error> {
        let buf = self.read_vec()?;

        serde_json::from_slice(&buf).map_err(|e| Error::Other(e.to_string()))
    }

    fn secret(&mut self, value: Value) -> Result<(), Error> {
        let buf = serde_json::to_vec(&value).map_err(|e| {
            Error::Other(format!(
                "unable to convert negotiation params to JSON (bytes): {}",
                e
            ))
        })?;

        self.write_vec(buf)
    }
}
