// SPDX-License-Identifier: Apache-2.0

mod limebroker;

use super::Backend;

use std::str::FromStr;

use anyhow::{anyhow, Result};
use raclients::frontend::unix::UnixConnection;

#[derive(Clone, Debug)]
pub enum BackendServer {
    Limebroker,
}

impl FromStr for BackendServer {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "limebroker" => Ok(Self::Limebroker),
            _ => Err(anyhow!("invalid backend server selection")),
        }
    }
}

impl Backend for BackendServer {
    fn attest(&self, conn: UnixConnection, url: String) -> Result<()> {
        match self {
            Self::Limebroker => limebroker::attest(conn, url),
        }
    }
}
