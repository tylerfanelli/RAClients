// SPDX-License-Identifier: Apache-2.0

pub mod server;

use anyhow::Result;
use raclients::frontend::unix::UnixConnection;

pub trait Backend {
    fn attest(&self, conn: UnixConnection, url: String) -> Result<()>;
}
