// SPDX-License-Identifier: Apache-2.0

use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
};

use raclients::frontend::{Error, RacProxyConnection, RacProxyRead, RacProxyWrite};

pub struct UnixConnection(pub UnixStream);

impl RacProxyRead for UnixConnection {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.0.read(buf).map_err(|e| Error::Other(e.to_string()))
    }
}

impl RacProxyWrite for UnixConnection {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.0.write(buf).map_err(|e| Error::Other(e.to_string()))
    }

    fn flush(&mut self) -> Result<(), Error> {
        self.0.flush().map_err(|e| Error::Other(e.to_string()))
    }
}

impl RacProxyConnection for UnixConnection {}
