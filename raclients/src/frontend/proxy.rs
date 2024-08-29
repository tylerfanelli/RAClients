// SPDX-License-Identifier: Apache-2.0

use super::lib::{
    alloc::{
        string::{String, ToString},
        vec,
    },
    core::{
        fmt::{self, Display, Formatter},
        num::TryFromIntError,
    },
    format, Vec,
};

#[derive(Debug)]
pub enum Error {
    Eof,
    UnexpectedEof,
    WriteZero,
    Other(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eof => write!(f, "End of file encountered"),
            Self::UnexpectedEof => write!(f, "Unexpected end of file encountered"),
            Self::WriteZero => write!(f, "Zero bytes written"),
            Self::Other(s) => write!(f, "{}", &s),
        }
    }
}

pub trait RacProxyRead {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error>;

    fn read_exact(&mut self, mut buf: &mut [u8]) -> Result<(), Error> {
        let mut read = 0;
        while !buf.is_empty() {
            match self.read(buf) {
                Ok(0) => break,
                Ok(n) => {
                    let tmp = buf;
                    buf = &mut tmp[n..];
                    read += n;
                }
                Err(e) => return Err(e),
            }
        }
        if !buf.is_empty() {
            if read == 0 {
                Err(Error::Eof)
            } else {
                Err(Error::UnexpectedEof)
            }
        } else {
            Ok(())
        }
    }

    fn read_vec(&mut self) -> Result<Vec<u8>, Error> {
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

        Ok(buf)
    }
}

pub trait RacProxyWrite {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error>;
    fn flush(&mut self) -> Result<(), Error>;

    fn write_all(&mut self, mut buf: &[u8]) -> Result<(), Error> {
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(0) => {
                    return Err(Error::WriteZero);
                }
                Ok(n) => buf = &buf[n..],
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn write_vec(&mut self, vec: Vec<u8>) -> Result<(), Error> {
        let len_bytes = {
            let len: u32 = vec
                .len()
                .try_into()
                .map_err(|_| Error::Other("cannot convert param bytes to u32".to_string()))?;

            u32::to_ne_bytes(len)
        };

        self.write_all(&len_bytes)?;
        self.write_all(&vec)?;

        self.flush()
    }
}

pub trait RacProxyConnection: RacProxyRead + RacProxyWrite {}
