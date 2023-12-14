use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::lib::{fmt, vec, Box, Debug, String, TryFromIntError};

#[derive(Debug)]
pub enum Error {
    JsonError(serde_json::Error),
    NumError(TryFromIntError),
    FlushError(anyhow::Error),
    ReadError(anyhow::Error),
    WriteError(anyhow::Error),
    WriteZero,
    UnexpectedEof,
    Eof,
    HttpError(u16, String),
    BodyExpected(RequestType),
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JsonError(je) => write!(f, "Malformed JSON - {je}"),
            Self::NumError(ne) => write!(f, "Integer converions failed - {ne}"),
            Self::FlushError(e) => write!(f, "Flush failed - {e}"),
            Self::ReadError(e) => write!(f, "Read failed - {e}"),
            Self::WriteError(e) => write!(f, "Write failed - {e}"),
            Self::WriteZero => write!(
                f,
                "Failed while writing the entire buffer - write() returned Ok(0)"
            ),
            Self::UnexpectedEof => write!(f, "Unexpected EOF while filling the buffer"),
            Self::Eof => write!(f, "Reached end of file"),
            Self::HttpError(status, body) => write!(f, "HTTP error code: {status} - {body}"),
            Self::BodyExpected(rt) => write!(
                f,
                "Request type {:#?} expects a body, but it was not provided",
                rt
            ),
        }
    }
}

impl From<Error> for crate::Error {
    fn from(e: Error) -> Self {
        Self::CP(e)
    }
}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::JsonError(e)
    }
}

impl From<TryFromIntError> for Error {
    fn from(e: TryFromIntError) -> Self {
        Self::NumError(e)
    }
}

pub trait Write {
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
}

pub trait Read {
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
}

pub trait Connection: Write + Read {}

#[cfg(feature = "std")]
pub mod unix {
    use std::io::{Read as IoRead, Write as IoWrite};

    use anyhow::anyhow;

    use super::{Connection, Error, Read, Write};

    pub struct UnixConnection(pub std::os::unix::net::UnixStream);

    impl Write for UnixConnection {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
            self.0.write(buf).map_err(|e| Error::WriteError(anyhow!(e)))
        }

        fn flush(&mut self) -> Result<(), Error> {
            self.0.flush().map_err(|e| Error::FlushError(anyhow!(e)))
        }
    }

    impl Read for UnixConnection {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
            self.0.read(buf).map_err(|e| Error::ReadError(anyhow!(e)))
        }
    }

    impl Connection for UnixConnection {}
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    GET,
    POST,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Request {
    pub endpoint: String,
    pub method: HttpMethod,
    pub body: Value,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Response {
    pub status: u16,
    pub body: String,
}

impl Response {
    pub fn is_success(&self) -> bool {
        self.status >= 200 && self.status <= 299
    }
}

#[derive(Copy, Clone, Debug)]
pub enum RequestType {
    Auth,
    Attest,
    Key,
}

pub trait ProxyRequest {
    fn make(
        &self,
        proxy: &mut Proxy,
        req_type: RequestType,
        body: Option<&Value>,
    ) -> Result<Option<String>, Error>;
}

pub struct Proxy {
    conn: Box<dyn Connection>,
}

impl Proxy {
    pub fn new(conn: Box<dyn Connection>) -> Self {
        Proxy { conn }
    }

    pub fn write_json(&mut self, json: &Value) -> Result<(), Error> {
        let buf = serde_json::to_vec(json)?;

        let len: u32 = buf.len().try_into()?;
        let buf_len = u32::to_ne_bytes(len);

        self.write_all(&buf_len)?;
        self.write_all(&buf)?;

        self.flush()?;

        Ok(())
    }

    pub fn read_json(&mut self) -> Result<Value, Error> {
        let mut buf_len = [0u8; 4];

        self.read_exact(&mut buf_len)?;

        let len: usize = u32::from_ne_bytes(buf_len).try_into()?;
        let mut buf = vec![0u8; len];

        self.read_exact(&mut buf)?;

        let json = serde_json::from_slice(&buf)?;

        Ok(json)
    }
}

impl Write for Proxy {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.conn.write(buf)
    }

    fn flush(&mut self) -> Result<(), Error> {
        self.conn.flush()
    }
}

impl Read for Proxy {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.conn.read(buf)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    struct Buffer {
        vec: Vec<u8>,
    }

    impl Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
            self.vec.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> Result<(), Error> {
            Ok(())
        }
    }

    impl Read for Buffer {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
            let len = std::cmp::min(buf.len(), self.vec.len());
            let data = self.vec.drain(0..len);
            buf[..].clone_from_slice(data.as_slice());
            Ok(len)
        }
    }

    impl Connection for Buffer {}

    #[test]
    fn test_proxy() {
        let conn = Buffer { vec: Vec::new() };
        let mut proxy = Proxy::new(Box::new(conn));

        let req = Request {
            endpoint: "/test".to_string(),
            method: HttpMethod::GET,
            body: json!("body".to_string()),
        };

        proxy.write_json(&json!(req)).unwrap();
        let data = proxy.read_json().unwrap();
        let req2: Request = serde_json::from_value(data).unwrap();

        assert_eq!(req, req2);
    }
}
