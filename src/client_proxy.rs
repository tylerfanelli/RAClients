use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::lib::{fmt, vec, Box, Debug, String, TryFromIntError};

#[derive(Debug)]
pub enum Error {
    JsonError(serde_json::Error),
    NumError(TryFromIntError),
    FlushError,
    ReadError,
    WriteError,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JsonError(je) => write!(f, "Malformed JSON - {je}"),
            Self::NumError(ne) => write!(f, "Integer converions failed - {ne}"),
            Self::FlushError => write!(f, "Flush failed"),
            Self::ReadError => write!(f, "Read failed"),
            Self::WriteError => write!(f, "Write failed"),
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
}

pub trait Read {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error>;
}

pub trait Connection: Write + Read {}

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

        let ret = self.write(&buf_len)?;
        if ret != buf_len.len() {
            return Err(Error::WriteError);
        }

        let ret = self.write(&buf)?;
        if ret != buf.len() {
            return Err(Error::WriteError);
        }

        self.flush()?;

        Ok(())
    }

    pub fn read_json(&mut self) -> Result<Value, Error> {
        let mut buf_len = [0u8; 4];

        let ret = self.read(&mut buf_len)?;
        if ret != buf_len.len() {
            return Err(Error::ReadError);
        }

        let len: usize = u32::from_ne_bytes(buf_len).try_into()?;
        let mut buf = vec![0u8; len];

        let ret = self.read(&mut buf)?;
        if ret != buf.len() {
            return Err(Error::ReadError);
        }

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
