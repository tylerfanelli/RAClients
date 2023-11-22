use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    lib::{vec, String, TryFromIntError},
    KBCError,
};

#[derive(Debug)]
pub enum CPError {
    JsonError(serde_json::Error),
    NumError(TryFromIntError),
    FlushError,
    ReadError,
    ReadPayloadTooShort,
    WriteError,
}

impl From<CPError> for KBCError {
    fn from(e: CPError) -> Self {
        Self::CP(e)
    }
}
impl From<serde_json::Error> for CPError {
    fn from(e: serde_json::Error) -> Self {
        Self::JsonError(e)
    }
}

impl From<TryFromIntError> for CPError {
    fn from(e: TryFromIntError) -> Self {
        Self::NumError(e)
    }
}

pub trait Write {
    fn write(&mut self, buf: &[u8]) -> Result<usize, CPError>;
    fn flush(&mut self) -> Result<(), CPError>;
}

pub trait Read {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, CPError>;
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
    pub body: String,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Response {
    pub status: u16,
    pub body: String,
}

pub struct Proxy {
    conn: *mut (dyn Connection),
}

impl Proxy {
    pub fn new(conn: *mut dyn Connection) -> Self {
        Proxy { conn }
    }

    pub fn write_json(&mut self, json: &Value) -> Result<(), CPError> {
        let buf = serde_json::to_vec(json)?;

        let len: u32 = buf.len().try_into()?;
        let buf_len = u32::to_ne_bytes(len);

        let ret = self.write(&buf_len)?;
        if ret != buf_len.len() {
            return Err(CPError::WriteError);
        }

        let ret = self.write(&buf)?;
        if ret != buf.len() {
            return Err(CPError::WriteError);
        }

        self.flush()?;

        Ok(())
    }

    pub fn read_json(&mut self) -> Result<Value, CPError> {
        let mut buf_len = [0u8; 4];

        let ret = self.read(&mut buf_len)?;
        if ret != buf_len.len() {
            return Err(CPError::ReadError);
        }

        let len: usize = u32::from_ne_bytes(buf_len).try_into()?;
        let mut buf = vec![0u8; len];

        let ret = self.read(&mut buf)?;
        if ret != buf.len() {
            return Err(CPError::ReadError);
        }

        let json = serde_json::from_slice(&buf)?;

        Ok(json)
    }
}

impl Write for Proxy {
    fn write(&mut self, buf: &[u8]) -> Result<usize, CPError> {
        unsafe { (*self.conn).write(buf) }
    }

    fn flush(&mut self) -> Result<(), CPError> {
        unsafe { (*self.conn).flush() }
    }
}

impl Read for Proxy {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, CPError> {
        unsafe { (*self.conn).read(buf) }
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
        fn write(&mut self, buf: &[u8]) -> Result<usize, CPError> {
            self.vec.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> Result<(), CPError> {
            Ok(())
        }
    }

    impl Read for Buffer {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, CPError> {
            let len = std::cmp::min(buf.len(), self.vec.len());
            let data = self.vec.drain(0..len);
            buf[..].clone_from_slice(&data.as_slice());
            Ok(len)
        }
    }

    impl Connection for Buffer {}

    #[test]
    fn test_proxy() {
        let mut conn = Buffer { vec: Vec::new() };
        let mut proxy = Proxy::new(&mut conn);

        let req = Request {
            endpoint: "/test".to_string(),
            method: HttpMethod::GET,
            body: "body".to_string(),
        };

        proxy.write_json(&json!(req)).unwrap();
        let data = proxy.read_json().unwrap();
        let req2: Request = serde_json::from_value(data).unwrap();

        assert_eq!(req, req2);
    }
}
