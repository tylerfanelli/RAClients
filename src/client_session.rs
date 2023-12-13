use base64ct::{Base64, Encoding};
use kbs_types::{Attestation, Challenge, Request, Response as KbsResponse, Tee, TeePubKey};
use num_bigint::BigUint;
use serde_json::{json, Value};

use crate::lib::{fmt, Debug, String, ToString, Vec};

#[cfg(feature = "keybroker")]
pub mod keybroker;

#[derive(Debug)]
pub enum Error {
    JsonError(serde_json::Error),
    HexError(hex::FromHexError),
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JsonError(je) => write!(f, "Malformed JSON - {je}"),
            Self::HexError(he) => write!(f, "Converion to hex failed - {he}"),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::JsonError(e)
    }
}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Self::HexError(e)
    }
}

impl From<Error> for crate::Error {
    fn from(e: Error) -> Self {
        Self::CS(e)
    }
}

pub trait ClientTee {
    fn tee(&self) -> Tee;
    fn extra_params(&self) -> Value;
    fn evidence(&self) -> Value;
}

pub struct ClientSession {}

impl Default for ClientSession {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientSession {
    pub fn new() -> Self {
        ClientSession {}
    }

    pub fn request(&self, tee: &dyn ClientTee) -> Result<Value, Error> {
        let request = Request {
            version: "0.1.0".to_string(),
            tee: tee.tee(),
            extra_params: json!(tee.extra_params()).to_string(),
        };

        Ok(json!(request))
    }

    pub fn challenge(&mut self, data: Value) -> Result<String, Error> {
        let challenge: Challenge = serde_json::from_value(data)?;

        Ok(challenge.nonce)
    }

    pub fn attestation(
        &self,
        k_mod: String,
        k_exp: String,
        tee: &dyn ClientTee,
    ) -> Result<Value, Error> {
        let tee_pubkey = TeePubKey {
            kty: "RSA".to_string(),
            alg: "RSA".to_string(),
            k_mod,
            k_exp,
        };

        let attestation = Attestation {
            tee_pubkey,
            tee_evidence: tee.evidence().to_string(),
        };

        Ok(json!(attestation))
    }

    pub fn secret(&self, data: String) -> Result<Vec<u8>, Error> {
        let resp: KbsResponse = serde_json::from_str(&data)?;

        // TODO: consider using decode_to_slice() to avoid heap allocation
        Ok(hex::decode(resp.ciphertext)?)
    }

    pub fn encode_key(key: &BigUint) -> Result<String, Error> {
        let bytes = key.to_bytes_be();
        Ok(Base64::encode_string(&bytes))
    }
}
