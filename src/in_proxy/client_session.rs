use base64ct::{Base64, Encoding};
pub use kbs_types::{Attestation, Challenge, Request, Response, Tee, TeePubKey};
use num_bigint::BigUint;
use rand_chacha::rand_core::SeedableRng;
use rdrand::RdSeed;
use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};

use crate::{
    client_proxy,
    client_proxy::Proxy,
    in_proxy::clients::{
        AttestationKey, AttestationRequest, AttestationResponse, NegotiationHash, NegotiationKey,
        NegotiationParam, NegotiationRequest, NegotiationResponse,
    },
    lib::{fmt, Box, Debug, String, ToString, Vec},
};

#[derive(Debug)]
pub enum Error {
    JsonError(serde_json::Error),
    HexError(hex::FromHexError),
    ProxyError(client_proxy::Error),
    ProtocolError(String),
    RSAError(rsa::Error),
    AttestationFailed,
    VersionUnsupported,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JsonError(je) => write!(f, "Malformed JSON - {je}"),
            Self::HexError(he) => write!(f, "Converion to hex failed - {he}"),
            Self::ProxyError(pe) => write!(f, "Proxy error - {pe}"),
            Self::ProtocolError(pe) => write!(f, "Protocol error - {pe}"),
            Self::RSAError(re) => write!(f, "RSA error - {re}"),
            Self::AttestationFailed => write!(f, "Remote attestation failed"),
            Self::VersionUnsupported => write!(f, "Protocol version not supported"),
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

impl From<rsa::Error> for Error {
    fn from(e: rsa::Error) -> Self {
        Self::RSAError(e)
    }
}

impl From<client_proxy::Error> for Error {
    fn from(e: client_proxy::Error) -> Self {
        Self::ProxyError(e)
    }
}

impl From<Error> for crate::Error {
    fn from(e: Error) -> Self {
        Self::CPS(e)
    }
}

pub struct ClientSessionGuest {
    priv_key: Option<RsaPrivateKey>,
    pub_key: Option<RsaPublicKey>,
}

impl Default for ClientSessionGuest {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientSessionGuest {
    pub fn new() -> Self {
        ClientSessionGuest {
            priv_key: None,
            pub_key: None,
        }
    }

    pub fn negotiation(&mut self, proxy: &mut Proxy, report_data: &mut [u8]) -> Result<(), Error> {
        let req = NegotiationRequest {
            version: "0.1.0".to_string(),
        };

        log::debug!("Sending negotiation request to the proxy...");
        proxy.write_json(&json!(req))?;
        log::debug!("Receiving negotiation response from the proxy...");
        let data = proxy.read_json()?;

        let resp: NegotiationResponse = serde_json::from_value(data)?;

        let mut hasher = match resp.hash {
            NegotiationHash::SHA256 => {
                // TODO: add specific error types
                return Err(Error::ProtocolError("Hash not supported".to_string()));
            }
            NegotiationHash::SHA512 => Box::new(Sha512::new()),
        };

        for param in resp.params {
            match param {
                NegotiationParam::Key(key) => {
                    let bit_size = match key {
                        NegotiationKey::RSA2048 => 2048,
                        NegotiationKey::RSA3072 => 3072,
                        NegotiationKey::RSA4096 => 4096,
                        _ => return Err(Error::ProtocolError("Key not supported".to_string())),
                    };

                    log::debug!("Setting up random generator...");
                    // TODO: check if we can use new() on SVSM now
                    let rdrand = unsafe { RdSeed::new_unchecked() };
                    let mut rng = rand_chacha::ChaChaRng::from_rng(rdrand).unwrap();

                    log::debug!("Generating RSA keys...");
                    let priv_key = RsaPrivateKey::new(&mut rng, bit_size)?;
                    let pub_key = RsaPublicKey::from(&priv_key);
                    log::debug!("Generating RSA keys... Done");

                    hasher.update(Self::encode_key(pub_key.n())?.as_bytes());
                    hasher.update(Self::encode_key(pub_key.e())?.as_bytes());

                    self.priv_key = Some(priv_key);
                    self.pub_key = Some(pub_key);
                }
                NegotiationParam::Extra(extra) => {
                    hasher.update(extra.as_bytes());
                }
            }
        }

        hasher.finalize_into(report_data.into());
        Ok(())
    }

    pub fn attestation(&self, proxy: &mut Proxy, report: &[u8]) -> Result<String, Error> {
        // TODO: handle errors
        let pub_key = self.pub_key.as_ref().unwrap();
        let priv_key = self.priv_key.as_ref().unwrap();

        let req = AttestationRequest {
            // TODO: reference-kbs specific, convert to Base64
            evidence: hex::encode(report),
            key: Some(AttestationKey::RSA {
                n: Self::encode_key(pub_key.n())?,
                e: Self::encode_key(pub_key.e())?,
            }),
        };

        log::debug!("Sending attestation request to the proxy...");
        proxy.write_json(&json!(req))?;
        log::debug!("Receiving attestation response from the proxy...");
        let data = proxy.read_json()?;

        let resp: AttestationResponse = serde_json::from_value(data)?;

        if !resp.success {
            return Err(Error::AttestationFailed);
        }

        // TODO: reference-kbs specific, convert to Base64
        let secret_encrypted = hex::decode(resp.secret.unwrap())?;
        log::debug!("Decrypting the secret...");
        let secret = priv_key.decrypt(rsa::Pkcs1v15Encrypt, &secret_encrypted)?;

        Ok(String::from_utf8(secret).unwrap())
    }

    fn encode_key(key: &BigUint) -> Result<String, Error> {
        let bytes = key.to_bytes_be();
        Ok(Base64::encode_string(&bytes))
    }
}

pub struct ClientSessionHost {}

impl Default for ClientSessionHost {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientSessionHost {
    pub fn new() -> Self {
        ClientSessionHost {}
    }

    pub fn negotiation_request(&mut self, proxy: &mut Proxy) -> Result<(), Error> {
        let data = proxy.read_json()?;

        let req: NegotiationRequest = serde_json::from_value(data)?;

        Ok(())
    }

    pub fn negotiation_response(
        &mut self,
        proxy: &mut Proxy,
        hash: NegotiationHash,
        params: Vec<NegotiationParam>,
    ) -> Result<(), Error> {
        let resp = NegotiationResponse { hash, params };

        proxy.write_json(&json!(resp))?;

        Ok(())
    }

    pub fn attestation_request(
        &mut self,
        proxy: &mut Proxy,
    ) -> Result<(String, AttestationKey), Error> {
        let data = proxy.read_json()?;

        let req: AttestationRequest = serde_json::from_value(data)?;
        let key = req
            .key
            .ok_or(Error::ProtocolError("Key needed".to_string()))?;

        // TODO: return Base64 object
        Ok((req.evidence, key))
    }

    pub fn attestation_response(
        &mut self,
        proxy: &mut Proxy,
        success: bool,
        // TODO: require Base64 object
        secret: String,
    ) -> Result<(), Error> {
        let resp = AttestationResponse {
            success,
            secret: Some(secret),
        };

        proxy.write_json(&json!(resp))?;

        Ok(())
    }
}
