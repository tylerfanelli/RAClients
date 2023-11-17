use kbs_types::{Attestation, Challenge, Request, SnpAttestation, SnpRequest, Tee, TeePubKey};
use num_bigint::BigUint;
use serde_json::{json, Value};

use crate::{
    lib::{fmt, String, ToString},
    KBSClientError,
};

#[derive(Debug)]
pub enum CSError {
    JsonError(serde_json::Error),
    HexError(hex::FromHexError),
}

impl From<serde_json::Error> for CSError {
    fn from(e: serde_json::Error) -> Self {
        Self::JsonError(e)
    }
}

impl From<hex::FromHexError> for CSError {
    fn from(e: hex::FromHexError) -> Self {
        Self::HexError(e)
    }
}

impl From<CSError> for KBSClientError {
    fn from(e: CSError) -> Self {
        Self::CS(e)
    }
}

pub trait ClientTee {
    fn tee(&self) -> Tee;
    fn extra_params(&self) -> Value;
    fn evidence(&self) -> Value;
}

pub struct ClientSession {
    session_id: Option<String>,
    nonce: Option<String>,
}

impl Default for ClientSession {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientSession {
    pub fn new() -> Self {
        ClientSession {
            session_id: None,
            nonce: None,
        }
    }

    pub fn set_session_id(&mut self, str: String) {
        self.session_id = Some(str);
    }

    pub fn session_id(&self) -> &Option<String> {
        &self.session_id
    }

    pub fn nonce(&self) -> &Option<String> {
        &self.nonce
    }

    pub fn request(&self, tee: &dyn ClientTee) -> Result<Value, CSError> {
        let request = Request {
            version: "0.1.0".to_string(),
            tee: tee.tee(),
            extra_params: json!(tee.extra_params()).to_string(),
        };

        Ok(json!(request))
    }

    pub fn challenge(&mut self, data: Value) -> Result<(), CSError> {
        let challenge: Challenge = serde_json::from_value(data)?;

        self.nonce = Some(challenge.nonce);

        Ok(())
    }

    pub fn attestation(
        &self,
        k_mod: &BigUint,
        k_exp: &BigUint,
        tee: &dyn ClientTee,
    ) -> Result<Value, CSError> {
        let tee_pubkey = TeePubKey {
            kty: "RSA".to_string(),
            alg: "RSA".to_string(),
            k_mod: k_mod.to_string(),
            k_exp: k_exp.to_string(),
        };

        let attestation = Attestation {
            tee_pubkey,
            tee_evidence: tee.evidence().to_string(),
        };

        Ok(json!(attestation))
    }

    // confidential-containers/kbs provides `Response` payloads, but
    // reference-kbs SNP attested just return a JSON String.
    pub fn secret(&self, data: Value) -> Result<Vec<u8>, CSError> {
        let secret: String = serde_json::from_value(data)?;

        // TODO: consider using decode_to_slice() to avoid heap allocation
        Ok(hex::decode(secret)?)
    }
}

pub enum SnpGeneration {
    Milan,
    Genoa,
}

impl fmt::Display for SnpGeneration {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SnpGeneration::Milan => write!(f, "milan"),
            SnpGeneration::Genoa => write!(f, "genoa"),
        }
    }
}

pub struct ClientTeeSnp {
    request: SnpRequest,
    attestation: SnpAttestation,
}

impl ClientTeeSnp {
    pub fn new(gen: SnpGeneration, workload_id: String) -> Self {
        ClientTeeSnp {
            request: SnpRequest { workload_id },
            attestation: SnpAttestation {
                report: "".to_string(),
                cert_chain: "".to_string(),
                gen: gen.to_string(),
            },
        }
    }

    pub fn update_report(&mut self, report: &[u8]) {
        self.attestation.report = hex::encode(report);
    }
}

impl ClientTee for ClientTeeSnp {
    fn tee(&self) -> Tee {
        Tee::Snp
    }
    fn extra_params(&self) -> Value {
        json!(self.request)
    }
    fn evidence(&self) -> Value {
        json!(self.attestation)
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;

    #[test]
    fn test() {
        let mut snp = ClientTeeSnp::new(SnpGeneration::Milan, "snp-workload".to_string());

        let mut cs = ClientSession::new();
        assert_eq!(*cs.session_id(), None);

        cs.set_session_id("42".to_string());
        assert_eq!(*cs.session_id(), Some("42".to_string()));

        let request = cs.request(&snp).unwrap();
        assert_eq!(
            request,
            json!({
                "version": "0.1.0",
                "tee": "snp",
                "extra-params": json!({"workload_id":"snp-workload"}).to_string(),
            }),
        );

        let challenge = r#"
        {
            "nonce": "424242",
            "extra-params": ""
        }"#;
        cs.challenge(serde_json::from_str(challenge).unwrap())
            .unwrap();
        assert_eq!(*cs.nonce(), Some("424242".to_string()));

        let report = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        snp.update_report(&report);

        let k_mod = BigUint::parse_bytes(b"98102316FFB6F426A242A619230E0F274AB9433DA04BB91B1A5792DDA8BC5DB86EE67F0F2E89A57716D1CF4469742BB1A9DD72BDA89CAA90CA7BF4D3D3DB1198BD61F12C7741ADC4426A88D1370412A936EC09340D3171B95AEAEDCE611C1E5F6C9E28EE212AE4C61F752978A596B153174DBF88D1125CA675AA7CFE23A8DD253546C68AEB2EE4A31D7FB66D9C7D665984C951158267A685E9C8D62BA7E62808D2B199926732C4BAF7C91A1630E5CB39CB96287032BA18D2642F743EDD09E0685657CF5063C095A9B05B2AAD214FBDE715644A9DE4C5C35C35BFE678F48A4083DA7D0D6C02604A3F0C9C03FD48E672F30D5B906BDE5958C9F4264A61B452211D", 16).unwrap();

        let attestation = cs
            .attestation(&k_mod, &BigUint::from_str("12345").unwrap(), &snp)
            .unwrap();
        assert_eq!(
            attestation,
            json!({
                "tee-pubkey": json!({
                    "alg": "RSA",
                    "kty": "RSA",
                    "n": k_mod.to_string(),
                    "e": "12345",
                }),
                "tee-evidence": json!({
                    "cert_chain": "",
                    "gen": "milan",
                    "report": hex::encode(report),
                }).to_string(),
            }),
        );

        let remote_secret = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0];
        let data = json!(hex::encode(remote_secret));
        let secret = cs.secret(data).unwrap();
        assert_eq!(secret, remote_secret);
    }
}
