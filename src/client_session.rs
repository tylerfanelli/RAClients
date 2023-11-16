use kbs_types::{Attestation, Challenge, Request, SnpAttestation, SnpRequest, Tee, TeePubKey};
use num_bigint::BigUint;
use serde_json::{json, Value};

use crate::{
    lib::{fmt, String, ToString},
    KBSClientError,
};

#[derive(Debug)]
pub enum CSError {
    // Tee is not supported by this implementation
    TeeNotSupported,
    JsonError(serde_json::Error),
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

impl From<serde_json::Error> for CSError {
    fn from(e: serde_json::Error) -> Self {
        Self::JsonError(e)
    }
}

impl From<CSError> for KBSClientError {
    fn from(e: CSError) -> Self {
        Self::CS(e)
    }
}

pub struct ClientSession {
    tee: Tee,
    workload_id: String,
    session_id: Option<String>,
    nonce: Option<String>,
}

impl ClientSession {
    pub fn new(tee: Tee, workload_id: String) -> Self {
        ClientSession {
            tee,
            workload_id,
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

    pub fn request(&self) -> Result<Value, CSError> {
        let extra_params = match self.tee {
            Tee::Snp => json!(SnpRequest {
                workload_id: self.workload_id.clone()
            }),
            _ => return Err(CSError::TeeNotSupported),
        };

        let request = Request {
            version: "0.1.0".to_string(),
            tee: self.tee.clone(),
            extra_params: json!(extra_params).to_string(),
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
        k_mod: BigUint,
        k_exp: BigUint,
        gen: SnpGeneration,
        report: &[u8],
    ) -> Result<Value, CSError> {
        let tee_pubkey = TeePubKey {
            kty: "RSA".to_string(),
            alg: "RSA".to_string(),
            k_mod: k_mod.to_string(),
            k_exp: k_exp.to_string(),
        };

        let tee_evidence = SnpAttestation {
            report: hex::encode(report),
            cert_chain: "".to_string(),
            gen: gen.to_string(),
        };

        let attestation = Attestation {
            tee_pubkey,
            tee_evidence: json!(tee_evidence).to_string(),
        };

        Ok(json!(attestation))
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;

    #[test]
    fn test() {
        let mut cs = ClientSession::new(Tee::Snp, "snp-workload".to_string());
        assert_eq!(*cs.session_id(), None);

        cs.set_session_id("42".to_string());
        assert_eq!(*cs.session_id(), Some("42".to_string()));

        let request = cs.request().unwrap();
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

        let k_mod = BigUint::parse_bytes(b"98102316FFB6F426A242A619230E0F274AB9433DA04BB91B1A5792DDA8BC5DB86EE67F0F2E89A57716D1CF4469742BB1A9DD72BDA89CAA90CA7BF4D3D3DB1198BD61F12C7741ADC4426A88D1370412A936EC09340D3171B95AEAEDCE611C1E5F6C9E28EE212AE4C61F752978A596B153174DBF88D1125CA675AA7CFE23A8DD253546C68AEB2EE4A31D7FB66D9C7D665984C951158267A685E9C8D62BA7E62808D2B199926732C4BAF7C91A1630E5CB39CB96287032BA18D2642F743EDD09E0685657CF5063C095A9B05B2AAD214FBDE715644A9DE4C5C35C35BFE678F48A4083DA7D0D6C02604A3F0C9C03FD48E672F30D5B906BDE5958C9F4264A61B452211D", 16).unwrap();

        let attestation = cs
            .attestation(
                k_mod.clone(),
                BigUint::from_str("12345").unwrap(),
                SnpGeneration::Milan,
                &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            )
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
                    "report": "00010203040506070809",
                }).to_string(),
            }),
        );
    }
}
