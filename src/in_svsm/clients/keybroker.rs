use kbs_types::{Response as KbsResponse, SnpAttestation, Tee};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    client_proxy::{
        Error as CPError, HttpMethod, Proxy, ProxyRequest, Request, RequestType, Response,
    },
    client_registration::TeeRegistration,
    in_svsm::{
        client_session::{Error as CSError, TeeSession},
        clients::SnpGeneration,
    },
    lib::{String, ToString, Vec},
};

pub struct KeybrokerClientSnp {
    attestation: SnpAttestation,
}

impl KeybrokerClientSnp {
    pub fn new(gen: SnpGeneration) -> Self {
        KeybrokerClientSnp {
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

impl TeeSession for KeybrokerClientSnp {
    fn version(&self) -> String {
        "0.1.0".to_string()
    }

    fn tee(&self) -> Tee {
        Tee::Snp
    }

    fn extra_params(&self) -> Value {
        Value::Null
    }

    fn evidence(&self) -> Value {
        json!(self.attestation)
    }

    fn secret(&self, data: String) -> Result<KbsResponse, CSError> {
        let resp: KbsResponse = serde_json::from_str(&data)?;

        Ok(resp)
    }
}

impl ProxyRequest for KeybrokerClientSnp {
    fn make(
        &self,
        proxy: &mut Proxy,
        req_type: RequestType,
        body: Option<&Value>,
    ) -> Result<Option<String>, CPError> {
        let req = match req_type {
            RequestType::Auth => Request {
                endpoint: "/kbs/v0/auth".to_string(),
                method: HttpMethod::POST,
                body: json!(&body.ok_or(CPError::BodyExpected(req_type))?),
            },
            RequestType::Attest => Request {
                endpoint: "/kbs/v0/attest".to_string(),
                method: HttpMethod::POST,
                body: json!(&body.ok_or(CPError::BodyExpected(req_type))?),
            },
            RequestType::Key => Request {
                endpoint: "/kbs/v0/resource".to_string(),
                method: HttpMethod::GET,
                body: json!(""),
            },
        };

        proxy.write_json(&json!(req))?;
        let data = proxy.read_json()?;
        let resp: Response = serde_json::from_value(data)?;

        if !resp.is_success() {
            return Err(CPError::HttpError(resp.status, resp.body));
        }

        match req_type {
            RequestType::Auth => Ok(Some(resp.body)),
            RequestType::Attest => Ok(None),
            RequestType::Key => Ok(Some(resp.body)),
        }
    }
}

pub struct KeybrokerRegistration {
    policy: String,
    queries: Vec<String>,
}

impl KeybrokerRegistration {
    pub fn new(policy: String, queries: Vec<String>) -> Self {
        KeybrokerRegistration { policy, queries }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Workload {
    policy: String,
    queries: Vec<String>,
    reference: String,
    resources: String,
}

impl TeeRegistration for KeybrokerRegistration {
    fn register(&self, measurement: &[u8], secret: String) -> Value {
        json!(Workload {
            policy: self.policy.clone(),
            queries: self.queries.clone(),
            reference: json!({"measurement": hex::encode(measurement)}).to_string(),
            resources: secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use num_bigint::BigUint;

    use super::*;
    use crate::{client_registration::*, in_svsm::client_session::*};

    #[test]
    fn test_session() {
        let mut snp = KeybrokerClientSnp::new(SnpGeneration::Milan);

        let mut cs = ClientSession::new();

        let request = cs.request(&snp).unwrap();
        assert_eq!(
            request,
            json!({
                "version": "0.1.0",
                "tee": "snp",
                "extra-params": json!(Value::Null).to_string(),
            }),
        );

        let challenge = r#"
        {
            "nonce": "424242",
            "extra-params": ""
        }"#;
        let nonce = cs
            .challenge(serde_json::from_str(challenge).unwrap())
            .unwrap();
        assert_eq!(nonce, "424242".to_string());

        let report = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        snp.update_report(&report);

        let k_mod = BigUint::parse_bytes(b"98102316FFB6F426A242A619230E0F274AB9433DA04BB91B1A5792DDA8BC5DB86EE67F0F2E89A57716D1CF4469742BB1A9DD72BDA89CAA90CA7BF4D3D3DB1198BD61F12C7741ADC4426A88D1370412A936EC09340D3171B95AEAEDCE611C1E5F6C9E28EE212AE4C61F752978A596B153174DBF88D1125CA675AA7CFE23A8DD253546C68AEB2EE4A31D7FB66D9C7D665984C951158267A685E9C8D62BA7E62808D2B199926732C4BAF7C91A1630E5CB39CB96287032BA18D2642F743EDD09E0685657CF5063C095A9B05B2AAD214FBDE715644A9DE4C5C35C35BFE678F48A4083DA7D0D6C02604A3F0C9C03FD48E672F30D5B906BDE5958C9F4264A61B452211D", 16).unwrap();
        let k_mod_encoded = ClientSession::encode_key(&k_mod).unwrap();
        let k_exp = BigUint::from_str("12345").unwrap();
        let k_exp_encoded = ClientSession::encode_key(&k_exp).unwrap();

        let attestation = cs
            .attestation(k_mod_encoded.clone(), k_exp_encoded.clone(), &snp)
            .unwrap();
        assert_eq!(
            attestation,
            json!({
                "tee-pubkey": json!({
                    "alg": "RSA",
                    "kty": "RSA",
                    "n": k_mod_encoded,
                    "e": k_exp_encoded,
                }),
                "tee-evidence": json!({
                    "cert_chain": "",
                    "gen": "milan",
                    "report": hex::encode(report),
                }).to_string(),
            }),
        );

        let remote_secret = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0];
        let data = {
            let resp = KbsResponse {
                protected: "".to_string(),
                encrypted_key: "".to_string(),
                iv: "".to_string(),
                ciphertext: hex::encode(remote_secret),
                tag: "".to_string(),
            };

            json!(resp)
        };
        let secret = cs.secret(data.to_string(), &snp).unwrap();
        assert_eq!(secret, remote_secret);
    }

    #[test]
    fn test_registration() {
        let kr = KeybrokerRegistration::new("my_policy".to_string(), vec!["my_query1".to_string()]);
        let registration = ClientRegistration::register(
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            "secret".to_string(),
            &kr,
        );
        assert_eq!(
            registration,
            json!({
                "policy": "my_policy",
                "queries": vec!["my_query1".to_string()],
                "reference": json!({"measurement": "00010203040506070809"}).to_string(),
                "resources": "secret",
            }),
        );
    }
}
