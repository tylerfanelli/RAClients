use kbs_types::{Response as KbsResponse, SnpAttestation, SnpRequest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    client_proxy::{
        Error as CPError, HttpMethod, Proxy, ProxyRequest, Request, RequestType, Response,
    },
    client_registration::TeeRegistration,
    in_svsm::{
        client_session::{Error as CSError, Tee, TeeSession},
        clients::SnpGeneration,
    },
    lib::{String, ToString},
};

pub struct ReferenceKBSClientSnp {
    request: SnpRequest,
    attestation: SnpAttestation,
}

impl ReferenceKBSClientSnp {
    pub fn new(gen: SnpGeneration, workload_id: String) -> Self {
        ReferenceKBSClientSnp {
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

impl TeeSession for ReferenceKBSClientSnp {
    fn version(&self) -> String {
        "0.1.0".to_string()
    }

    fn tee(&self) -> Tee {
        Tee::Snp
    }

    fn extra_params(&self) -> Value {
        json!(self.request)
    }

    fn evidence(&self) -> Value {
        json!(self.attestation)
    }

    fn secret(&self, data: String) -> Result<KbsResponse, CSError> {
        let response = KbsResponse {
            ciphertext: serde_json::from_str(&data)?,
            protected: "".to_string(),
            encrypted_key: "".to_string(),
            iv: "".to_string(),
            tag: "".to_string(),
        };

        Ok(response)
    }
}

impl ProxyRequest for ReferenceKBSClientSnp {
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
                endpoint: "/kbs/v0/key/".to_string() + &self.request.workload_id,
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

pub struct ReferenceKBSRegistration {
    workload_id: String,
}

impl ReferenceKBSRegistration {
    pub fn new(workload_id: String) -> Self {
        ReferenceKBSRegistration { workload_id }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Workload {
    workload_id: String,
    launch_measurement: String,
    tee_config: String,
    passphrase: String,
}

impl TeeRegistration for ReferenceKBSRegistration {
    fn register(&self, measurement: &[u8], secret: String) -> Value {
        json!(Workload {
            workload_id: self.workload_id.clone(),
            launch_measurement: hex::encode(measurement),
            tee_config: "".to_string(),
            passphrase: secret,
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
        let mut snp = ReferenceKBSClientSnp::new(SnpGeneration::Milan, "snp-workload".to_string());

        let mut cs = ClientSession::new();

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
        let data = json!(hex::encode(remote_secret));
        let secret = cs.secret(data.to_string(), &snp).unwrap();
        assert_eq!(secret, remote_secret);
    }

    #[test]
    fn test_registration() {
        let rkr = ReferenceKBSRegistration::new("snp-workload".to_string());
        let registration = ClientRegistration::register(
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            "secret".to_string(),
            &rkr,
        );
        assert_eq!(
            registration,
            json!({
                "workload_id": "snp-workload",
                "launch_measurement": "00010203040506070809",
                "tee_config": "",
                "passphrase": "secret",
            }),
        );
    }
}
