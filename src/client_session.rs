// TODO: remove
#![allow(dead_code)]
#![allow(unused_imports)]

use kbs_types::{Attestation, Challenge, Request, SnpRequest, Tee};
use serde_json::{json, Value};

use crate::{
    lib::{String, ToString},
    KBSClientError,
};

#[derive(Debug)]
pub enum CSError {
    // Tee is not supported by this implementation
    TeeNotSupported,
    JsonError(serde_json::Error),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lib::*;

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
    }
}
