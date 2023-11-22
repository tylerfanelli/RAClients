use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    lib::{String, ToString},
    KBCError,
};

#[derive(Debug)]
pub enum CRError {}

impl From<CRError> for KBCError {
    fn from(e: CRError) -> Self {
        Self::CR(e)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Workload {
    workload_id: String,
    launch_measurement: String,
    tee_config: String,
    passphrase: String,
}

pub struct ClientRegistration {
    workload_id: String,
}

impl ClientRegistration {
    pub fn new(workload_id: String) -> Self {
        ClientRegistration { workload_id }
    }

    pub fn register(&self, measurement: &[u8], passphrase: String) -> Result<Value, CRError> {
        let workload = Workload {
            workload_id: self.workload_id.clone(),
            launch_measurement: hex::encode(measurement),
            tee_config: "".to_string(),
            passphrase,
        };

        Ok(json!(workload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        let cr = ClientRegistration::new("snp-workload".to_string());

        let registration = cr
            .register(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], "secret".to_string())
            .unwrap();
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
