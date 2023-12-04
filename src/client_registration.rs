use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::lib::{Debug, String};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientRegistration {
    measurement: String,
    secret: String,
}

impl ClientRegistration {
    pub fn new(measurement: &[u8], secret: String) -> Self {
        Self {
            measurement: hex::encode(measurement),
            secret,
        }
    }

    pub fn register(&self) -> Value {
        json!(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration() {
        let cr = ClientRegistration::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], "secret".to_string());

        let registration = cr.register();
        assert_eq!(
            registration,
            json!({
                "measurement": "00010203040506070809",
                "secret": "secret",
            }),
        );
    }
}
