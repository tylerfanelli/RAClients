use serde_json::Value;

use crate::lib::String;

pub trait TeeRegistration {
    fn register(&self, measurement: &[u8], secret: String) -> Value;
}

pub struct ClientRegistration {}

impl Default for ClientRegistration {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientRegistration {
    pub fn new() -> Self {
        Self {}
    }

    pub fn register(measurement: &[u8], secret: String, tee: &dyn TeeRegistration) -> Value {
        tee.register(measurement, secret)
    }
}
