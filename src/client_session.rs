use crate::lib::String;

pub struct ClientSession {
    id: String,
}

impl ClientSession {
    pub fn new(id: String) -> Self {
        ClientSession { id }
    }

    pub fn id(&self) -> String {
        self.id.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lib::*;

    #[test]
    fn test() {
        let cs = ClientSession::new("42".to_string());
        assert_eq!(cs.id(), "42".to_string());
    }
}
