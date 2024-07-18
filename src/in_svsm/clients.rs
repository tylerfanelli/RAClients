use crate::lib::{fmt, Display};

#[cfg(feature = "keybroker")]
pub mod keybroker;

#[cfg(feature = "reference_kbs")]
pub mod reference_kbs;

pub enum SnpGeneration {
    Milan,
    Genoa,
}

impl Display for SnpGeneration {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SnpGeneration::Milan => write!(f, "milan"),
            SnpGeneration::Genoa => write!(f, "genoa"),
        }
    }
}
