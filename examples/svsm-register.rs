use clap::Parser;
use log::{debug, error, info};
use reference_kbc::{
    client_registration::ClientRegistration,
    clients::{keybroker::KeybrokerRegistration, reference_kbs::ReferenceKBSRegistration},
};
use reqwest::blocking::Client;
use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("Communication with the HTTP server failed - {0}")]
    HttpCommunication(reqwest::Error),
    #[error("KBS is failing to register the SVSM workload")]
    RegistrationFailed,
}

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None, group(
    clap::ArgGroup::new("server_type")
        .required(true)
))]
struct ProxyArgs {
    /// HTTP url to KBS (e.g. http://server:4242)
    #[clap(long)]
    url: String,
    /// Pre-calculated measurement (hex encoded string - e.g. 8a60c0196d2e9f)
    #[clap(long)]
    measurement: String,
    /// Secret to share with the CVM
    #[clap(long)]
    passphrase: String,
    /// The remote server is `keybroker`
    #[clap(long, group = "server_type")]
    keybroker: bool,
    /// The remote server is `reference_kbs`. ID of the workload must be
    /// specified.
    #[clap(long, group = "server_type", value_name = "WORKLOAD_ID")]
    reference_kbs: Option<String>,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let config = ProxyArgs::parse();

    info!("Registering workload at {}", config.url);

    let (resource, registration) = if config.keybroker {
        let kr = KeybrokerRegistration::new();
        let registration =
            ClientRegistration::register(&hex::decode(config.measurement)?, config.passphrase, &kr);

        ("/kbs/v0/register", registration)
    } else if config.reference_kbs.is_some() {
        let rkr = ReferenceKBSRegistration::new(config.reference_kbs.unwrap().clone());
        let registration = ClientRegistration::register(
            &hex::decode(config.measurement)?,
            config.passphrase,
            &rkr,
        );
        ("/kbs/v0/register_workload", registration)
    } else {
        panic!();
    };

    let resp = Client::new()
        .post(config.url.clone() + resource)
        .json(&registration)
        .send()
        .map_err(Error::HttpCommunication)?;

    debug!("register_workload - resp: {:#?}", resp);

    if !resp.status().is_success() {
        error!(
            "KBS returned error {0} - {1}",
            resp.status(),
            resp.text().unwrap()
        );
        return Err(Error::RegistrationFailed.into());
    }

    info!("Workload successfully registered at {}", config.url);

    if config.keybroker {
        let uuid = String::from_utf8(resp.bytes().unwrap().to_ascii_lowercase()).unwrap();
        info!("registration UUID: {}", uuid);
    }

    Ok(())
}
