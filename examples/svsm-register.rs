use std::{
    fs::{read, read_to_string},
    path::PathBuf,
};

use clap::{Args, Parser};
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

#[derive(Args, Clone, Debug)]
struct KeybrokerArgs {
    /// The remote server is `keybroker`
    #[clap(
        long,
        group = "server_type",
        requires = "policy",
        requires = "queries",
        requires = "resources"
    )]
    keybroker: bool,
    /// [keybroker] Path to the policy file
    #[arg(long, requires = "keybroker")]
    policy: Option<PathBuf>,
    /// [keybroker] Path to the queries file
    #[arg(long, requires = "keybroker")]
    queries: Option<PathBuf>,
    /// [keybroker] Path to the resources file
    #[arg(long, requires = "keybroker")]
    resources: Option<PathBuf>,
}

#[derive(Args, Clone, Debug)]
struct RefKBSArgs {
    /// The remote server is `reference_kbs`
    #[arg(
        long,
        group = "server_type",
        requires = "workload_id",
        requires = "passphrase",
        requires = "resource"
    )]
    reference_kbs: bool,
    /// [reference_kbs] ID of the workload
    #[arg(long, requires = "reference_kbs")]
    workload_id: Option<String>,
    /// [reference_kbs] Secret to share with the CVM
    #[arg(long, requires = "reference_kbs", conflicts_with = "resource")]
    passphrase: Option<String>,
    /// [reference_kbs] Resource blob to release to the CVM (e.g. vTPM state)
    #[arg(long, requires = "reference_kbs", conflicts_with = "passphrase")]
    resource: Option<PathBuf>,
}

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None, group(
    clap::ArgGroup::new("server_type")
        .required(true)
))]
struct ProxyArgs {
    /// HTTP url to KBS (e.g. http://server:4242)
    #[arg(long)]
    url: String,
    /// Pre-calculated measurement (hex encoded string - e.g. 8a60c0196d2e9f)
    #[arg(long)]
    measurement: String,
    #[command(flatten)]
    kb_args: KeybrokerArgs,
    #[command(flatten)]
    rkbs_args: RefKBSArgs,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let config = ProxyArgs::parse();

    info!("Registering workload at {}", config.url);

    let (resource, registration) = if config.kb_args.keybroker {
        let resources = read_to_string(config.kb_args.resources.unwrap())?;
        let policy = read_to_string(config.kb_args.policy.unwrap())?;
        let queries: Vec<String> =
            serde_json::from_str(&read_to_string(config.kb_args.queries.unwrap())?)?;

        let kr = KeybrokerRegistration::new(policy, queries);
        let registration =
            ClientRegistration::register(&hex::decode(config.measurement)?, resources, &kr);

        ("/rvp/registration", registration)
    } else if config.rkbs_args.reference_kbs {
        let rkr = ReferenceKBSRegistration::new(config.rkbs_args.workload_id.unwrap().clone());
        let resource = if config.rkbs_args.passphrase.is_some() {
            config.rkbs_args.passphrase.unwrap()
        } else if config.rkbs_args.resource.is_some() {
            let file_content = read(config.rkbs_args.resource.unwrap())?;
            hex::encode(file_content)
        } else {
            panic!();
        };
        let registration =
            ClientRegistration::register(&hex::decode(config.measurement)?, resource, &rkr);
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

    if config.kb_args.keybroker {
        info!("registration - host_data: {}", resp.text().unwrap());
    }

    Ok(())
}
