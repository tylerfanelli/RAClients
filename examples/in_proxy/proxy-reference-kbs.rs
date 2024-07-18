use std::{
    os::unix::net::{UnixListener, UnixStream},
    thread,
};

use clap::Parser;
use kbs_types::{Attestation, Challenge, Request, SnpAttestation, SnpRequest, Tee, TeePubKey};
use log::{debug, error, info};
use raclients::{
    client_proxy::{unix::UnixConnection, Error as CPError, Proxy},
    in_proxy::{
        client_session::{ClientSessionHost, Error as CSError},
        clients::{AttestationKey, NegotiationHash, NegotiationKey, NegotiationParam},
    },
};
use reqwest::blocking::{Client, ClientBuilder};
use serde_json::json;
use thiserror::Error as ThisError;

/// Custom error types
#[derive(Debug, ThisError)]
pub enum Error {
    #[error("Creation of Unix socket failed - {0}")]
    UnixListen(std::io::Error),
    #[error("Reading from the Unix socket failed - {0}")]
    SessionError(CSError),
    #[error("Converting JSON - {0}")]
    JsonError(serde_json::Error),
    #[error("Communication with the HTTP server failed - {0}")]
    HttpCommunication(reqwest::Error),
    #[error("HTTP error code - {0}")]
    HttpError(u16),
}

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct ProxyArgs {
    /// HTTP url to KBS (e.g. http://server:4242)
    #[clap(long)]
    url: String,
    /// Unix domain socket path to the SVSM serial port
    #[clap(long)]
    unix: String,
    /// ID of the workload to be used with KBS
    #[clap(long)]
    workload_id: String,
    /// Force Unix domain socket removal before bind
    #[clap(long, short, default_value_t = false)]
    force: bool,
}

fn start_proxy(stream: UnixStream, url: String, workload_id: String) -> anyhow::Result<()> {
    let mut proxy = Proxy::new(Box::new(UnixConnection(stream)));

    let http_client = ClientBuilder::new().cookie_store(true).build()?;
    info!("Starting HTTP proxy for {url}");

    loop {
        let mut cs = ClientSessionHost::new();
        match cs.negotiation_request(&mut proxy) {
            Ok(_) => {}
            Err(CSError::ProxyError(CPError::Eof)) => {
                info!("Client disconnected!");
                break;
            }
            Err(e) => {
                return Err(Error::SessionError(e).into());
            }
        };

        let request = Request {
            version: "0.1.0".to_string(),
            tee: Tee::Snp,
            extra_params: json!(SnpRequest {
                workload_id: workload_id.clone()
            })
            .to_string(),
        };
        let http_req = http_client
            .post(url.clone() + "/kbs/v0/auth")
            .json(&request);
        debug!("HTTP request - {:#?}", http_req);

        let http_resp = http_req.send().map_err(Error::HttpCommunication)?;
        debug!("HTTP response - {:#?}", http_resp);

        if !http_resp.status().is_success() {
            return Err(Error::HttpError(http_resp.status().as_u16()).into());
        }

        let challenge: Challenge = serde_json::from_str(&http_resp.text()?)?;
        let params = vec![
            NegotiationParam::Extra(challenge.nonce),
            NegotiationParam::Key(NegotiationKey::RSA2048),
        ];

        cs.negotiation_response(&mut proxy, NegotiationHash::SHA512, params)?;

        let (report, key) = cs.attestation_request(&mut proxy)?;

        let (k_mod, k_exp) = match key {
            AttestationKey::RSA { n, e } => (n, e),
            _ => return Err(anyhow::anyhow!("Key not supported")),
        };

        let evidence = SnpAttestation {
            report,
            cert_chain: "".to_string(),
            gen: "milan".to_string(),
        };

        let attestation = Attestation {
            tee_pubkey: TeePubKey {
                kty: "RSA".to_string(),
                alg: "RSA".to_string(),
                k_mod,
                k_exp,
            },
            tee_evidence: json!(evidence).to_string(),
        };
        let http_req = http_client
            .post(url.clone() + "/kbs/v0/attest")
            .json(&attestation);
        debug!("HTTP request - {:#?}", http_req);

        let http_resp = http_req.send().map_err(Error::HttpCommunication)?;
        debug!("HTTP response - {:#?}", http_resp);

        if !http_resp.status().is_success() {
            return Err(Error::HttpError(http_resp.status().as_u16()).into());
        }

        let http_req = http_client.get(url.clone() + "/kbs/v0/key/" + &workload_id);
        debug!("HTTP request - {:#?}", http_req);

        let http_resp = http_req.send().map_err(Error::HttpCommunication)?;
        debug!("HTTP response - {:#?}", http_resp);

        if !http_resp.status().is_success() {
            return Err(Error::HttpError(http_resp.status().as_u16()).into());
        }

        let secret: String = serde_json::from_str(&http_resp.text()?)?;
        cs.attestation_response(&mut proxy, true, secret)?;
    }

    Ok(())
}

fn handle_client(stream: UnixStream, url: String, workload_id: String) {
    if let Err(e) = start_proxy(stream, url, workload_id) {
        error!("{e}");
    }
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let config = ProxyArgs::parse();

    if config.force {
        let _ = std::fs::remove_file(config.unix.clone());
    }

    let listener = UnixListener::bind(config.unix).map_err(Error::UnixListen)?;

    // We will probably receive a 404 error, but let's try a GET just to raise
    // an error right away and get out if the server is already unreachable.
    let _ = Client::new()
        .get(config.url.clone())
        .send()
        .map_err(Error::HttpCommunication)?;

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let url = config.url.clone();
                let workload_id = config.workload_id.clone();
                thread::spawn(|| handle_client(stream, url, workload_id));
            }
            Err(e) => {
                error!("{e}");
            }
        }
    }

    Ok(())
}
