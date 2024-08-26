use std::{
    os::unix::net::{UnixListener, UnixStream},
    thread,
};

use base64ct::{Base64, Encoding};
use clap::Parser;
use log::{debug, error, info};
use num_bigint::BigUint;
use raclients::{
    client_proxy::{unix::UnixConnection, Error as CPError, Proxy},
    in_proxy::{
        client_session::{ClientSessionHost, Error as CSError},
        clients::{AttestationKey, NegotiationHash, NegotiationKey, NegotiationParam},
    },
};
use reqwest::blocking::{Client, ClientBuilder};
use rsa::{pkcs8::EncodePublicKey, RsaPublicKey};
use serde_json::{json, Map, Value};
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
    /// HTTP url to TEE broker (e.g. http://server:4242)
    #[clap(long)]
    url: String,

    /// Unix domain socket path to the SVSM serial port
    #[clap(long)]
    unix: String,

    /// Secret to be encrypted/decrypted by the TEE broker
    #[clap(long)]
    secret: String,

    /// Force Unix domain socket removal before bind
    #[clap(long, short, default_value_t = false)]
    force: bool,
}

fn start_proxy(stream: UnixStream, url: String, secret: String) -> anyhow::Result<()> {
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

        let http_req = http_client.get(url.clone() + "/tee/challenge");
        debug!("HTTP request - {:#?}", http_req);

        let http_resp = http_req.send().map_err(Error::HttpCommunication)?;
        debug!("HTTP response - {:#?}", http_resp);

        if !http_resp.status().is_success() {
            return Err(Error::HttpError(http_resp.status().as_u16()).into());
        }

        let challenge: Map<String, Value> = serde_json::from_str(&http_resp.text()?)?;

        let nonce = {
            let val = challenge.get("nonce").unwrap();
            match val {
                Value::String(s) => s,
                _ => panic!("nonce is not a string"),
            }
        };

        let params = vec![
            NegotiationParam::Extra(nonce.to_string()),
            NegotiationParam::Key(NegotiationKey::RSA2048),
        ];

        cs.negotiation_response(&mut proxy, NegotiationHash::SHA512, params)?;

        let (report, key) = cs.attestation_request(&mut proxy)?;

        let (k_mod, k_exp) = match key {
            AttestationKey::RSA { n, e } => (n, e),
            _ => return Err(anyhow::anyhow!("Key not supported")),
        };

        let report = {
            let bytes = hex::decode(report).unwrap();
            Base64::encode_string(&bytes)
        };

        let modulus = {
            let bytes = Base64::decode_vec(&k_mod).unwrap();
            BigUint::from_bytes_be(&bytes)
        };

        let exponent = {
            let bytes = Base64::decode_vec(&k_exp).unwrap();
            BigUint::from_bytes_be(&bytes)
        };

        let rsa = RsaPublicKey::new(modulus, exponent).unwrap();

        let der = {
            let doc = rsa.to_public_key_der().unwrap();
            doc.into_vec()
        };

        let evidence = json!({
            "tee": "snp".to_string(),
            "report": report,
            "cvm_ikey": Base64::encode_string(&der),
            "secret": secret,
        });

        let http_req = http_client
            .post(url.clone() + "/tee/attest")
            .json(&evidence);
        debug!("HTTP request - {:#?}", http_req);

        let http_resp = http_req.send().map_err(Error::HttpCommunication)?;
        debug!("HTTP response - {:#?}", http_resp);

        if !http_resp.status().is_success() {
            return Err(Error::HttpError(http_resp.status().as_u16()).into());
        }

        let secret: String = serde_json::from_str(&http_resp.text()?)?;
        debug!("secret: {:#?}", secret);
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
                let secret = config.secret.clone();
                thread::spawn(|| handle_client(stream, url, secret));
            }
            Err(e) => {
                error!("{e}");
            }
        }
    }

    Ok(())
}
