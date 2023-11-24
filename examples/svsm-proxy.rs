use std::{
    os::unix::net::{UnixListener, UnixStream},
    thread,
};

use clap::Parser;
use log::{debug, error, info};
use reference_kbc::client_proxy::{
    unix::UnixConnection, Error as CPError, HttpMethod, Proxy, Request, Response,
};
use reqwest::blocking::{Client, ClientBuilder};
use serde_json::{json, Value};
use thiserror::Error as ThisError;

/// Custom error types
#[derive(Debug, ThisError)]
pub enum Error {
    #[error("Creation of Unix socket failed - {0}")]
    UnixListen(std::io::Error),
    #[error("Reading from the Unix socket failed - {0}")]
    ProxyRead(CPError),
    #[error("Communication with the HTTP server failed - {0}")]
    HttpCommunication(reqwest::Error),
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
    /// Force Unix domain socket removal before bind
    #[clap(long, short, default_value_t = false)]
    force: bool,
}

fn forward_request(http_client: &Client, url: &str, data: Value) -> anyhow::Result<Response> {
    let req: Request = serde_json::from_value(data)?;

    let url_req = url.to_owned() + &req.endpoint;
    let http_req = match req.method {
        HttpMethod::GET => http_client.get(url_req).json(&req.body),
        HttpMethod::POST => http_client.post(url_req).json(&req.body),
    };
    debug!("HTTP request - {:#?}", http_req);

    let http_resp = http_req.send().map_err(Error::HttpCommunication)?;
    debug!("HTTP response - {:#?}", http_resp);

    let resp = Response {
        status: http_resp.status().as_u16(),
        body: http_resp.text().unwrap_or(String::new()),
    };

    Ok(resp)
}

fn start_proxy(stream: UnixStream, url: String) -> anyhow::Result<()> {
    let mut proxy = Proxy::new(Box::new(UnixConnection(stream)));

    let http_client = ClientBuilder::new().cookie_store(true).build()?;

    info!("Starting HTTP proxy for {url}");

    loop {
        let data = match proxy.read_json() {
            Ok(data) => data,
            Err(CPError::Eof) => {
                info!("Client disconnected!");
                break;
            }
            Err(e) => {
                return Err(Error::ProxyRead(e).into());
            }
        };

        let resp = match forward_request(&http_client, &url, data) {
            Ok(resp) => resp,
            Err(e) => {
                error!("{e}");
                Response {
                    status: 999,
                    body: e.to_string(),
                }
            }
        };

        proxy.write_json(&json!(resp))?;
    }

    Ok(())
}

fn handle_client(stream: UnixStream, url: String) {
    if let Err(e) = start_proxy(stream, url) {
        error!("{e}");
    }
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let config = ProxyArgs::parse();

    if config.force {
        std::fs::remove_file(config.unix.clone())?;
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
                thread::spawn(|| handle_client(stream, url));
            }
            Err(e) => {
                error!("{e}");
            }
        }
    }

    Ok(())
}
