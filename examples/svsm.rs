extern crate reference_kbc;

use std::{
    env,
    io::{Read as IoRead, Write as IoWrite},
    os::unix::net::UnixStream,
    thread,
};

use log::{debug, error, info};
use reference_kbc::{
    client_proxy::{CPError, Connection, HttpMethod, Proxy, Read, Request, Response, Write},
    client_registration::ClientRegistration,
    client_session::{ClientSession, ClientTeeSnp, SnpGeneration},
};
use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use serde_json::json;
use sev::firmware::guest::AttestationReport;
use sha2::{Digest, Sha512};

struct UnixConnection(UnixStream);

impl Write for UnixConnection {
    fn write(&mut self, buf: &[u8]) -> Result<usize, CPError> {
        self.0.write_all(buf).map_err(|_| CPError::WriteError)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), CPError> {
        self.0.flush().map_err(|_| CPError::FlushError)
    }
}

impl Read for UnixConnection {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, CPError> {
        self.0.read_exact(buf).map_err(|_| CPError::ReadError)?;
        Ok(buf.len())
    }
}

impl Connection for UnixConnection {}

fn svsm(socket: UnixStream, workload_id: String, mut attestation: AttestationReport) {
    let mut conn = UnixConnection(socket);
    let mut proxy = Proxy::new(&mut conn);

    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);

    let mut snp = ClientTeeSnp::new(SnpGeneration::Milan, workload_id);
    let mut cs = ClientSession::new();

    let request = cs.request(&snp).unwrap();

    let req = Request {
        endpoint: "/kbs/v0/auth".to_string(),
        method: HttpMethod::POST,
        body: json!(&request),
    };
    proxy.write_json(&json!(req)).unwrap();
    let data = proxy.read_json().unwrap();
    let resp: Response = serde_json::from_value(data).unwrap();

    let challenge = if resp.is_success() {
        let challenge = resp.body;
        info!("Authentication success - {}", challenge);
        challenge
    } else {
        error!("Authentication error({0}) - {1}", resp.status, resp.body);
        return;
    };

    debug!("Challenge: {:#?}", challenge);
    let nonce = cs
        .challenge(serde_json::from_str(&challenge).unwrap())
        .unwrap();

    info!("Nonce: {}", nonce);

    let mut hasher = Sha512::new();
    hasher.update(nonce.as_bytes());
    hasher.update(pub_key.n().to_string().as_bytes());
    hasher.update(pub_key.e().to_string().as_bytes());

    attestation.report_data = hasher.finalize().into();

    snp.update_report(unsafe {
        core::slice::from_raw_parts(
            (&attestation as *const AttestationReport) as *const u8,
            core::mem::size_of::<AttestationReport>(),
        )
    });

    let attestation = cs.attestation(pub_key.n(), pub_key.e(), &snp).unwrap();

    let req = Request {
        endpoint: "/kbs/v0/attest".to_string(),
        method: HttpMethod::POST,
        body: json!(&attestation),
    };
    proxy.write_json(&json!(req)).unwrap();
    let data = proxy.read_json().unwrap();
    let resp: Response = serde_json::from_value(data).unwrap();
    if resp.is_success() {
        info!("Attestation success - {}", resp.body)
    } else {
        error!("Attestation error({0}) - {1}", resp.status, resp.body)
    }
}

fn main() {
    env_logger::init();

    let workload_id = "snp-workload".to_string();

    let url_server = env::args().nth(1).unwrap_or("http://127.0.0.1:8000".into());
    let client = reqwest::blocking::ClientBuilder::new()
        .cookie_store(true)
        .build()
        .unwrap();

    info!("Connecting to KBS at {url_server}");

    let mut attestation = AttestationReport::default();
    attestation.measurement[0] = 42;
    attestation.measurement[47] = 24;

    let cr = ClientRegistration::new(workload_id.clone());
    let registration = cr
        .register(&attestation.measurement, "secret passphrase".to_string())
        .unwrap();

    let resp = client
        .post(url_server.clone() + "/kbs/v0/register_workload")
        .json(&registration)
        .send()
        .unwrap();
    debug!("register_workload - resp: {:#?}", resp);

    if resp.status().is_success() {
        info!("Registration success")
    } else {
        error!(
            "Registration error({0}) - {1}",
            resp.status(),
            resp.text().unwrap()
        )
    }

    let (socket, remote_socket) = UnixStream::pair().unwrap();
    let svsm = thread::spawn(move || svsm(remote_socket, workload_id, attestation));

    let mut conn = UnixConnection(socket);
    let mut proxy = Proxy::new(&mut conn);

    loop {
        let data = match proxy.read_json() {
            Ok(data) => data,
            Err(_) => break,
        };
        let req: Request = serde_json::from_value(data).unwrap();

        let url = url_server.clone() + &req.endpoint;
        let http_req = match req.method {
            HttpMethod::GET => client.get(url).json(&req.body),
            HttpMethod::POST => client.post(url).json(&req.body),
        };
        debug!("HTTP request - {:#?}", http_req);

        let http_resp = http_req.send().unwrap();
        debug!("HTTP response - {:#?}", http_resp);

        let resp = Response {
            status: http_resp.status().as_u16(),
            body: http_resp.text().unwrap_or(String::new()),
        };
        if proxy.write_json(&json!(resp)).is_err() {
            break;
        }
    }

    svsm.join().unwrap();
}
