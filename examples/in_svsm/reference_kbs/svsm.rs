extern crate raclients;

use std::{env, os::unix::net::UnixStream, thread};

use log::{debug, error, info};
use raclients::{
    client_proxy::{
        unix::UnixConnection, Error as CPError, HttpMethod, Proxy, ProxyRequest, Request,
        RequestType, Response,
    },
    client_registration::ClientRegistration,
    in_svsm::{
        client_session::ClientSession,
        clients::{
            reference_kbs::{ReferenceKBSClientSnp, ReferenceKBSRegistration},
            SnpGeneration,
        },
    },
};
use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use serde_json::json;
use sev::firmware::guest::AttestationReport;
use sha2::{Digest, Sha512};

fn svsm(socket: UnixStream, workload_id: String, mut attestation: AttestationReport) {
    let mut proxy = Proxy::new(Box::new(UnixConnection(socket)));

    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);

    let mut snp = ReferenceKBSClientSnp::new(SnpGeneration::Milan, workload_id);
    let mut cs = ClientSession::new();

    let request = cs.request(&snp).unwrap();

    let challenge = match snp.make(&mut proxy, RequestType::Auth, Some(&request)) {
        Ok(challenge) => challenge.unwrap(),
        Err(e) => {
            error!("Authentication error - {e}");
            return;
        }
    };

    info!("Authentication success - {}", challenge);

    debug!("Challenge: {:#?}", challenge);
    let nonce = cs
        .challenge(serde_json::from_str(&challenge).unwrap())
        .unwrap();

    info!("Nonce: {}", nonce);

    let key_n_encoded = ClientSession::encode_key(pub_key.n()).unwrap();
    let key_e_encoded = ClientSession::encode_key(pub_key.e()).unwrap();

    let mut hasher = Sha512::new();
    hasher.update(nonce.as_bytes());
    hasher.update(key_n_encoded.as_bytes());
    hasher.update(key_e_encoded.as_bytes());

    attestation.report_data = hasher.finalize().into();

    snp.update_report(unsafe {
        core::slice::from_raw_parts(
            (&attestation as *const AttestationReport) as *const u8,
            core::mem::size_of::<AttestationReport>(),
        )
    });

    let attestation = cs.attestation(key_n_encoded, key_e_encoded, &snp).unwrap();

    if let Err(e) = snp.make(&mut proxy, RequestType::Attest, Some(&attestation)) {
        error!("Attestation error - {e}");
        return;
    }

    info!("Attestation success");
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

    let rkr = ReferenceKBSRegistration::new(workload_id.clone());
    let registration = ClientRegistration::register(
        &attestation.measurement,
        "secret passphrase".to_string(),
        &rkr,
    );

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

    let mut proxy = Proxy::new(Box::new(UnixConnection(socket)));

    loop {
        let data = match proxy.read_json() {
            Ok(data) => data,
            Err(CPError::Eof) => {
                info!("Client disconnected!");
                break;
            }
            Err(e) => {
                error!("{e}");
                break;
            }
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
        if let Err(e) = proxy.write_json(&json!(resp)) {
            error!("{e}");
            break;
        }
    }

    svsm.join().unwrap();
}
