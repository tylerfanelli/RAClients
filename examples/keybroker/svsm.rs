extern crate reference_kbc;

use std::{
    env, fs::read_to_string, os::unix::net::UnixStream, path::PathBuf, str::FromStr, thread,
};

use base64ct::{Base64, Encoding};
use log::{debug, error, info};
use reference_kbc::{
    client_proxy::{
        unix::UnixConnection, Error as CPError, HttpMethod, Proxy, ProxyRequest, Request,
        RequestType, Response,
    },
    client_registration::ClientRegistration,
    client_session::ClientSession,
    clients::{
        keybroker::{KeybrokerClientSnp, KeybrokerRegistration},
        SnpGeneration,
    },
};
use rsa::{traits::PublicKeyParts, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use serde_json::{from_str, json};
use sev::firmware::guest::AttestationReport;
use sha2::{Digest, Sha512};

fn svsm(socket: UnixStream, mut attestation: AttestationReport) {
    let mut proxy = Proxy::new(Box::new(UnixConnection(socket)));

    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);

    let mut snp = KeybrokerClientSnp::new(SnpGeneration::Milan);
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

    info!("Fetching LUKS passphrase");

    let key = match snp.make(&mut proxy, RequestType::Key, None) {
        Ok(key) => key.unwrap(),
        Err(e) => {
            error!("Key fetch error - {e}");
            return;
        }
    };

    debug!("Key fetch success - {}", key);

    let secret = cs.secret(key, &snp).unwrap();
    let decrypted = priv_key.decrypt(Pkcs1v15Encrypt, &secret).unwrap();

    info!(
        "Decrypted passphrase: {}",
        String::from_utf8(decrypted).unwrap()
    );
}

fn main() {
    env_logger::init();

    let url_server = env::args().nth(1).unwrap_or("http://127.0.0.1:8000".into());
    let client = reqwest::blocking::ClientBuilder::new()
        .cookie_store(true)
        .build()
        .unwrap();

    let resources =
        read_to_string(PathBuf::from_str("examples/keybroker/data/resources.json").unwrap())
            .unwrap();
    let policy =
        read_to_string(PathBuf::from_str("examples/keybroker/data/policy.rego").unwrap()).unwrap();
    let queries: Vec<String> = from_str(
        &read_to_string(PathBuf::from_str("examples/keybroker/data/queries.json").unwrap())
            .unwrap(),
    )
    .unwrap();

    info!("Connecting to KBS at {url_server}");

    let mut attestation = AttestationReport::default();
    attestation.measurement[0] = 42;
    attestation.measurement[47] = 24;

    let kr = KeybrokerRegistration::new(policy, queries);
    let registration = ClientRegistration::register(&attestation.measurement, resources, &kr);

    let resp = client
        .post(url_server.clone() + "/rvp/registration")
        .json(&registration)
        .send()
        .unwrap();
    debug!("register - resp: {:#?}", resp);

    if resp.status().is_success() {
        info!("Registration success")
    } else {
        panic!(
            "Registration error({0}) - {1}",
            resp.status(),
            resp.text().unwrap()
        )
    }

    let contents = resp.text().unwrap();
    let host_data = Base64::decode_vec(&contents[1..contents.len() - 1]).unwrap();
    debug!("host_data - {:#?}", host_data);

    attestation.host_data.copy_from_slice(&host_data);

    let (socket, remote_socket) = UnixStream::pair().unwrap();
    let svsm = thread::spawn(move || svsm(remote_socket, attestation));

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
