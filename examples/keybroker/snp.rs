extern crate raclients;

use std::{env, fs::read_to_string, path::PathBuf, str::FromStr};

use base64ct::{Base64, Encoding};
use log::{debug, error, info};
use raclients::{
    client_registration::ClientRegistration,
    client_session::ClientSession,
    clients::{
        keybroker::{KeybrokerClientSnp, KeybrokerRegistration},
        SnpGeneration,
    },
};
use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use serde_json::from_str;
use sev::firmware::guest::AttestationReport;
use sha2::{Digest, Sha512};

fn main() {
    env_logger::init();

    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);

    let url = env::args().nth(1).unwrap_or("http://127.0.0.1:8000".into());
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

    info!("Connecting to KBS at {url}");

    let mut attestation = AttestationReport::default();
    attestation.measurement[0] = 42;
    attestation.measurement[47] = 24;

    let kr = KeybrokerRegistration::new(policy, queries);
    let registration = ClientRegistration::register(&attestation.measurement, resources, &kr);

    let resp = client
        .post(url.clone() + "/rvp/registration")
        .json(&registration)
        .send()
        .unwrap();
    debug!("register_workload - resp: {:#?}", resp);

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

    let mut snp = KeybrokerClientSnp::new(SnpGeneration::Milan);

    let mut cs = ClientSession::new();

    let request = cs.request(&snp).unwrap();
    let req = client.post(url.clone() + "/kbs/v0/auth").json(&request);
    debug!("auth - {:#?}", req);

    let resp = req.send().unwrap();
    debug!("auth - {:#?}", resp);

    let challenge = if resp.status().is_success() {
        let challenge = resp.text().unwrap();
        info!("Authentication success - {}", challenge);
        challenge
    } else {
        error!(
            "Authentication error({0}) - {1}",
            resp.status(),
            resp.text().unwrap()
        );
        return;
    };

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
    attestation.host_data.copy_from_slice(&host_data);

    snp.update_report(unsafe {
        core::slice::from_raw_parts(
            (&attestation as *const AttestationReport) as *const u8,
            core::mem::size_of::<AttestationReport>(),
        )
    });

    let attestation = cs.attestation(key_n_encoded, key_e_encoded, &snp).unwrap();

    let req = client
        .post(url.clone() + "/kbs/v0/attest")
        .json(&attestation);
    debug!("attest - {:#?}", req);

    let resp = req.send().unwrap();
    debug!("attest - {:#?}", resp);

    if resp.status().is_success() {
        info!("Attestation success - {}", resp.text().unwrap())
    } else {
        error!(
            "Attestation error({0}) - {1}",
            resp.status(),
            resp.text().unwrap()
        )
    }
}
