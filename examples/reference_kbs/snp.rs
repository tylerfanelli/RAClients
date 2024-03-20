extern crate raclients;

use std::env;

use log::{debug, error, info};
use raclients::{
    client_registration::ClientRegistration,
    client_session::ClientSession,
    clients::{
        reference_kbs::{ReferenceKBSClientSnp, ReferenceKBSRegistration},
        SnpGeneration,
    },
};
use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
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

    info!("Connecting to KBS at {url}");

    let workload_id = "snp-workload".to_string();
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
        .post(url.clone() + "/kbs/v0/register_workload")
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

    let mut snp = ReferenceKBSClientSnp::new(SnpGeneration::Milan, workload_id.clone());

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
