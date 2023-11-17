extern crate reference_kbc;

use std::env;

use reference_kbc::client_session::{ClientSession, ClientTeeSnp, SnpGeneration};

fn main() {
    env_logger::init();

    let url = env::args().nth(1).unwrap_or("http://127.0.0.1:8000".into());

    println!("Connecting to KBS at {url}");
    let snp = ClientTeeSnp::new(SnpGeneration::Milan, "snp-workload".to_string());
    let cs = ClientSession::new();
    let id = cs.session_id();
    println!("Created new client sessions with ID {id:?}");

    let request = cs.request(&snp).unwrap();

    let client = reqwest::blocking::Client::new();
    let resp = client.post(url + "/kbs/v0/auth").json(&request).send();
    println!("{:#?}", resp);

    println!("Response: {:#?}", resp.unwrap().text());
}
