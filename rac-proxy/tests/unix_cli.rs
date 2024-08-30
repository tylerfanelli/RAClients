// SPDX-License-Identifier: Apache-2.0

use std::{mem::size_of, os::unix::net::UnixStream, slice::from_raw_parts};

use openssl::{
    base64::{decode_block, encode_block},
    bn::BigNum,
    pkey::Public,
    rsa::{Padding, Rsa},
    sha::Sha512,
};
use raclients::frontend::{unix::UnixConnection, FrontendClient, NegotiationParam};
use reqwest::blocking::get;
use serde_json::{json, Map, Value};
use sev::firmware::guest::AttestationReport;

const TEST_MILAN_ATTESTATION_REPORT: &[u8] = include_bytes!("data/report_milan.hex");

const SECRET: &str = "hello, world!";

#[test]
fn unix_cli() {
    let encrypted = tee_key_encrypt();

    let stream = UnixStream::connect("/tmp/rac-proxy.sock").unwrap();
    let mut conn = UnixConnection(stream);

    let params = conn.negotiation().unwrap();
    let cvm_ikey = Rsa::generate(2048).unwrap();

    let hash = {
        let mut sha = Sha512::new();

        for np in params {
            match np {
                NegotiationParam::RsaPubkeyN => sha.update(&cvm_ikey.n().to_vec()),
                NegotiationParam::RsaPubkeyE => sha.update(&cvm_ikey.e().to_vec()),
                NegotiationParam::Bytes(b) => sha.update(&b),
            }
        }

        sha.finish()
    };

    let mut report: AttestationReport = {
        let bytes = hex::decode(TEST_MILAN_ATTESTATION_REPORT).unwrap();

        unsafe { std::ptr::read(bytes.as_ptr() as *const _) }
    };

    report.report_data.copy_from_slice(&hash);

    let report_bytes: &[u8] = unsafe {
        from_raw_parts(
            (&report as *const AttestationReport) as *const u8,
            size_of::<AttestationReport>(),
        )
    };

    let json = json!({
        "tee": "snp".to_string(),
        "report": encode_block(report_bytes),
        "cvm_ikey": encode_block(&cvm_ikey.public_key_to_der().unwrap()),
        "secret": encode_block(&encrypted),
    });

    let map = if let Value::Object(m) = json {
        m
    } else {
        panic!("JSON object not a map");
    };

    conn.evidence(map).unwrap();

    let secret = conn.secret().unwrap();

    let secret = if let Value::String(s) = secret {
        s
    } else {
        panic!("JSON object not a string");
    };

    let bytes = decode_block(&secret).unwrap();

    let mut dec = [0u8; 256];
    cvm_ikey
        .private_decrypt(&bytes, &mut dec, Padding::NONE)
        .expect("unable to decrypt secret with CVM integrity key");

    let string = String::from_utf8(dec.to_vec()).expect("cannot parse decrypted secret from UTF-8");

    assert_eq!(string.trim_matches(char::from(0)), SECRET);
}

fn tee_key_encrypt() -> [u8; 256] {
    let rsa = get_akey();

    let mut encrypted = [0u8; 256];

    rsa.public_encrypt(SECRET.as_bytes(), &mut encrypted, Padding::PKCS1)
        .unwrap();

    encrypted
}

fn b64_bn(label: &str, json_val: &Value) -> BigNum {
    let slice = if let Value::String(s) = json_val {
        decode_block(&s).expect(&format!("unable to decode {} from base64", label))
    } else {
        panic!("{}", format!("{} in JSON response not a string", label));
    };

    BigNum::from_slice(&slice).expect(&format!("unable to convert {} to OpenSSL BIGNUM", label))
}

fn get_akey() -> Rsa<Public> {
    let body = get("http://127.0.0.1:8000/akey/public_components")
        .expect("GET /akey/public_components failed")
        .text()
        .expect("unable to read /akey/public_components response");

    let json: Map<String, Value> =
        serde_json::from_str(&body).expect("cannot parse /akey/public_components output as JSON");

    let n = b64_bn(
        "modulus",
        json.get("n")
            .expect("/akey/public_components modulus not found in JSON response"),
    );

    let e = b64_bn(
        "exponent",
        json.get("e")
            .expect("/akey/public_components exponent not found in JSON response"),
    );

    Rsa::from_public_components(n, e).expect(
        "unable to create public RSA key from modulus and exponent from /akey/public_components",
    )
}
