// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use openssl::base64::decode_block;
use raclients::frontend::{unix::UnixConnection, FrontendServer, NegotiationParam};
use reqwest::{
    blocking::{get, ClientBuilder, Response},
    cookie::Jar,
    Url,
};
use serde_json::{Map, Value};

pub fn attest(mut conn: UnixConnection, url: String) -> Result<()> {
    let (body, id) = {
        let resp = get(format!("{}/tee/challenge", url)).context("GET /tee/challenge")?;

        let id = limebroker_id(&resp)?;

        let body = resp
            .text()
            .context("cannot read text output of /tee/challenge")?;

        (body, id)
    };

    let json: Map<String, Value> =
        serde_json::from_str(&body).expect("cannot parse /tee/challenge output as JSON");

    let encoded = json.get("nonce").expect("nonce not found from response");

    let nonce = if let Value::String(s) = encoded {
        decode_block(s).expect("unable to decode nonce from base64")
    } else {
        return Err(anyhow!("nonce value in JSON response not a string"));
    };

    let params = vec![
        NegotiationParam::RsaPubkeyN,
        NegotiationParam::RsaPubkeyE,
        NegotiationParam::Bytes(nonce),
    ];

    conn.negotiation(params).unwrap();

    let evidence = conn.evidence().unwrap();

    let jar = Jar::default();
    jar.add_cookie_str(
        &format!("limebroker-id={}", id),
        &Url::parse(&format!("{}/tee/attest", url)).unwrap(),
    );

    let client = ClientBuilder::new()
        .cookie_store(true)
        .cookie_provider(Arc::new(jar))
        .build()
        .unwrap();

    let res = client
        .post(format!("{}/tee/attest", url))
        .json(&evidence)
        .send()
        .unwrap();

    let json: Map<String, Value> = res.json().unwrap();

    let secret = json.get("secret").unwrap();

    conn.secret(secret.clone()).unwrap();

    Ok(())
}

fn limebroker_id(resp: &Response) -> Result<String> {
    let cookies = resp.cookies();

    for c in cookies {
        if c.name() == "limebroker-id" {
            return Ok(c.value().to_string());
        }
    }

    Err(anyhow!("unable to find limebroker-id cookie in response"))
}
