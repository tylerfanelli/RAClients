// SPDX-License-Identifier: Apache-2.0

use std::{fs, os::unix::net::UnixListener};

use clap::Parser;

use raclients::frontend::{unix::*, FrontendServer, *};

#[derive(Parser, Debug)]
#[clap(version, about)]
struct Args {
    //    #[clap(long)]
    //    url: String,
    #[clap(long)]
    unix: String,

    #[clap(long, short, default_value_t = false)]
    force: bool,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args = Args::parse();

    if args.force {
        let _ = fs::remove_file(args.unix.clone());
    }

    let listener = UnixListener::bind(args.unix).unwrap();

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let mut conn = UnixConnection(stream);
                let params = vec![NegotiationParam::RsaPubkeyN];
                let evidence = conn.evidence(params);
                println!("{:?}", evidence);
            }
            Err(_) => panic!("error"),
        }
    }

    Ok(())
}
