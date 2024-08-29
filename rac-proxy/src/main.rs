// SPDX-License-Identifier: Apache-2.0

mod backend;

use backend::Backend;

use std::{fs, os::unix::net::UnixListener, thread};

use clap::Parser;

use raclients::frontend::unix::*;

#[derive(Parser, Debug)]
#[clap(version, about)]
struct Args {
    #[clap(long)]
    url: String,

    #[clap(long)]
    unix: String,

    #[clap(long, short, default_value_t = false)]
    force: bool,

    #[clap(long)]
    backend: backend::server::BackendServer,
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
                let conn = UnixConnection(stream);

                let (url, backend) = (args.url.clone(), args.backend.clone());

                thread::spawn(move || backend.attest(conn, url));
            }
            Err(_) => panic!("error"),
        }
    }

    Ok(())
}
