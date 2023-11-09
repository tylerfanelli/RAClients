extern crate reference_kbs_client;

use reference_kbs_client::client_session::ClientSession;

fn main() {
    env_logger::init();

    println!("Example started");
    let cs = ClientSession::new("0".to_string());
    let id = cs.id();
    println!("Created new client sessions with ID {id}");
}
