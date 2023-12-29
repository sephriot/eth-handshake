use std::error::Error;
use std::thread::sleep;
use std::time::Duration;

use rs_handshake::p2p::UnauthenticatedP2PConnection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let enode = "enode://63c310dd920adca1b8682a195557f8ca3ab824b49a9d977003d2c9efbbaec1d4bd3f838ae80676f6349eaea59e8f3db85544f4ecd1a550323f90b6ee55282a18@127.0.0.1:30303";
    let unauth_p2p = UnauthenticatedP2PConnection::new(enode).await?;
    println!("Initiating P2P Handshake");
    let mut auth_p2p = unauth_p2p.handshake().await?;
    println!("P2P Handshake finished successfully");
    println!("Initiating ETH Handshake");
    auth_p2p.handshake().await?;
    println!("ETH Handshake finished successfully");
    println!("Waiting 10 seconds before program finishes...");
    sleep(Duration::from_secs(10));
    Ok(())
}
