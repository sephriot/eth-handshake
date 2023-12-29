use std::error::Error;
use std::thread::sleep;
use std::time::Duration;

use rs_handshake::p2p::UnauthenticatedP2PConnection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let enode = "enode://63c310dd920adca1b8682a195557f8ca3ab824b49a9d977003d2c9efbbaec1d4bd3f838ae80676f6349eaea59e8f3db85544f4ecd1a550323f90b6ee55282a18@127.0.0.1:30303";
    let unauth_p2p = UnauthenticatedP2PConnection::new(enode).await?;
    let mut auth_p2p = unauth_p2p.handshake().await?;
    auth_p2p.handshake().await?;

    sleep(Duration::from_secs(10));
    Ok(())
}
