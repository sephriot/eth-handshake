use alloy_rlp::{Encodable, Decodable};
use bytes::BytesMut;

use rs_handshake::ecies::ECIES;
use rs_handshake::ethmessage::ProtocolMessage;
use rs_handshake::p2pmessage::P2PMessage;
use rs_handshake::snappy::{snappy_decode, snappy_encode};
use rs_handshake::stream::TcpStreamHandler;
use rs_handshake::util::{peer_id_2_public_key, pk2id};

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};
use std::thread::sleep;
use std::time::Duration;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 0x92332c4beb163f7b814d9a6aa586c14191d1317d3ca958dd0ba4866afeee8dd203f219ae1a41c1a9e720252d4b3a335b27e93da09918076645be3c67adc3edca
    // let server_peer_id = "0x92332c4beb163f7b814d9a6aa586c14191d1317d3ca958dd0ba4866afeee8dd203f219ae1a41c1a9e720252d4b3a335b27e93da09918076645be3c67adc3edca";
    // GETH GOERLI
    // let server_peer_id = "49b228dd83ca2438a0ba76412afc43c555f3bfd52d1b61df1da4553c83ec8d0a99c84f6751e38589f784e6c6eced974b1a565bae4ea88bb7c6216e448d165d8a";
    // GETH mainnet
    let server_peer_id = "63c310dd920adca1b8682a195557f8ca3ab824b49a9d977003d2c9efbbaec1d4bd3f838ae80676f6349eaea59e8f3db85544f4ecd1a550323f90b6ee55282a18";

    let mut stream_handler =
        TcpStreamHandler::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 30303).await;
    let mut ecies = ECIES::new_client(pk2id(&peer_id_2_public_key(server_peer_id)));
    let auth = ecies.create_auth();
    println!("Writing auth");
    stream_handler.write(&auth).await?;
    println!("Auth written");
    let mut remote_ack = stream_handler.read().await?;
    println!("Auth received");
    ecies.read_ack(&mut remote_ack)?;
    println!("Auth OK");
    println!("PeerId = {:?}", ecies.peer_id());

    println!("Reading ETH hello message");
    let mut hello_message = stream_handler.read().await?;
    println!("{:?} || {:?}", hello_message, hello_message.len());
    println!("Reading header");
    ecies.read_header(&mut hello_message)?;
    println!("Reading Body");
    let mut raw_server_msg = ecies.read_body(&mut hello_message[ECIES::header_len()..])?;
    
    let server_hello : P2PMessage = P2PMessage::decode(&mut &raw_server_msg[..])?;
    
    // let mut my_hello : HelloMessage;
    // if let P2PMessage::Hello(server_hello) = server_hello {
    //     println!("{:?}", server_hello);
    //     let mut my_hello = server_hello;
    // }

    let my_hello_raw = match server_hello {
        P2PMessage::Hello(server_hello) => Ok(server_hello),
        _ => Err(()),
    };
    let mut my_hello = my_hello_raw.unwrap();
    println!("{:?}", my_hello);
    my_hello.id = ecies.peer_id();
    
    // let protocols = vec![EthVersion::Eth67.into()];
    // let mut my_hello = HelloMessageWithProtocols {
    //     protocol_version: ProtocolVersion::V5,
    //     client_version: "eth/1.0.0".to_string(),
    //     protocols,
    //     port: 30303,
    //     id: ecies.peer_id(),
    // };

    let mut raw_hello_bytes = BytesMut::new();
    P2PMessage::Hello(my_hello).encode(&mut raw_hello_bytes);
    println!("{:?}", raw_hello_bytes);
    let mut ecies_hello_header = ecies.create_header(raw_hello_bytes.len());
    println!("Writing header | {:?}", ecies_hello_header);
    ecies.write_body(&mut ecies_hello_header, &raw_hello_bytes);
    stream_handler.write(&ecies_hello_header).await?;
    /////////////////// P2P handshake finished

    /////////////////// ETH handshake
    let mut status_msg = stream_handler.read().await?;
    println!("Status MSG: {:?}", status_msg);
    ecies.read_header(&mut status_msg)?;
    println!("Reading Body | {:?} | {:?}", ecies.body_len(), status_msg.len());
    raw_server_msg = ecies.read_body(&mut status_msg[ECIES::header_len()..])?;
    println!("raw_server_msg | {:?} ", raw_server_msg.len());
    // println!("raw_server_msg | {:?} ", hex::encode(raw_server_msg));
    let decoded_raw_msg = snappy_decode(raw_server_msg)?;

    let status_msg = ProtocolMessage::decode_message(&mut decoded_raw_msg.as_ref()).expect("decode error in eth handshake");
    println!("Server status msg{:?}", status_msg);
    
    let mut my_status_bytes = BytesMut::with_capacity(1 + 88);
    status_msg.encode(&mut my_status_bytes);
    let snappy_encoded_status = snappy_encode(my_status_bytes.freeze())?;
    let mut ecies_status_msg = BytesMut::new();
    ecies.write_header(&mut ecies_status_msg, snappy_encoded_status.len());
    ecies.write_body(&mut ecies_status_msg, &snappy_encoded_status);
    stream_handler.write(&ecies_status_msg).await?;

    println!("========================================");

    sleep(Duration::from_secs(10));
    Ok(())
}
