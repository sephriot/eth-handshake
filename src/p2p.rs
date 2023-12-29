use std::error::Error;

use alloy_rlp::{Decodable, Encodable};
use bytes::{Bytes, BytesMut};

use crate::{
    ecies::ECIES, ethmessage::ProtocolMessage, p2pmessage::P2PMessage, stream::TcpStreamHandler,
    util::enode2p2pparams,
};

pub struct UnauthenticatedP2PConnection {
    stream_handler: TcpStreamHandler,
    ecies: ECIES,
}

impl UnauthenticatedP2PConnection {
    pub async fn new(enode: &str) -> Result<Self, Box<dyn Error>> {
        let (peer_id, ip_addr, port) = enode2p2pparams(enode)?;
        Ok(Self {
            stream_handler: TcpStreamHandler::new(ip_addr, port).await,
            ecies: ECIES::new_client(peer_id),
        })
    }

    pub async fn handshake(mut self) -> Result<AuthenticatedP2PConnection, Box<dyn Error>> {
        // Exchange encryption keys
        let auth = self.ecies.create_auth();
        self.stream_handler.write(&auth).await?;
        let mut remote_ack = self.stream_handler.read().await?;
        self.ecies.read_ack(&mut remote_ack)?;
        // Keys exchanged

        // Exchange hello message
        let mut hello_message = self.stream_handler.read().await?;
        self.ecies.read_header(&mut hello_message)?;
        let raw_server_hello = self
            .ecies
            .read_body(&mut hello_message[ECIES::header_len()..])?;

        let server_hello: P2PMessage = P2PMessage::decode(&mut &raw_server_hello[..])?;

        let my_hello_raw = match server_hello {
            P2PMessage::Hello(server_hello) => Ok(server_hello),
            _ => Err(()),
        };
        // Normally you should check compatibility or minimum requirements at this point
        // Modify Hello message with client's peerId and send it back.
        let mut my_hello = my_hello_raw.unwrap();
        my_hello.id = self.ecies.peer_id();

        let mut raw_hello_bytes = BytesMut::new();
        P2PMessage::Hello(my_hello).encode(&mut raw_hello_bytes);
        let mut ecies_hello_header = self.ecies.create_header(raw_hello_bytes.len());
        self.ecies
            .write_body(&mut ecies_hello_header, &raw_hello_bytes);
        self.stream_handler.write(&ecies_hello_header).await?;

        Ok(AuthenticatedP2PConnection::from_unauthenticated(self))
    }
}

pub struct AuthenticatedP2PConnection {
    inner: UnauthenticatedP2PConnection,
    encoder: snap::raw::Encoder,
    decoder: snap::raw::Decoder,
}

impl AuthenticatedP2PConnection {
    pub fn from_unauthenticated(unauth: UnauthenticatedP2PConnection) -> Self {
        Self {
            inner: unauth,
            encoder: snap::raw::Encoder::new(),
            decoder: snap::raw::Decoder::new(),
        }
    }

    fn snappy_encode(&mut self, item: Bytes) -> Result<BytesMut, snap::Error> {
        pub const MAX_RESERVED_MESSAGE_ID: u8 = 0x0f;

        let mut compressed = BytesMut::zeroed(1 + snap::raw::max_compress_len(item.len() - 1));
        let compressed_size = self
            .encoder
            .compress(&item[1..], &mut compressed[1..])
            .map_err(|err| err)?;

        compressed.truncate(compressed_size + 1);
        compressed[0] = item[0] + MAX_RESERVED_MESSAGE_ID + 1;

        Ok(compressed)
    }

    fn snappy_decode(&mut self, bytes: &[u8]) -> Result<BytesMut, snap::Error> {
        let decompressed_len = snap::raw::decompress_len(&bytes[1..])?;
        let mut decompress_buf = BytesMut::zeroed(decompressed_len + 1);
        self.decoder
            .decompress(&bytes[1..], &mut decompress_buf[1..])
            .map_err(|err| err)?;
        Ok(decompress_buf)
    }

    pub async fn handshake(&mut self) -> Result<u8, Box<dyn Error>> {
        let mut status_msg = self.inner.stream_handler.read().await?;
        self.inner.ecies.read_header(&mut status_msg)?;
        let raw_server_status = self
            .inner
            .ecies
            .read_body(&mut status_msg[ECIES::header_len()..])?;
        let decoded_raw_status = self.snappy_decode(raw_server_status)?;

        let status_msg = ProtocolMessage::decode_message(&mut decoded_raw_status.as_ref())
            .expect("decode error in eth handshake");

        // Normally you should compatibility here, but in this case I'm just sending back whatever was received

        let mut my_status_bytes = BytesMut::with_capacity(1 + 88);
        status_msg.encode(&mut my_status_bytes);
        let snappy_encoded_status = self.snappy_encode(my_status_bytes.freeze())?;
        let mut ecies_status_msg = BytesMut::new();
        self.inner
            .ecies
            .write_header(&mut ecies_status_msg, snappy_encoded_status.len());
        self.inner
            .ecies
            .write_body(&mut ecies_status_msg, &snappy_encoded_status);
        self.inner.stream_handler.write(&ecies_status_msg).await?;
        Ok(0)
    }
}
