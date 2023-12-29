use core::fmt;
use std::fmt::Display;
use std::fmt::Debug;

use alloy_primitives::{U256, B256, hex};
use alloy_rlp::{Encodable, Decodable, RlpDecodable, RlpEncodable, RlpMaxEncodedLen, RlpEncodableWrapper, RlpDecodableWrapper};
use bytes::{BufMut, Buf};
use serde::{Deserialize, Serialize};
use crc::*;

use crate::error::EthStreamError;
use crate::chain::Chain;

pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

// Minimalistic implementation
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EthMessageID {
    Status = 0x00,
}

impl Encodable for EthMessageID {
    fn encode(&self, out: &mut dyn BufMut) {
        out.put_u8(*self as u8);
    }
    fn length(&self) -> usize {
        1
    }
}

impl Decodable for EthMessageID {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let id = buf.first().ok_or(alloy_rlp::Error::InputTooShort)?;
        let id = match id {
            0x00 => EthMessageID::Status,
            _ => return Err(alloy_rlp::Error::Custom("Invalid message ID")),
        };
        buf.advance(1);
        Ok(id)
    }
}

impl TryFrom<usize> for EthMessageID {
    type Error = &'static str;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(EthMessageID::Status),
            _ => Err("Invalid message ID"),
        }
    }
}

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    RlpEncodableWrapper,
    RlpDecodableWrapper,
    RlpMaxEncodedLen,
    Serialize,
    Deserialize,
)]
pub struct ForkHash(pub [u8; 4]);

impl fmt::Debug for ForkHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ForkHash").field(&hex::encode(&self.0[..])).finish()
    }
}

const CRC_32_IEEE: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

impl From<B256> for ForkHash {
    fn from(genesis: B256) -> Self {
        Self(CRC_32_IEEE.checksum(&genesis[..]).to_be_bytes())
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    RlpEncodable,
    RlpDecodable,
    RlpMaxEncodedLen,
    Serialize,
    Deserialize,
)]
pub struct ForkId {
    pub hash: ForkHash,
    pub next: u64,
}

#[derive(Copy, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable, Serialize, Deserialize)]
pub struct Status {
    pub version: u8,
    pub chain: Chain,
    pub total_difficulty: U256,
    pub blockhash: B256,
    pub genesis: B256,
    pub forkid: ForkId,
}

impl Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hexed_blockhash = hex::encode(self.blockhash);
        let hexed_genesis = hex::encode(self.genesis);
        write!(
            f,
            "Status {{ version: {}, chain: {}, total_difficulty: {}, blockhash: {}, genesis: {}, forkid: {:X?} }}",
            self.version,
            self.chain,
            self.total_difficulty,
            hexed_blockhash,
            hexed_genesis,
            self.forkid
        )
    }
}

impl Debug for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hexed_blockhash = hex::encode(self.blockhash);
        let hexed_genesis = hex::encode(self.genesis);
        if f.alternate() {
            write!(
                f,
                "Status {{\n\tversion: {:?},\n\tchain: {:?},\n\ttotal_difficulty: {:?},\n\tblockhash: {},\n\tgenesis: {},\n\tforkid: {:X?}\n}}",
                self.version,
                self.chain,
                self.total_difficulty,
                hexed_blockhash,
                hexed_genesis,
                self.forkid
            )
        } else {
            write!(
                f,
                "Status {{ version: {:?}, chain: {:?}, total_difficulty: {:?}, blockhash: {}, genesis: {}, forkid: {:X?} }}",
                self.version,
                self.chain,
                self.total_difficulty,
                hexed_blockhash,
                hexed_genesis,
                self.forkid
            )
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EthMessage {
    // Status is required for the protocol handshake
    Status(Status),
}

impl EthMessage {
    pub fn message_id(&self) -> EthMessageID {
        match self {
            EthMessage::Status(_) => EthMessageID::Status
        }
    }
}

impl Encodable for EthMessage {
    fn encode(&self, out: &mut dyn BufMut) {
        match self {
            EthMessage::Status(status) => status.encode(out)
        }
    }
    fn length(&self) -> usize {
        match self {
            EthMessage::Status(status) => status.length()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolMessage {
    pub message_type: EthMessageID,
    pub message: EthMessage,
}

impl ProtocolMessage {
    pub fn decode_message(buf: &mut &[u8]) -> Result<Self, EthStreamError> {
        println!("MSG1: {:?}", buf);
        let message_type = EthMessageID::decode(buf)?;
        println!("MSG2: {:?}", buf);
        let message = match message_type {
            EthMessageID::Status => EthMessage::Status(Status::decode(buf)?),
        };
        Ok(ProtocolMessage { message_type, message })
    }
}

impl Encodable for ProtocolMessage {
    fn encode(&self, out: &mut dyn BufMut) {
        self.message_type.encode(out);
        self.message.encode(out);
    }
    fn length(&self) -> usize {
        self.message_type.length() + self.message.length()
    }
}

impl From<EthMessage> for ProtocolMessage {
    fn from(message: EthMessage) -> Self {
        ProtocolMessage { message_type: message.message_id(), message }
    }
}