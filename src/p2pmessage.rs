use core::fmt;
use std::borrow::Cow;

use alloy_primitives::B512;
use alloy_rlp::{
    Decodable, Encodable, Error as RlpError, RlpDecodable, RlpEncodable, EMPTY_LIST_CODE,
};
use bytes::{Buf, BufMut};
use serde::{Deserialize, Serialize};

use crate::error::ECIESError;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolVersion {
    V4 = 4,
    #[default]
    V5 = 5,
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", *self as u8)
    }
}

impl Encodable for ProtocolVersion {
    fn encode(&self, out: &mut dyn BufMut) {
        (*self as u8).encode(out)
    }
    fn length(&self) -> usize {
        // the version should be a single byte
        (*self as u8).length()
    }
}

impl Decodable for ProtocolVersion {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let version = u8::decode(buf)?;
        match version {
            4 => Ok(ProtocolVersion::V4),
            5 => Ok(ProtocolVersion::V5),
            _ => Err(RlpError::Custom("unknown p2p protocol version")),
        }
    }
}

#[derive(
    Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable, Default, Hash, Serialize, Deserialize,
)]
pub struct Capability {
    pub name: Cow<'static, str>,
    pub version: usize,
}

impl Capability {
    pub fn new(name: String, version: usize) -> Self {
        Self {
            name: Cow::Owned(name),
            version,
        }
    }

    pub const fn new_static(name: &'static str, version: usize) -> Self {
        Self {
            name: Cow::Borrowed(name),
            version,
        }
    }

    pub const fn eth(version: EthVersion) -> Self {
        Self::new_static("eth", version as usize)
    }

    pub const fn eth_66() -> Self {
        Self::eth(EthVersion::Eth66)
    }

    pub const fn eth_67() -> Self {
        Self::eth(EthVersion::Eth67)
    }

    pub const fn eth_68() -> Self {
        Self::eth(EthVersion::Eth68)
    }

    #[inline]
    pub fn is_eth_v66(&self) -> bool {
        self.name == "eth" && self.version == 66
    }

    #[inline]
    pub fn is_eth_v67(&self) -> bool {
        self.name == "eth" && self.version == 67
    }

    #[inline]
    pub fn is_eth_v68(&self) -> bool {
        self.name == "eth" && self.version == 68
    }

    #[inline]
    pub fn is_eth(&self) -> bool {
        self.is_eth_v66() || self.is_eth_v67() || self.is_eth_v68()
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.name, self.version)
    }
}

impl From<EthVersion> for Capability {
    #[inline]
    fn from(value: EthVersion) -> Self {
        Capability::eth(value)
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum EthVersion {
    Eth66 = 66,

    Eth67 = 67,

    Eth68 = 68,
}

impl EthVersion {
    pub const LATEST: EthVersion = EthVersion::Eth68;

    pub const fn total_messages(&self) -> u8 {
        match self {
            EthVersion::Eth66 => 15,
            EthVersion::Eth67 | EthVersion::Eth68 => {
                // eth/67,68 are eth/66 minus GetNodeData and NodeData messages
                13
            }
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EthMessageID {
    Status = 0x00,
}

impl EthMessageID {
    pub const fn max() -> u8 {
        Self::Status as u8
    }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloMessageWithProtocols {
    pub protocol_version: ProtocolVersion,
    pub client_version: String,
    pub protocols: Vec<Protocol>,
    pub port: u16,
    pub id: B512,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Protocol {
    pub cap: Capability,
    messages: u8,
}

impl Protocol {
    pub const fn new(cap: Capability, messages: u8) -> Self {
        Self { cap, messages }
    }

    pub const fn eth(version: EthVersion) -> Self {
        let cap = Capability::eth(version);
        let messages = version.total_messages();
        Self::new(cap, messages)
    }

    pub const fn eth_66() -> Self {
        Self::eth(EthVersion::Eth66)
    }

    pub const fn eth_67() -> Self {
        Self::eth(EthVersion::Eth67)
    }

    pub const fn eth_68() -> Self {
        Self::eth(EthVersion::Eth68)
    }

    pub fn messages(&self) -> u8 {
        if self.cap.is_eth() {
            return EthMessageID::max() + 1;
        }
        self.messages
    }
}

impl From<EthVersion> for Protocol {
    fn from(version: EthVersion) -> Self {
        Self::eth(version)
    }
}

impl HelloMessageWithProtocols {
    #[inline]
    pub fn message(&self) -> HelloMessage {
        HelloMessage {
            protocol_version: self.protocol_version,
            client_version: self.client_version.clone(),
            capabilities: self.protocols.iter().map(|p| p.cap.clone()).collect(),
            port: self.port,
            id: self.id,
        }
    }

    pub fn into_message(self) -> HelloMessage {
        HelloMessage {
            protocol_version: self.protocol_version,
            client_version: self.client_version,
            capabilities: self.protocols.into_iter().map(|p| p.cap).collect(),
            port: self.port,
            id: self.id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable)]
pub struct HelloMessage {
    pub protocol_version: ProtocolVersion,
    pub client_version: String,
    pub capabilities: Vec<Capability>,
    pub port: u16,
    pub id: B512,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum P2PMessage {
    Hello(HelloMessage),
    Disconnect(u8),
    Ping,
    Pong,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum P2PMessageID {
    Hello = 0x00,
    Disconnect = 0x01,
    Ping = 0x02,
    Pong = 0x03,
}

impl From<P2PMessage> for P2PMessageID {
    fn from(msg: P2PMessage) -> Self {
        match msg {
            P2PMessage::Hello(_) => P2PMessageID::Hello,
            P2PMessage::Disconnect(_) => P2PMessageID::Disconnect,
            P2PMessage::Ping => P2PMessageID::Ping,
            P2PMessage::Pong => P2PMessageID::Pong,
        }
    }
}

impl P2PMessage {
    pub fn message_id(&self) -> P2PMessageID {
        match self {
            P2PMessage::Hello(_) => P2PMessageID::Hello,
            P2PMessage::Disconnect(_) => P2PMessageID::Disconnect,
            P2PMessage::Ping => P2PMessageID::Ping,
            P2PMessage::Pong => P2PMessageID::Pong,
        }
    }
}

impl TryFrom<u8> for P2PMessageID {
    type Error = ECIESError;

    fn try_from(id: u8) -> Result<Self, Self::Error> {
        match id {
            0x00 => Ok(P2PMessageID::Hello),
            0x01 => Ok(P2PMessageID::Disconnect),
            0x02 => Ok(P2PMessageID::Ping),
            0x03 => Ok(P2PMessageID::Pong),
            _ => Err(ECIESError::UnknownError {
                message: "UnknownReservedMessageId".to_owned(),
            }),
        }
    }
}

impl Encodable for P2PMessage {
    fn encode(&self, out: &mut dyn BufMut) {
        (self.message_id() as u8).encode(out);
        match self {
            P2PMessage::Hello(msg) => msg.encode(out),
            P2PMessage::Disconnect(msg) => msg.encode(out),
            P2PMessage::Ping => {
                // Ping payload is _always_ snappy encoded
                out.put_u8(0x01);
                out.put_u8(0x00);
                out.put_u8(EMPTY_LIST_CODE);
            }
            P2PMessage::Pong => {
                // Pong payload is _always_ snappy encoded
                out.put_u8(0x01);
                out.put_u8(0x00);
                out.put_u8(EMPTY_LIST_CODE);
            }
        }
    }

    fn length(&self) -> usize {
        let payload_len = match self {
            P2PMessage::Hello(msg) => msg.length(),
            P2PMessage::Disconnect(msg) => msg.length(),
            // id + snappy encoded payload
            P2PMessage::Ping => 3, // len([0x01, 0x00, 0xc0]) = 3
            P2PMessage::Pong => 3, // len([0x01, 0x00, 0xc0]) = 3
        };
        payload_len + 1 // (1 for length of p2p message id)
    }
}

impl Decodable for P2PMessage {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        fn advance_snappy_ping_pong_payload(buf: &mut &[u8]) -> alloy_rlp::Result<()> {
            if buf.len() < 3 {
                return Err(RlpError::InputTooShort);
            }
            if buf[..3] != [0x01, 0x00, EMPTY_LIST_CODE] {
                return Err(RlpError::Custom("expected snappy payload"));
            }
            buf.advance(3);
            Ok(())
        }

        let message_id = u8::decode(&mut &buf[..])?;
        let id = P2PMessageID::try_from(message_id)
            .or(Err(RlpError::Custom("unknown p2p message id")))?;
        buf.advance(1);
        match id {
            P2PMessageID::Hello => Ok(P2PMessage::Hello(HelloMessage::decode(buf)?)),
            P2PMessageID::Disconnect => Ok(P2PMessage::Disconnect(buf[0])),
            P2PMessageID::Ping => {
                advance_snappy_ping_pong_payload(buf)?;
                Ok(P2PMessage::Ping)
            }
            P2PMessageID::Pong => {
                advance_snappy_ping_pong_payload(buf)?;
                Ok(P2PMessage::Pong)
            }
        }
    }
}
