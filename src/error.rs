use std::{fmt, io};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ECIESError {
    OutOfBounds { idx: usize, len: usize },
    TagCheckDecryptFailed,
    Secp256k1(secp256k1::Error),
    InvalidAuthData,
    RLPDecoding(alloy_rlp::Error),
    InvalidAckData,
    TagCheckHeaderFailed,
    TagCheckBodyFailed,
    InvalidHeader,
    IO(io::Error),
    FromInt(std::num::TryFromIntError),
    UnknownError { message: String },
}

impl fmt::Display for ECIESError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl From<secp256k1::Error> for ECIESError {
    fn from(source: secp256k1::Error) -> Self {
        ECIESError::Secp256k1(source).into()
    }
}

impl From<alloy_rlp::Error> for ECIESError {
    fn from(source: alloy_rlp::Error) -> Self {
        ECIESError::RLPDecoding(source).into()
    }
}

impl From<std::io::Error> for ECIESError {
    fn from(source: std::io::Error) -> Self {
        ECIESError::IO(source).into()
    }
}

impl From<std::num::TryFromIntError> for ECIESError {
    fn from(source: std::num::TryFromIntError) -> Self {
        ECIESError::FromInt(source).into()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum EthStreamError {
    #[error("AlloyRlpError")]
    AlloyRlpError(alloy_rlp::Error),
}

impl From<alloy_rlp::Error> for EthStreamError {
    fn from(err: alloy_rlp::Error) -> Self {
        EthStreamError::AlloyRlpError(err).into()
    }
}
