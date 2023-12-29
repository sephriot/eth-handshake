use alloy_primitives::{U256, U64};
use alloy_rlp::{Decodable, Encodable};
use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use strum::{AsRefStr, EnumCount, EnumIter, EnumString, EnumVariantNames};

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    AsRefStr,
    EnumVariantNames,
    EnumString,
    EnumIter,
    EnumCount,
    Deserialize,
    Serialize,
    TryFromPrimitive,
)]
#[serde(rename_all = "snake_case")]
#[repr(u64)]
pub enum NamedChain {
    Mainnet = 1,
    Goerli = 5,
    Holesky = 17000,
    Sepolia = 11155111,
    Dev = 1337,
}

impl From<NamedChain> for u64 {
    fn from(value: NamedChain) -> Self {
        value as u64
    }
}

impl fmt::Display for NamedChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_ref().fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Chain {
    Named(NamedChain),
    Id(u64),
}

impl Chain {
    pub const fn mainnet() -> Self {
        Chain::Named(NamedChain::Mainnet)
    }

    pub const fn goerli() -> Self {
        Chain::Named(NamedChain::Goerli)
    }

    pub const fn sepolia() -> Self {
        Chain::Named(NamedChain::Sepolia)
    }

    pub const fn holesky() -> Self {
        Chain::Named(NamedChain::Holesky)
    }

    pub const fn dev() -> Self {
        Chain::Named(NamedChain::Dev)
    }

    pub fn named(&self) -> Option<NamedChain> {
        match self {
            Chain::Named(chain) => Some(*chain),
            Chain::Id(id) => NamedChain::try_from(*id).ok(),
        }
    }

    pub fn id(&self) -> u64 {
        match self {
            Chain::Named(chain) => *chain as u64,
            Chain::Id(id) => *id,
        }
    }
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Chain::Named(chain) => chain.fmt(f),
            Chain::Id(id) => {
                if let Ok(chain) = NamedChain::try_from(*id) {
                    chain.fmt(f)
                } else {
                    id.fmt(f)
                }
            }
        }
    }
}

impl From<NamedChain> for Chain {
    fn from(id: NamedChain) -> Self {
        Chain::Named(id)
    }
}

impl From<u64> for Chain {
    fn from(id: u64) -> Self {
        NamedChain::try_from(id)
            .map(Chain::Named)
            .unwrap_or_else(|_| Chain::Id(id))
    }
}

impl From<U256> for Chain {
    fn from(id: U256) -> Self {
        id.to::<u64>().into()
    }
}

impl From<Chain> for u64 {
    fn from(c: Chain) -> Self {
        match c {
            Chain::Named(c) => c as u64,
            Chain::Id(id) => id,
        }
    }
}

impl From<Chain> for U64 {
    fn from(c: Chain) -> Self {
        U64::from(u64::from(c))
    }
}

impl From<Chain> for U256 {
    fn from(c: Chain) -> Self {
        U256::from(u64::from(c))
    }
}

impl TryFrom<Chain> for NamedChain {
    type Error = <NamedChain as TryFrom<u64>>::Error;

    fn try_from(chain: Chain) -> Result<Self, Self::Error> {
        match chain {
            Chain::Named(chain) => Ok(chain),
            Chain::Id(id) => id.try_into(),
        }
    }
}

impl FromStr for Chain {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(chain) = NamedChain::from_str(s) {
            Ok(Chain::Named(chain))
        } else {
            s.parse::<u64>()
                .map(Chain::Id)
                .map_err(|_| format!("Expected known chain or integer, found: {s}"))
        }
    }
}

impl Encodable for Chain {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        match self {
            Self::Named(chain) => u64::from(*chain).encode(out),
            Self::Id(id) => id.encode(out),
        }
    }
    fn length(&self) -> usize {
        match self {
            Self::Named(chain) => u64::from(*chain).length(),
            Self::Id(id) => id.length(),
        }
    }
}

impl Decodable for Chain {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Ok(u64::decode(buf)?.into())
    }
}

impl Default for Chain {
    fn default() -> Self {
        NamedChain::Mainnet.into()
    }
}
