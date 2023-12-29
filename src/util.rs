use std::error::Error;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::str::FromStr;

use alloy_primitives::{hex, B256, B512};
use hmac::Hmac;
use hmac::Mac;
use regex::Regex;
use secp256k1::{PublicKey, SecretKey};
use sha2::Digest;
use sha2::Sha256;

// Utility function to extract specific parts from "connection string"
// e.g. enode://63c310dd920adca1b8682a195557f8ca3ab824b49a9d977003d2c9efbbaec1d4bd3f838ae80676f6349eaea59e8f3db85544f4ecd1a550323f90b6ee55282a18@127.0.0.1:30303

pub fn enode2p2pparams(enode: &str) -> Result<(B512, IpAddr, u16), Box<dyn Error>> {
    let re = Regex::new(r"enode://([^@]+)@([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)").unwrap();
    let caps = re.captures(enode);
    match caps {
        Some(caps) => {
            let peer_id =
                B512::from_slice(hex::decode(caps.get(1).map_or("", |m| m.as_str()))?.as_slice());
            let ip = Ipv4Addr::from_str(caps.get(2).map_or("", |m| m.as_str()))?;
            let port = caps.get(3).map_or("", |m| m.as_str()).parse::<u16>()?;
            Ok((peer_id, ip.into(), port))
        }
        None => Err("Enode string did not match the pattern".into()),
    }
}

pub fn id2pk(id: B512) -> Result<PublicKey, secp256k1::Error> {
    let mut s = [0u8; 65];
    // SECP256K1_TAG_PUBKEY_UNCOMPRESSED = 0x04
    // see: https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1.h#L221
    s[0] = 4;
    s[1..].copy_from_slice(id.as_slice());
    PublicKey::from_slice(&s)
}

pub fn pk2id(pk: &PublicKey) -> B512 {
    B512::from_slice(&pk.serialize_uncompressed()[1..])
}

pub fn sha256(data: &[u8]) -> B256 {
    B256::from(Sha256::digest(data).as_ref())
}

pub fn hmac_sha256(key: &[u8], input: &[&[u8]], auth_data: &[u8]) -> B256 {
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    for input in input {
        hmac.update(input);
    }
    hmac.update(auth_data);
    B256::from_slice(&hmac.finalize().into_bytes())
}

pub fn ecdh_x(public_key: &PublicKey, secret_key: &SecretKey) -> B256 {
    B256::from_slice(&secp256k1::ecdh::shared_secret_point(public_key, secret_key)[..32])
}

pub fn kdf(secret: B256, s1: &[u8], dest: &mut [u8]) {
    let mut ctr = 1_u32;
    let mut written = 0_usize;
    while written < dest.len() {
        let mut hasher = Sha256::default();
        let ctrs = [
            (ctr >> 24) as u8,
            (ctr >> 16) as u8,
            (ctr >> 8) as u8,
            ctr as u8,
        ];
        hasher.update(ctrs);
        hasher.update(secret.as_slice());
        hasher.update(s1);
        let d = hasher.finalize();
        dest[written..(written + 32)].copy_from_slice(&d);
        written += 32;
        ctr += 1;
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use super::enode2p2pparams;

    #[test]
    fn test_enode() {
        let enode = "enode://63c310dd920adca1b8682a195557f8ca3ab824b49a9d977003d2c9efbbaec1d4bd3f838ae80676f6349eaea59e8f3db85544f4ecd1a550323f90b6ee55282a18@127.0.0.1:30303";
        let res = enode2p2pparams(enode);
        assert!(!res.is_err());
        let (_, ip_addr, port) = res.unwrap();
        assert_eq!(port, 30303);
        assert_eq!(ip_addr, Ipv4Addr::new(127, 0, 0, 1));
    }
}
