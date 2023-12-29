use alloy_primitives::{hex, B256, B512};
use hmac::Hmac;
use sha2::Sha256;
use sha2::Digest;
use secp256k1::{SecretKey, PublicKey};
use hmac::Mac;

pub fn peer_id_2_public_key(peer_id: &str) -> secp256k1::PublicKey {
    // SECP256K1_TAG_PUBKEY_UNCOMPRESSED = 0x04
    // see: https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1.h#L221
    let decoded_server_peer_id = hex::decode(peer_id).expect("Decoding peer id to hex slice failed");
    let mut s: [u8; 65] = [0u8; 65];
    s[0] = 4;
    s[1..].copy_from_slice(decoded_server_peer_id.as_slice());
    return PublicKey::from_slice(&s).expect("Cannot decode public key from peer id")
}

pub fn id2pk(id: B512) -> Result<PublicKey, secp256k1::Error> {
    let mut s = [0u8; 65];
    // SECP256K1_TAG_PUBKEY_UNCOMPRESSED = 0x04
    // see: https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1.h#L211
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
        let ctrs = [(ctr >> 24) as u8, (ctr >> 16) as u8, (ctr >> 8) as u8, ctr as u8];
        hasher.update(ctrs);
        hasher.update(secret.as_slice());
        hasher.update(s1);
        let d = hasher.finalize();
        dest[written..(written + 32)].copy_from_slice(&d);
        written += 32;
        ctr += 1;
    }
}