use aes::Aes256;
use aes::{cipher::StreamCipher, Aes128};
use alloy_primitives::{B128, B256, B512};
use alloy_rlp::{Encodable, Rlp, RlpEncodable};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use bytes::{BufMut, Bytes, BytesMut};
use ctr::cipher::KeyIvInit;
use ctr::Ctr64BE;
use rand::{thread_rng, Rng};
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use sha3::Digest;
use sha3::Keccak256;

use crate::error::ECIESError;
use crate::mac::{HeaderBytes, MAC};
use crate::util::{ecdh_x, hmac_sha256, id2pk, kdf, pk2id, sha256};

const PROTOCOL_VERSION: usize = 4;

fn split_at_mut<T>(arr: &mut [T], idx: usize) -> Result<(&mut [T], &mut [T]), ECIESError> {
    if idx > arr.len() {
        return Err(ECIESError::OutOfBounds {
            idx,
            len: arr.len(),
        }
        .into());
    }
    Ok(arr.split_at_mut(idx))
}

pub struct ECIES {
    secret_key: SecretKey,
    public_key: PublicKey,
    ephemeral_secret_key: SecretKey,

    ephemeral_shared_secret: Option<B256>,

    remote_public_key: Option<PublicKey>,
    remote_ephemeral_public_key: Option<PublicKey>,

    nonce: B256,
    remote_nonce: Option<B256>,

    init_msg: Option<Bytes>,
    remote_init_msg: Option<Bytes>,

    ingress_aes: Option<Ctr64BE<Aes256>>,
    egress_aes: Option<Ctr64BE<Aes256>>,
    ingress_mac: Option<MAC>,
    egress_mac: Option<MAC>,

    body_size: Option<usize>,
}

impl ECIES {
    pub fn new_client(remote_id: B512) -> Self {
        let mut rng = thread_rng();
        let nonce = rng.gen();
        let secret_key = SecretKey::new(&mut rng);
        let ephemeral_secret_key = SecretKey::new(&mut rng);
        let public_key = PublicKey::from_secret_key(SECP256K1, &secret_key);
        let remote_public_key = id2pk(remote_id).unwrap();

        Self {
            secret_key,
            public_key,
            ephemeral_secret_key,
            nonce,

            remote_public_key: Some(remote_public_key),
            remote_ephemeral_public_key: None,
            remote_nonce: None,
            ephemeral_shared_secret: None,
            init_msg: None,
            remote_init_msg: None,

            body_size: None,
            egress_aes: None,
            ingress_aes: None,
            egress_mac: None,
            ingress_mac: None,
        }
    }

    pub fn peer_id(&self) -> B512 {
        return pk2id(&self.public_key);
    }

    pub fn encrypt_message(&self, data: &[u8], out: &mut BytesMut) {
        let mut rng = thread_rng();

        out.reserve(secp256k1::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE + 16 + data.len() + 32);

        let secret_key = SecretKey::new(&mut rng);
        out.extend_from_slice(
            &PublicKey::from_secret_key(SECP256K1, &secret_key).serialize_uncompressed(),
        );

        let x = ecdh_x(&self.remote_public_key.unwrap(), &secret_key);
        let mut key = [0u8; 32];
        kdf(x, &[], &mut key);

        let enc_key = B128::from_slice(&key[..16]);
        let mac_key = sha256(&key[16..32]);

        let iv: B128 = rng.gen();
        let mut encryptor = Ctr64BE::<Aes128>::new((&enc_key.0).into(), (&iv.0).into());

        let mut encrypted = data.to_vec();
        encryptor.apply_keystream(&mut encrypted);

        let total_size: u16 = u16::try_from(65 + 16 + data.len() + 32).unwrap();

        let tag = hmac_sha256(
            mac_key.as_ref(),
            &[iv.as_slice(), &encrypted],
            &total_size.to_be_bytes(),
        );

        out.extend_from_slice(iv.as_slice());
        out.extend_from_slice(&encrypted);
        out.extend_from_slice(tag.as_ref());
    }

    pub fn decrypt_message<'a>(&self, data: &'a mut [u8]) -> Result<&'a mut [u8], ECIESError> {
        let (auth_data, encrypted) = split_at_mut(data, 2)?;
        let (pubkey_bytes, encrypted) = split_at_mut(encrypted, 65)?;
        let public_key = PublicKey::from_slice(pubkey_bytes)?;
        let (data_iv, tag_bytes) = split_at_mut(encrypted, encrypted.len() - 32)?;
        let (iv, encrypted_data) = split_at_mut(data_iv, 16)?;
        let tag = B256::from_slice(tag_bytes);

        let x = ecdh_x(&public_key, &self.secret_key);
        let mut key = [0u8; 32];
        kdf(x, &[], &mut key);
        let enc_key = B128::from_slice(&key[..16]);
        let mac_key = sha256(&key[16..32]);

        let check_tag = hmac_sha256(mac_key.as_ref(), &[iv, encrypted_data], auth_data);
        if check_tag != tag {
            return Err(ECIESError::TagCheckDecryptFailed.into());
        }

        let decrypted_data = encrypted_data;

        let mut decryptor = Ctr64BE::<Aes128>::new((&enc_key.0).into(), (*iv).into());
        decryptor.apply_keystream(decrypted_data);

        Ok(decrypted_data)
    }

    pub fn create_auth_unencrypted(&self) -> BytesMut {
        let x = ecdh_x(&self.remote_public_key.unwrap(), &self.secret_key);
        let msg = x ^ self.nonce;
        let (rec_id, sig) = SECP256K1
            .sign_ecdsa_recoverable(
                &secp256k1::Message::from_digest_slice(msg.as_slice()).unwrap(),
                &self.ephemeral_secret_key,
            )
            .serialize_compact();

        let mut sig_bytes = [0u8; 65];
        sig_bytes[..64].copy_from_slice(&sig);
        sig_bytes[64] = rec_id.to_i32() as u8;

        let id = pk2id(&self.public_key);

        #[derive(RlpEncodable)]
        struct S<'a> {
            sig_bytes: &'a [u8; 65],
            id: &'a B512,
            nonce: &'a B256,
            protocol_version: u8,
        }

        let mut out = BytesMut::new();
        S {
            sig_bytes: &sig_bytes,
            id: &id,
            nonce: &self.nonce,
            protocol_version: PROTOCOL_VERSION as u8,
        }
        .encode(&mut out);

        out.resize(out.len() + thread_rng().gen_range(100..=300), 0);
        out
    }

    pub fn create_auth(&mut self) -> BytesMut {
        let mut buf = BytesMut::new();
        self.write_auth(&mut buf);
        buf
    }

    pub fn write_auth(&mut self, buf: &mut BytesMut) {
        let unencrypted = self.create_auth_unencrypted();

        let mut out = buf.split_off(buf.len());
        out.put_u16(0);

        let mut encrypted = out.split_off(out.len());
        self.encrypt_message(&unencrypted, &mut encrypted);

        let len_bytes = u16::try_from(encrypted.len()).unwrap().to_be_bytes();
        out[..len_bytes.len()].copy_from_slice(&len_bytes);

        out.unsplit(encrypted);

        self.init_msg = Some(Bytes::copy_from_slice(&out));

        buf.unsplit(out);
    }

    pub fn parse_ack_unencrypted(&mut self, data: &[u8]) -> Result<(), ECIESError> {
        let mut data = Rlp::new(data)?;
        self.remote_ephemeral_public_key =
            Some(id2pk(data.get_next()?.ok_or(ECIESError::InvalidAckData)?)?);
        self.remote_nonce = Some(data.get_next()?.ok_or(ECIESError::InvalidAckData)?);

        self.ephemeral_shared_secret = Some(ecdh_x(
            &self.remote_ephemeral_public_key.unwrap(),
            &self.ephemeral_secret_key,
        ));
        Ok(())
    }

    /// Read and verify an ack message from the input data.
    pub fn read_ack(&mut self, data: &mut [u8]) -> Result<(), ECIESError> {
        self.remote_init_msg = Some(Bytes::copy_from_slice(data));
        let unencrypted = self.decrypt_message(data)?;
        self.parse_ack_unencrypted(unencrypted)?;
        self.setup_frame(false);
        Ok(())
    }

    pub fn setup_frame(&mut self, incoming: bool) {
        let mut hasher = Keccak256::new();
        for el in &if incoming {
            [self.nonce, self.remote_nonce.unwrap()]
        } else {
            [self.remote_nonce.unwrap(), self.nonce]
        } {
            hasher.update(el);
        }
        let h_nonce = B256::from(hasher.finalize().as_ref());

        let iv = B128::default();
        let shared_secret: B256 = {
            let mut hasher = Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.unwrap().0.as_ref());
            hasher.update(h_nonce.0.as_ref());
            B256::from(hasher.finalize().as_ref())
        };

        let aes_secret: B256 = {
            let mut hasher = Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.unwrap().0.as_ref());
            hasher.update(shared_secret.0.as_ref());
            B256::from(hasher.finalize().as_ref())
        };
        self.ingress_aes = Some(Ctr64BE::<Aes256>::new(
            (&aes_secret.0).into(),
            (&iv.0).into(),
        ));
        self.egress_aes = Some(Ctr64BE::<Aes256>::new(
            (&aes_secret.0).into(),
            (&iv.0).into(),
        ));

        let mac_secret: B256 = {
            let mut hasher = Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.unwrap().0.as_ref());
            hasher.update(aes_secret.0.as_ref());
            B256::from(hasher.finalize().as_ref())
        };
        self.ingress_mac = Some(MAC::new(mac_secret));
        self.ingress_mac
            .as_mut()
            .unwrap()
            .update((mac_secret ^ self.nonce).as_ref());
        self.ingress_mac
            .as_mut()
            .unwrap()
            .update(self.remote_init_msg.as_ref().unwrap());
        self.egress_mac = Some(MAC::new(mac_secret));
        self.egress_mac
            .as_mut()
            .unwrap()
            .update((mac_secret ^ self.remote_nonce.unwrap()).as_ref());
        self.egress_mac
            .as_mut()
            .unwrap()
            .update(self.init_msg.as_ref().unwrap());
    }

    pub fn create_header(&mut self, size: usize) -> BytesMut {
        let mut out = BytesMut::new();
        self.write_header(&mut out, size);
        out
    }

    pub fn write_header(&mut self, out: &mut BytesMut, size: usize) {
        let mut buf = [0u8; 8];
        BigEndian::write_uint(&mut buf, size as u64, 3);
        let mut header = [0u8; 16];
        header[..3].copy_from_slice(&buf[..3]);
        header[3..6].copy_from_slice(&[194, 128, 128]);

        let mut header = HeaderBytes::from(header);
        self.egress_aes
            .as_mut()
            .unwrap()
            .apply_keystream(&mut header);
        self.egress_mac.as_mut().unwrap().update_header(&header);
        let tag = self.egress_mac.as_mut().unwrap().digest();

        out.reserve(ECIES::header_len());
        out.extend_from_slice(&header);
        out.extend_from_slice(tag.as_slice());
    }

    pub fn read_header(&mut self, data: &mut [u8]) -> Result<usize, ECIESError> {
        let (header_bytes, mac_bytes) = split_at_mut(data, 16)?;
        let header = HeaderBytes::from_mut_slice(header_bytes);
        let mac = B128::from_slice(&mac_bytes[..16]);

        self.ingress_mac.as_mut().unwrap().update_header(header);
        let check_mac = self.ingress_mac.as_mut().unwrap().digest();
        if check_mac != mac {
            return Err(ECIESError::TagCheckHeaderFailed.into());
        }

        self.ingress_aes.as_mut().unwrap().apply_keystream(header);
        if header.as_slice().len() < 3 {
            return Err(ECIESError::InvalidHeader.into());
        }

        let body_size = usize::try_from(header.as_slice().read_uint::<BigEndian>(3)?)?;

        self.body_size = Some(body_size);

        Ok(self.body_size.unwrap())
    }

    pub const fn header_len() -> usize {
        32
    }

    pub fn write_body(&mut self, out: &mut BytesMut, data: &[u8]) {
        let len = if data.len() % 16 == 0 {
            data.len()
        } else {
            (data.len() / 16 + 1) * 16
        };
        let old_len = out.len();
        out.resize(old_len + len, 0);

        let encrypted = &mut out[old_len..old_len + len];
        encrypted[..data.len()].copy_from_slice(data);

        self.egress_aes.as_mut().unwrap().apply_keystream(encrypted);
        self.egress_mac.as_mut().unwrap().update_body(encrypted);
        let tag = self.egress_mac.as_mut().unwrap().digest();

        out.extend_from_slice(tag.as_slice());
    }

    pub fn read_body<'a>(&mut self, data: &'a mut [u8]) -> Result<&'a mut [u8], ECIESError> {
        let (body, mac_bytes) = split_at_mut(data, data.len() - 16)?;
        let mac = B128::from_slice(mac_bytes);
        self.ingress_mac.as_mut().unwrap().update_body(body);
        let check_mac = self.ingress_mac.as_mut().unwrap().digest();
        if check_mac != mac {
            return Err(ECIESError::TagCheckBodyFailed.into());
        }

        let size = self.body_size.unwrap();
        self.body_size = None;
        let ret = body;
        self.ingress_aes.as_mut().unwrap().apply_keystream(ret);
        Ok(split_at_mut(ret, size)?.0)
    }
}
