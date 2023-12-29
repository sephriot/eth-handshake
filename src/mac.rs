#![allow(missing_docs)]
use aes::Aes256Enc;
use alloy_primitives::{B128, B256};
use block_padding::NoPadding;
use cipher::BlockEncrypt;
use digest::KeyInit;
use generic_array::GenericArray;
use sha3::{Digest, Keccak256};
use typenum::U16;

pub type HeaderBytes = GenericArray<u8, U16>;

#[derive(Debug)]
pub struct MAC {
    secret: B256,
    hasher: Keccak256,
}

impl MAC {
    pub fn new(secret: B256) -> Self {
        Self {
            secret,
            hasher: Keccak256::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data)
    }

    pub fn update_header(&mut self, data: &HeaderBytes) {
        let aes = Aes256Enc::new_from_slice(self.secret.as_ref()).unwrap();
        let mut encrypted = self.digest().0;

        aes.encrypt_padded::<NoPadding>(&mut encrypted, B128::len_bytes())
            .unwrap();
        for i in 0..data.len() {
            encrypted[i] ^= data[i];
        }
        self.hasher.update(encrypted);
    }

    pub fn update_body(&mut self, data: &[u8]) {
        self.hasher.update(data);
        let prev = self.digest();
        let aes = Aes256Enc::new_from_slice(self.secret.as_ref()).unwrap();
        let mut encrypted = self.digest().0;

        aes.encrypt_padded::<NoPadding>(&mut encrypted, B128::len_bytes())
            .unwrap();
        for i in 0..16 {
            encrypted[i] ^= prev[i];
        }
        self.hasher.update(encrypted);
    }

    pub fn digest(&self) -> B128 {
        B128::from_slice(&self.hasher.clone().finalize()[..16])
    }
}
