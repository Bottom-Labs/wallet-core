use crate::KdfParams;
use crate::cache_derived_key::CacheDerivedKey;
use common::random_iv;
use bitcoin_hashes::hex::{ToHex, FromHex};
use serde::{Deserialize, Serialize};
use hash::{Keccak256, Hashable};
use crate::{Error, Result};

const CREDENTIAL_LEN: usize = 64usize;
pub type Credential = [u8; CREDENTIAL_LEN];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CipherParams {
    iv: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncPair {
    pub enc_str: String,
    pub nonce: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Crypto<T: KdfParams> {
    cipher: String,
    cipherparams: CipherParams,
    ciphertext: String,
    kdf: String,
    kdfparams: T,
    mac: String,
    #[serde(skip)]
    cached_derived_key: Option<CacheDerivedKey>,
}

pub enum Key {
    Password(String),
    DerivedKey(String),
}

impl<T> Crypto<T>
where
    T: KdfParams,
{
    pub fn new (password: &str, origin: &[u8]) -> Crypto<T> {
        let mut param = T::default();
        param.set_salt(&random_iv(32).to_hex());
        let iv = random_iv(16);

        let mut crypto = Crypto {
            cipher: "aes-128-ctr".to_string(),
            cipherparams: CipherParams {iv: iv.to_hex()},
            ciphertext: "".to_string(),
            kdf: T::key(),
            kdfparams: param,
            mac: "".to_string(),
            cached_derived_key: None
        };

        let derived_key = crypto
            .generate_derived_key(password)
            .expect("new crypto generate_derived_key");
        let ciphertext = crypto.encrypt(password, origin);
        crypto.ciphertext = ciphertext.to_hex();
        let mac = Self::generate_mac(&derived_key, &ciphertext);
        crypto.mac = mac.to_hex();
        crypto
    }

    pub fn verify_password(&self, password: &str) -> bool {
        let derived_key = self.generate_derived_key(password);
        derived_key.is_ok()
            && self.verify_derived_key(&derived_key.unwrap())
    }

    pub fn decrypt(&self, key: Key) -> Result<Vec<u8>> {
        let encrypted: Vec<u8> = FromHex::from_hex(&self.ciphertext).unwrap();
        let iv: Vec<u8> = FromHex::from_hex(&self.cipherparams.iv).unwrap();
        self.decrypt_data(key, &encrypted, &iv)
    }

    pub fn encrypt(&self, password: &str, origin: &[u8]) -> Vec<u8> {
        let derived_key = self
            .generate_derived_key(password)
            .unwrap();
        let key = &derived_key[0..16];
        let iv: Vec<u8> = FromHex::from_hex(&self.cipherparams.iv).unwrap();
        super::aes::aes::encrypt(origin, key, &iv)
            .expect("encrypt_nopadding key or iv's length must be 16")
    }

    pub fn generate_derived_key(&self, key: &str) -> Result<Vec<u8>> {
        if let Some(ckd) = &self.cached_derived_key{
            ckd.get_derived_key(key)
        } else {
            let mut derived_key: Credential = [0u8; CREDENTIAL_LEN];
            self.kdfparams
                .generate_derived_key(key.as_bytes(), &mut derived_key);
            if &self.mac != "" && !self.verify_derived_key(&derived_key) {
                return Err(Error::PasswordIncorrect.into());
            }
            Ok(derived_key.to_vec())
        }
    }

    pub fn derive_enc_pair(&self, password: &str, origin: &[u8]) -> Result<EncPair> {
        let iv = random_iv(16);
        let encrypted_data = self.encrypt_data(password, origin, &iv)?;
        Ok(
            EncPair {
                enc_str: encrypted_data.to_hex(),
                nonce: iv.to_hex(),
            })
    }

    pub fn decrypt_enc_pair(&self, key: Key, enc_pair: &EncPair) -> Result<Vec<u8>> {
        let encrypted: Vec<u8> = FromHex::from_hex(&enc_pair.enc_str).unwrap();
        let iv: Vec<u8> = FromHex::from_hex(&enc_pair.nonce).unwrap();
        self.decrypt_data(key, &encrypted, &iv)
    }

    fn encrypt_data(&self, password: &str, origin: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        let derived_key = self.generate_derived_key(password)?;
        if !self.verify_derived_key(&derived_key) {
            return Err(Error::PasswordIncorrect.into());
        }

        let key = &derived_key[0..16];
        super::aes::aes::encrypt(origin, key, &iv)
    }

    fn decrypt_data(&self, key: Key, encrypted: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        let derived_key: Vec<u8> = match key {
            Key::Password(password) => {
                let dk = self.generate_derived_key(&password)?;
                if !self.verify_derived_key(&dk) {
                    return Err(Error::PasswordIncorrect.into());
                } else {
                    dk
                }
            }
            Key::DerivedKey(dk) => {
                if !(cfg!(feature = "cache_dk")) {
                    return Err(Error::CachedDkFeatureNotSupport.into());
                } else {
                    let dk = hex::decode(dk)?;
                    if !self.verify_derived_key(&dk) {
                        return Err(Error::DerivedKeyNotMatched.into());
                    } else {
                        dk
                    }
                }
            }
        };

        let key = &derived_key[0..16];
        super::aes::aes::decrypt(encrypted, key, &iv)
    }

    pub fn verify_derived_key(&self, dk: &[u8]) -> bool {
        let bytes = Vec::from_hex(&self.ciphertext)
            .expect("vec::from_hex");
        let mac = Self::generate_mac(&dk, &bytes);
        self.mac == mac.to_hex()
    }

    fn generate_mac(derived_key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        let ret = [&derived_key[16..32], ciphertext].concat();
        Keccak256::hash(&ret)
    }

    pub fn cache_derived_key(&mut self, key: &str, derived_key: &[u8]) {
        let cdk = CacheDerivedKey::new(key, derived_key);
        self.cached_derived_key = Some(cdk);
    }

    pub fn clear_cache_derived_key(&mut self) {
        self.cached_derived_key = None;
    }
}