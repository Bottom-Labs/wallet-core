pub mod hd;
pub mod private;
pub mod guard;

use curve::ecc::{TypedPublicKey, TypedPrivateKey, TypedDeterministicPublicKey};
use core::result;
use common::CoinInfo;
use common::curve_type::CurveType;
use std::time::{SystemTime, UNIX_EPOCH};
use crypto::crypto::Crypto;
use crypto::kdf::Pbkdf2Params;
use crate::private::PrivateKeystore;
use crate::hd::HdKeystore;

pub type Result<T> = result::Result<T, failure::Error>;

#[macro_use]
extern crate common;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Store {
    pub id: String,
    pub version: i64,
    pub key_hash: String,
    pub crypto: Crypto<Pbkdf2Params>,
    pub active_accounts: Vec<Account>,

    #[serde(rename = "imTokenMeta")]
    pub meta: Metadata,
}

#[derive(Fail, Debug, PartialOrd, PartialEq)]
pub enum Error {
    #[fail(display = "mnemonic_invalid")]
    MnemonicInvalid,
    #[fail(display = "mnemonic_word_invalid")]
    MnemonicWordInvalid,
    #[fail(display = "mnemonic_length_invalid")]
    MnemonicLengthInvalid,
    #[fail(display = "mnemonic_checksum_invalid")]
    MnemonicChecksumInvalid,
    #[fail(display = "account_not_found")]
    AccountNotFound,
    #[fail(display = "can_not_derive_key")]
    CannotDeriveKey,
    #[fail(display = "keystore_locked")]
    KeystoreLocked,
    #[fail(display = "invalid_version")]
    InvalidVersion,
    #[fail(display = "pkstore_can_not_add_other_curve_account")]
    PkstoreCannotAddOtherCurveAccount,
}

fn transform_mnemonic_error(err: failure::Error) -> Error {
    let err = err.downcast::<bip39::ErrorKind>().unwrap();
    match err {
        bip39::ErrorKind::InvalidChecksum => Error::MnemonicChecksumInvalid,
        bip39::ErrorKind::InvalidWord => Error::MnemonicWordInvalid,
        bip39::ErrorKind::InvalidWordLength(_) => Error::MnemonicLengthInvalid,
        _ => Error::MnemonicInvalid,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub address: String,
    pub derivation_path: String,
    pub curve: CurveType,
    pub coin: String,
    pub network: String,
    pub seg_wit: String,
    pub ext_pub_key: String,
}

pub trait Address {
    fn from_public_key(public_key: &TypedPublicKey, coin: &CoinInfo) -> Result<String>;

    fn is_valid(address: &str, coin: &CoinInfo) -> bool;
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Source {
    Wif,
    Private,
    Keystore,
    Mnemonic,
    NewIdentity,
    RecoveredIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub name: String,
    pub password_hint: String,
    #[serde(default = "metadata_default_time")]
    pub timestamp: i64,
    #[serde(default = "metadata_default_source")]
    pub source: Source,
}

fn metadata_default_time() -> i64 {
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("get timestamp");
    since_the_epoch.as_secs() as i64
}

fn metadata_default_source() -> Source {
    Source::Mnemonic
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            name: "Unknown".to_string(),
            password_hint: String::new(),
            timestamp: metadata_default_time(),
            source: Source::Mnemonic
        }
    }
}

pub enum Keystore {
    PrivateKey(PrivateKeystore),
    Hd(HdKeystore),
}

impl Keystore {
    pub fn from_private_key(private_key: &str, password: &str, meta: Metadata) -> Keystore {
        Self::PrivateKey(PrivateKeystore::from_private_key(
            private_key,
            password,
            meta,
        ))
    }

    pub fn from_mnemonic(mnemonic: &str, password: &str, metadata: Metadata) -> Result<Keystore> {
        Ok(Keystore::Hd(HdKeystore::from_mnemonic(
            mnemonic,
            password,
            metadata,
        )?))
    }

    pub fn id(&self) -> String {self.store().id.to_string()}

    pub fn set_id(&mut self, id: &str) {self.store_mut().id = id.to_string()}

    fn store(&self) -> &Store {
        match self {
            Self::PrivateKey(ks) => ks.store(),
            Self::Hd(ks) => ks.store(),
        }
    }

    fn store_mut(&mut self) -> &mut Store {
        match self {
            Self::PrivateKey(ks) => ks.store_mut(),
            Self::Hd(ks) => ks.store_mut(),
        }
    }

    pub fn meta(&self) -> Metadata {
        self.store().meta.clone()
    }

    pub fn key_hash(&self) -> String {self.store().key_hash.to_string()}

    pub fn unlock_by_password(&mut self, password: &str) -> Result<()> {
        match self {
            Self::PrivateKey(ks) => ks.unlock_by_password(password),
            Self::Hd(ks) => ks.unlock_by_password(password),
        }
    }

    pub fn unlock_by_derived_key(&mut self, derived_key: &str) -> Result<()> {
        match self {
            Self::PrivateKey(ks) => ks.unlock_by_derived_key(derived_key),
            Self::Hd(ks) => ks.unlock_by_derived_key(derived_key),
        }
    }

    #[cfg(feature = "cache_dk")]
    pub fn get_derived_key(&self, password: &str) -> Result<String> {
        self.store()
            .crypto
            .generate_derived_key(password)
            .map(|arr| hex::encode(arr))
    }

    pub fn is_locked(&self) -> bool {
        match self {
            Self::PrivateKey(ks) => ks.is_locked(),
            Self::Hd(ks) => ks.is_locked(),
        }
    }

    pub fn determinable(&self) -> bool {
        match self {
            Self::PrivateKey(_) => false,
            Self::Hd(_) => true,
        }
    }

    pub fn export(&self) -> Result<String> {
        match self {
            Self::PrivateKey(pk_store) => pk_store.private_key(),
            Self::Hd(hd_store) => hd_store.mnemonic(),
        }
    }

    pub fn export_private_key(&mut self, coin: &str, main_address: &str, path: Option<&str>) -> Result<String> {
        match self {
            Self::PrivateKey(pk_store) => {
                let _ = pk_store
                    .account(coin, main_address)
                    .ok_or(Error::AccountNotFound)?;
                pk_store.private_key()
            }
            Self::Hd(hd_store) => {
                let typed_pk = if let Some(path) = path {
                    hd_store.find_private_key_by_path(coin, main_address, path)?
                } else {
                    hd_store.find_private_key(coin, main_address)?
                };
                Ok(hex::encode(typed_pk.to_bytes()))
            }
        }
    }

    pub fn lock(&mut self) {
        match self {
            Self::PrivateKey(ks) => ks.lock(),
            Self::Hd(ks) => ks.lock(),
        }
    }

    pub fn derive_coin<A: Address>(&mut self, coin_info: &CoinInfo) -> Result<Account> {
        match self {
            Self::PrivateKey(ks) => ks.derive_coin::<A>(coin_info),
            Self::Hd(ks) => ks.derive_coin::<A>(coin_info),
        }
    }

    pub fn find_private_key(&mut self, symbol: &str, address: &str) -> Result<TypedPrivateKey> {
        match self {
            Self::PrivateKey(ks) => ks.find_private_key(address),
            Self::Hd(ks) => ks.find_private_key(symbol, address),
        }
    }

    pub fn find_private_key_by_path(&mut self, symbol: &str, address: &str, path: &str) -> Result<TypedPrivateKey> {
        match self {
            Self::Hd(ks) => ks.find_private_key_by_path(symbol, address, path),
            Self::PrivateKey(ks) => ks.find_private_key(address),
        }
    }

    pub fn find_deterministic_public_key(&mut self, symbol: &str, address: &str) -> Result<TypedDeterministicPublicKey> {
        match self {
            Self::Hd(ks) => ks.find_deterministic_public_key(symbol, address),
            _ => Err(Error::CannotDeriveKey.into()),
        }
    }

    pub fn account(&self, symbol: &str, address: &str) -> Option<&Account> {
        match self {
            Self::PrivateKey(ks) => ks.account(symbol, address),
            Self::Hd(ks) => ks.account(symbol, address),
        }
    }

    pub fn accounts(&self) -> &[Account] {
        match self {
            Self::PrivateKey(ks) => ks.store().active_accounts.as_slice(),
            Self::Hd(ks) => ks.store().active_accounts.as_slice(),
        }
    }

    pub fn verify_password(&self, password: &str) -> bool {
        match self {
            Self::PrivateKey(ks) => ks.verify_password(password),
            Self::Hd(ks) => ks.verify_password(password),
        }
    }

    pub fn from_json(json: &str) -> Result<Keystore> {
        let store: Store = serde_json::from_str(json)?;
        match store.version {
            HdKeystore::VERSION => Ok(Self::Hd(HdKeystore::from_store(store))),
            PrivateKeystore::VERSION => {
                Ok(Self::PrivateKey(PrivateKeystore::from_store(store)))
            }
            _ => Err(Error::InvalidVersion.into()),
        }
    }

    pub fn to_json(&self) -> String {
        match self {
            Self::PrivateKey(ks) => serde_json::to_string(ks.store()).unwrap(),
            Self::Hd(ks) => serde_json::to_string(ks.store()).unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
