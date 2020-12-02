use std::collections::HashMap;
use curve::ecc::{TypedDeterministicPrivateKey, TypedPrivateKey, TypedDeterministicPublicKey};
use crate::{Store, transform_mnemonic_error, Account, Metadata, Address};
use crate::{Result, Error};
use bip39::{Language, Mnemonic, Seed};
use hash::{Sha256d, Hashable};
use crypto::crypto::{Key, Crypto};
use curve::derive::{Derive, get_account_path};
use curve::rand::generate_mnemonic;
use crypto::kdf::Pbkdf2Params;
use uuid::Uuid;
use common::{CoinInfo};
use common::curve_type::CurveType;
use curve::ToHex;

struct Cache {
    mnemonic: String,
    keys: HashMap<String, TypedDeterministicPrivateKey>,
}

pub struct HdKeystore {
    store: Store,
    cache: Option<Cache>,
}

pub fn key_hash_from_mnemonic(mnemonic: &str) -> Result<String> {
    let mn = Mnemonic::from_phrase(mnemonic, Language::English)
        .map_err(transform_mnemonic_error)?;
    let seed = Seed::new(&mn, "");
    let bytes = Sha256d::hash(seed.as_bytes())[..20].to_vec();
    Ok(hex::encode(bytes))
}

impl HdKeystore {
    pub const VERSION: i64 = 11000i64;

    pub fn new(password: &str, meta: Metadata) -> HdKeystore {
        let mnemonic = generate_mnemonic();
        Self::from_mnemonic(&mnemonic, password, meta).unwrap()
    }

    pub(crate) fn store(&self) -> &Store { &self.store }
    pub(crate) fn store_mut(&mut self) -> &mut Store {&mut self.store}
    pub(crate) fn from_store(store: Store) -> Self {Self{ store, cache: None }}


    fn cache_mnemonic(&mut self, mnemonic_bytes: Vec<u8>) -> Result<()> {
        let mnemonic_str = String::from_utf8(mnemonic_bytes)?;
        let _mnemonic = Mnemonic::from_phrase(&mnemonic_str, Language::English)
            .map_err(transform_mnemonic_error)?;
        self.cache = Some(Cache {
            mnemonic: mnemonic_str,
            keys: HashMap::new(),
        });
        Ok(())
    }

    pub fn from_mnemonic(mnemonic: &str, password: &str, meta: Metadata) -> Result<Self> {
        let mnemonic: &str = &mnemonic.split_whitespace().collect::<Vec<&str>>().join(" ");
        let key_hash = key_hash_from_mnemonic(mnemonic)?;
        let crypto: Crypto<Pbkdf2Params> = Crypto::new(password, mnemonic.as_bytes());
        Ok(Self {
            store: Store {
                id: Uuid::new_v4().to_hyphenated().to_string(),
                version: Self::VERSION,
                key_hash,
                crypto,
                active_accounts: vec![],
                meta,
            },
            cache: None
        })
    }

    pub(crate) fn account(&self, symbol: &str, address: &str) -> Option<&Account> {
        self.store
            .active_accounts
            .iter()
            .find(|acc| acc.address == address && acc.coin == symbol)
    }

    pub(crate) fn unlock_by_password(&mut self, password: &str) -> Result<()> {
        let mnemonic_bytes = self.store
            .crypto.decrypt(Key::Password(password.to_owned()))?;
        self.cache_mnemonic(mnemonic_bytes)
    }

    pub(crate) fn unlock_by_derived_key(&mut self, derived_key: &str) -> Result<()> {
        let mnemonic_bytes = self.store
            .crypto.decrypt(Key::DerivedKey(derived_key.to_owned()))?;
        self.cache_mnemonic(mnemonic_bytes)
    }

    pub(crate) fn lock(&mut self) {self.cache = None;}

    pub(crate) fn is_locked(&self) -> bool {self.cache.is_none()}

    pub(crate) fn verify_password(&self, password: &str) -> bool {
        self.store.crypto.verify_password(password)
    }

    pub(crate) fn mnemonic(&self) -> Result<String> {
        let cache = self.cache.as_ref().ok_or(Error::KeystoreLocked)?;
        Ok(cache.mnemonic.to_string())
    }

    pub(crate) fn find_private_key(&self, symbol: &str, address: &str) -> Result<TypedPrivateKey> {
        let cache = self.cache.as_ref().ok_or(Error::KeystoreLocked)?;
        let account = self.account(symbol, address)
            .ok_or(Error::AccountNotFound)?;
        let root = TypedDeterministicPrivateKey::from_mnemonic(account.curve, &cache.mnemonic)?;
        Ok(root.derive(&account.derivation_path)?.private_key())
    }

    pub(crate) fn find_deterministic_public_key(&mut self, symbol: &str, address: &str) -> Result<TypedDeterministicPublicKey> {
        let account = self.account(symbol, address)
            .ok_or(Error::AccountNotFound)?;
        TypedDeterministicPublicKey::from_hex(account.curve, &account.ext_pub_key)
    }

    pub(crate) fn find_private_key_by_path(&mut self, symbol: &str, main_address: &str, relative_path: &str) -> Result<TypedPrivateKey> {
        let cache = self.cache.as_ref().ok_or(Error::KeystoreLocked)?;
        if !cache.keys.contains_key(main_address) {
            let account = self.account(symbol, main_address)
                .ok_or(Error::AccountNotFound)?;
            let esk = TypedDeterministicPrivateKey::from_mnemonic(account.curve, &cache.mnemonic)?;
            let k = esk.derive(&get_account_path(&account.derivation_path)?)?;
            self.cache
                .as_mut()
                .unwrap()
                .keys
                .insert(main_address.to_owned(), k);
        }

        let esk = &self.cache.as_ref().unwrap().keys[main_address];
        Ok(esk.derive(relative_path)?.private_key())
    }

    pub(crate) fn derive_coin<A: Address>(&mut self, coin_info: &CoinInfo) -> Result<Account> {
        let cache = self.cache.as_ref().ok_or(Error::KeystoreLocked)?;
        let root = TypedDeterministicPrivateKey::from_mnemonic(coin_info.curve, &cache.mnemonic)?;
        let private_key = root.derive(&coin_info.derivation_path)?.private_key();
        let public_key = private_key.public_key();
        let address = A::from_public_key(&public_key, coin_info)?;
        let ext_pub_key = match coin_info.curve {
            CurveType::SubSr25519 => "".to_owned(),
            _ => root
                .derive(&get_account_path(&coin_info.derivation_path)?)?
                .deterministic_public_key()
                .to_hex(),
        };
        let account = Account {
            address,
            derivation_path: coin_info.derivation_path.to_string(),
            curve: coin_info.curve,
            coin: coin_info.coin.to_string(),
            network: coin_info.network.to_string(),
            seg_wit: coin_info.seg_wit.to_string(),
            ext_pub_key
        };
        if let Some(_) = self.store
            .active_accounts
            .iter()
            .find(|x| x.address == account.address && x.coin == account.coin) {
            return Ok(account)
        } else {
            self.store.active_accounts.push(account.clone());
            Ok(account)
        }
    }
}