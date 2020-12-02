use crate::ecc::{KeyError, PrivateKey as TraitPrivateKey, PublicKey as TraitPublicKey, PrivateKey};
use crate::{FromHex, Result, ToHex};
use sp_core::sr25519::{Public, Pair};
use sp_core::{Pair as TraitPair, Public as TraitPublic};
use schnorrkel::SecretKey;
use failure::_core::fmt::Formatter;

#[derive(Clone)]
pub struct Sr25519PublicKey(pub Public);

#[derive(Clone)]
pub struct Sr25519PrivateKey(pub Pair);

impl From<Public> for Sr25519PublicKey {
    fn from(pk: Public) -> Self {
        Self(pk)
    }
}

impl From<Pair> for Sr25519PrivateKey {
    fn from(sk: Pair) -> Self {
        Self(sk)
    }
}

impl TraitPrivateKey for Sr25519PrivateKey {
    type PublicKey = Sr25519PublicKey;

    fn from_slice(data: &[u8]) -> Result<Self> {
        let pk = SecretKey::from_ed25519_bytes(data)
            .map_err(|_| KeyError::InvalidSr25519Key)?;
        Ok(Self(Pair::from(pk)))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_raw_vec()
    }

    fn public_key(&self) -> Self::PublicKey {
        Sr25519PublicKey(self.0.public())
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(self.0.sign(data).0.to_vec())
    }

    fn sign_recoverable(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.sign(data)
    }
}

impl std::fmt::Display for Sr25519PublicKey {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        self.0.fmt(f)
    }
}

impl TraitPublicKey for Sr25519PublicKey {
    fn from_slice(data: &[u8]) -> Result<Self> {
        Ok(Self(Public::from_slice(data)))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl ToHex for Sr25519PublicKey {
    fn to_hex(&self) -> String {
        hex::encode(self.0.to_raw_vec())
    }
}

impl FromHex for Sr25519PublicKey {
    fn from_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex)?;
        let pk = Self::from_slice(bytes.as_slice())?;
        Ok(pk)
    }
}