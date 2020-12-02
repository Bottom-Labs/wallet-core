use crate::ecc::{KeyError, PrivateKey as TraitPrivateKey, PublicKey as TraitPublicKey};
use bitcoin::util::key::{PrivateKey, PublicKey};
use bitcoin::util::base58;
use crate::{Result, Ss58Codec};
use bitcoin::Network;
use crate::constant::SECP256K1_ENGINE;
use secp256k1::Message;
use failure::_core::fmt::Formatter;

fn transform_secp256k1_error(err: secp256k1::Error) -> KeyError {
    match err {
        secp256k1::Error::IncorrectSignature => KeyError::InvalidSignature,
        secp256k1::Error::InvalidMessage => KeyError::InvalidMessage,
        secp256k1::Error::InvalidPublicKey => KeyError::InvalidPublicKey,
        secp256k1::Error::InvalidSignature => KeyError::InvalidSignature,
        secp256k1::Error::InvalidSecretKey => KeyError::InvalidPrivateKey,
        secp256k1::Error::InvalidRecoveryId => KeyError::InvalidRecoveryId,
        secp256k1::Error::InvalidTweak => KeyError::InvalidTweak,
        secp256k1::Error::NotEnoughMemory => KeyError::NotEnoughMemory,
    }
}

#[derive(Clone)]
pub struct Secp256k1PublicKey(pub PublicKey);

impl From<PublicKey> for Secp256k1PublicKey {
    fn from(pk: PublicKey) -> Self {
        Secp256k1PublicKey(pk)
    }
}

#[derive(Clone)]
pub struct Secp256k1PrivateKey(pub PrivateKey);

impl From<PrivateKey> for Secp256k1PrivateKey{
    fn from(sk: PrivateKey) -> Self {
        Self(sk)
    }
}

impl Secp256k1PublicKey {
    pub fn to_compressed(&self) -> Vec<u8> {
        self.0.key.serialize().to_vec()
    }

    pub fn to_uncompressed(&self) -> Vec<u8> {
        self.0.key.serialize_uncompressed().to_vec()
    }
}

impl Secp256k1PrivateKey {
    pub fn from_wif(wif: &str) -> Result<Self> {

    }
}

impl TraitPrivateKey for Secp256k1PrivateKey {
    type PublicKey = Secp256k1PublicKey;

    fn from_slice(data: &[u8]) -> Result<Self> {
        let key = secp256k1::SecretKey::from_slice(data)
            .map_err(transform_secp256k1_error)?;
        Ok(Self(PrivateKey{
            key,
            compressed: true,
            network: Network::Bitcoin,
        }))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    fn public_key(&self) -> Self::PublicKey {
        Secp256k1PublicKey(self.0.public_key(&SECP256K1_ENGINE))
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let msg = Message::from_slice(data)
            .map_err(transform_secp256k1_error)?;
        let signature = SECP256K1_ENGINE.sign(&msg, &self.0.key);
        Ok(signature.serialize_der().to_vec())
    }

    fn sign_recoverable(&self, data: &[u8]) -> Result<Vec<u8>> {
        let msg = Message::from_slice(data)
            .map_err(transform_secp256k1_error)?;
        let signature = SECP256K1_ENGINE.sign_recoverable(&msg, &self.0.key);
        let (recover_id, sign) = signature.serialize_compact();
        let signed_bytes = [sign[..].to_vec(), vec![(recover_id.to_i32()) as u8]]
            .concat();
        Ok(signed_bytes)
    }
}

impl std::fmt::Display for Secp256k1PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::std::fmt::Result {
        self.0.key.fmt(f)
    }
}

impl TraitPublicKey for Secp256k1PublicKey {
    fn from_slice(data: &[u8]) -> Result<Self> {
        let key = PublicKey::from_slice(data)?;
        Ok(Secp256k1PublicKey(key))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

impl Ss58Codec for Secp256k1PrivateKey {
    fn from_ss58check_with_version(wif: &str) -> Result<(Self, Vec<u8>)> {
        let data = base58::from_check(wif)?;
        let compressed = match data.len() {
            33 => false,
            34 => true,
            _ => {
                return Err(KeyError::InvalidPrivateKey.into());
            }
        };

        let pk = Self(PrivateKey{
            key: secp256k1::SecretKey::from_slice(&data[1..33])?,
            compressed,
            network: Network::Bitcoin,
        });

        Ok((pk, vec![data[0]]))
    }

    fn to_ss58check_with_version(&self, version: &[u8]) -> String {
        let mut ret = [0; 34];
        ret[0..1].copy_from_slice(&version[0..]);
        ret[1..33].copy_from_slice(&self.0.key[..]);
        if self.0.compressed {
            ret[33] = 1;
            base58::check_encode_slice(&ret[..]).to_string()
        } else {
            base58::check_encode_slice(&ret[..33]).to_string()
        }
    }
}