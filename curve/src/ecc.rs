use crate::Result;
use crate::derive::Derive;
use crate::{ToHex, FromHex};
use crate::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use crate::sr25519::{Sr25519PrivateKey, Sr25519PublicKey};
use common::curve_type::CurveType;
use std::path::Component::CurDir;
use crate::bip32::{Bip32DeterministicPublicKey, Bip32DeterministicPrivateKey};
use crate::ecc::TypedDeterministicPrivateKey::{Bip32Secp256k1, SubSr25519};
use sp_core::Pair;

#[derive(Fail, Debug, PartialEq)]
pub enum KeyError {
    #[fail(display = "invalid_ecdsa")]
    InvalidEcdsa,
    #[fail(display = "invalid_child_number_format")]
    InvalidChildNumberFormat,
    #[fail(display = "overflow_child_number")]
    OverflowChildNumber,
    #[fail(display = "invalid_derivation_path_format")]
    InvalidDerivationPathFormat,
    #[fail(display = "invalid_signature")]
    InvalidSignature,
    #[fail(display = "invalid_child_number")]
    InvalidChildNumber,
    #[fail(display = "cannot_derive_from_hardened_key")]
    CannotDeriveFromHardenedKey,
    #[fail(display = "cannot_derive_key")]
    InvalidBase58,
    #[fail(display = "invalid_private_key")]
    InvalidPrivateKey,
    #[fail(display = "invalid_public_key")]
    InvalidPublicKey,
    #[fail(display = "invalid_message")]
    InvalidMessage,
    #[fail(display = "invalid_recovery_id")]
    InvalidRecoveryId,
    #[fail(display = "invalid_tweak")]
    InvalidTweak,
    #[fail(display = "not_enough_memory")]
    NotEnoughMemory,
    #[fail(display = "invalid_curve_type")]
    InvalidCurveType,
    #[fail(display = "invalid_sr25519_key")]
    InvalidSr25519Key,
}

pub trait PublicKey: Sized {
    fn from_slice(data: &[u8]) -> Result<Self>;
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait PrivateKey: Sized {
    type PublicKey: PublicKey;

    fn from_slice(data: &[u8]) -> Result<Self>;
    fn to_bytes(&self) -> Vec<u8>;

    fn public_key(&self) -> Self::PublicKey;
    fn sign(&self, _: &[u8]) -> Result<Vec<u8>>;
    fn sign_recoverable(&self, data: &[u8]) -> Result<Vec<u8>>;
}

pub trait DeterministicPublicKey: Derive + ToHex + FromHex {
    type PublicKey: PublicKey;

    fn public_key(&self) -> Self::PublicKey;
}

pub trait DeterministicPrivateKey: Derive {
    type DeterministicPublicKey: DeterministicPublicKey;
    type PrivateKey: PrivateKey;

    fn from_seed(seed: &[u8]) -> Result<Self>;
    fn from_mnemonic(mnemonic: &str) -> Result<Self>;
    fn private_key(&self) -> Self::PrivateKey;
    fn deterministic_public_key(&self) -> Self::DeterministicPublicKey;
}

pub trait TypedPrivateKeyDisplay {
    fn fmt(data: &[u8], network: &str) -> Result<String>;
}

pub enum TypedPrivateKey {
    Secp256k1(Secp256k1PrivateKey),
    Sr25519(Sr25519PrivateKey),
}

impl TypedPrivateKey {
    pub fn curve_type(&self) -> CurveType {
        match self {
            TypedPrivateKey::Secp256k1(_) => CurveType::SECP256k1,
            TypedPrivateKey::Sr25519(_) => CurveType::SubSr25519,
        }
    }

    pub fn from_slice(curve_type: CurveType, data: &[u8]) -> Result<TypedPrivateKey> {
        match curve_type {
            CurveType::SECP256k1 => Ok(TypedPrivateKey::Secp256k1(
                Secp256k1PrivateKey::from_slice(data)?,
            )),
            CurveType::SubSr25519 => Ok(TypedPrivateKey::Sr25519(
                Sr25519PrivateKey::from_slice(data)?,
            )),
            _ => Err(KeyError::InvalidCurveType.into()),
        }
    }

    pub fn as_secp256k1(&self) -> Result<&Secp256k1PrivateKey> {
        match self {
            TypedPrivateKey::Secp256k1(sk) => Ok(sk),
            _ => Err(KeyError::InvalidCurveType.into()),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            TypedPrivateKey::Secp256k1(sk) => sk.to_bytes(),
            TypedPrivateKey::Sr25519(sk) => sk.to_bytes(),
        }
    }

    pub fn public_key(&self) -> TypedPublicKey {
        match self {
            TypedPrivateKey::Secp256k1(sk) => TypedPublicKey::Secp256k1(sk.public_key()),
            TypedPrivateKey::Sr25519(sk) => TypedPublicKey::Sr25519(sk.public_key()),
        }
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            TypedPrivateKey::Secp256k1(sk) => sk.sign(data),
            TypedPrivateKey::Sr25519(sk) => sk.sign(data),
        }
    }

    pub fn sign_recoverable(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            TypedPrivateKey::Secp256k1(sk) => sk.sign_recoverable(data),
            TypedPrivateKey::Sr25519(sk) => sk.sign_recoverable(data),
        }
    }
}

pub enum TypedPublicKey {
    Secp256k1(Secp256k1PublicKey),
    Sr25519(Sr25519PublicKey),
}

impl TypedPublicKey {
    pub fn curve_type(&self) -> CurveType {
        match self {
            TypedPublicKey::Secp256k1(_) => CurveType::SECP256k1,
            TypedPublicKey::Sr25519(_) => CurveType::SubSr25519,
        }
    }

    pub fn from_slice(curve_type: CurveType, data: &[u8]) -> Result<TypedPublicKey> {
        match curve_type {
            CurveType::SECP256k1 => Ok(TypedPublicKey::Secp256k1(Secp256k1PublicKey::from_slice(data)?)),
            CurveType::SubSr25519 => Ok(TypedPublicKey::Sr25519(Sr25519PublicKey::from_slice(data)?)),
            _ => Err(KeyError::InvalidCurveType.into()),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            TypedPublicKey::Secp256k1(pk) => pk.to_bytes(),
            TypedPublicKey::Sr25519(pk) => pk.to_bytes(),
        }
    }

    pub fn as_secp256k1(&self) -> Result<&Secp256k1PublicKey> {
        match self {
            TypedPublicKey::Secp256k1(pk) => Ok(pk),
            _ => Err(format_err!("not support")),
        }
    }
}

pub enum TypedDeterministicPublicKey {
    Bip32Secp256k1(Bip32DeterministicPublicKey),
    SubSr25519(Sr25519PublicKey),
}

impl TypedDeterministicPublicKey {
    pub fn curve_type(&self) -> CurveType {
        match self {
            TypedDeterministicPublicKey::Bip32Secp256k1(_) => CurveType::SECP256k1,
            TypedDeterministicPublicKey::SubSr25519(_) => CurveType::SubSr25519,
        }
    }

    pub fn public_key(&self) -> TypedPublicKey {
        match self {
            TypedDeterministicPublicKey::Bip32Secp256k1(epk) => {
                TypedPublicKey::Secp256k1(epk.public_key())
            }
            TypedDeterministicPublicKey::SubSr25519(epk) => {
                TypedPublicKey::Sr25519(epk.public_key())
            }
        }
    }
}

impl ToString for TypedDeterministicPublicKey {
    fn to_string(&self) -> String {
        match self {
            Self::Bip32Secp256k1(epk) => epk.to_string(),
            Self::SubSr25519(epk) => epk.to_string(),
        }
    }
}

impl TypedDeterministicPublicKey {
    pub fn from_hex(curve_type: CurveType, hex: &str) -> Result<TypedDeterministicPublicKey> {
        match curve_type {
            CurveType::SECP256k1 => Ok(TypedDeterministicPublicKey::Bip32Sepc256k1(
                Bip32DeterministicPublicKey::from_hex(hex)?,
            )),
            CurveType::SubSr25519 => Ok(TypedDeterministicPublicKey::SubSr25519(
                Sr25519PublicKey::from_hex(hex)?,
            )),
            _ => Err(KeyError::InvalidCurveType.into()),
        }
    }
}

impl ToHex for TypedDeterministicPublicKey {
    fn to_hex(&self) -> String {
        match self {
            TypedDeterministicPublicKey::Bip32Sepc256k1(epk) => epk.to_hex(),
            TypedDeterministicPublicKey::SubSr25519(epk) => epk.to_hex(),
        }
    }
}

impl Derive for TypedDeterministicPublicKey {
    fn derive(&self, path: &str) -> Result<Self> {
        match self {
            Self::Bip32Secp256k1(epk) => Ok(Self::Bip32Secp256k1(epk.derive(path)?)),
            Self::SubSr25519(epk) => Ok(Self::SubSr25519(epk.derive(path)?)),
        }
    }
}

pub enum TypedDeterministicPrivateKey {
    Bip32Secp256k1(Bip32DeterministicPrivateKey),
    SubSr25519(Sr25519PrivateKey),
}

impl TypedDeterministicPrivateKey {
    pub fn curve_type(&self) -> CurveType {
        match self {
            Self::Bip32Secp256k1(_) => CurveType::SECP256k1,
            Self::SubSr25519(_) => CurveType::SubSr25519,
        }
    }

    pub fn from_mnemonic(
        curve_type: CurveType,
        mnemonic: &str,
    ) -> Result<TypedDeterministicPrivateKey> {
        match curve_type {
            CurveType::SECP256k1 => Ok(Bip32Secp256k1(
                Bip32DeterministicPrivateKey::from_mnemonic(mnemonic)?)),
            CurveType::SubSr25519 => Ok(SubSr25519(
                Sr25519PrivateKey::from_mnemonic(mnemonic)?)),
            _ => Err(KeyError::InvalidCurveType.into()),
        }
    }

    pub fn private_key(&self) -> TypedPrivateKey {
        match self {
            Self::Bip32Secp256k1(sk) => TypedPrivateKey::Secp256k1(sk.private_key()),
            Self::SubSr25519(sk) => TypedPrivateKey::Sr25519(sk.private_key()),
        }
    }

    pub fn deterministic_public_key(&self) -> TypedDeterministicPublicKey
    {
        match self {
            Self::Bip32Secp256k1(sk) => TypedDeterministicPublicKey::Bip32Secp256k1(sk.deterministic_public_key()),
            Self::SubSr25519(sk) => TypedDeterministicPublicKey::SubSr25519(sk.deterministic_public_key()),
        }
    }
}

impl ToString for TypedDeterministicPrivateKey {
    fn to_string(&self) -> String {
        match self {
            TypedDeterministicPrivateKey::Bip32Sepc256k1(sk) => sk.to_string(),
            TypedDeterministicPrivateKey::SubSr25519(sk) => hex::encode(sk.0.to_raw_vec()),
        }
    }
}

impl Derive for TypedDeterministicPrivateKey {
    fn derive(&self, path: &str) -> Result<Self> {
        match self {
            TypedDeterministicPrivateKey::Bip32Sepc256k1(dsk) => Ok(
                TypedDeterministicPrivateKey::Bip32Sepc256k1(dsk.derive(path)?),
            ),
            TypedDeterministicPrivateKey::SubSr25519(dsk) => {
                Ok(TypedDeterministicPrivateKey::SubSr25519(dsk.derive(path)?))
            }
        }
    }
}


