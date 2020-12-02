use bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey, Error as Bip32Error, ChildNumber, Fingerprint, ChainCode};
use crate::ecc::{KeyError, DeterministicPrivateKey, DeterministicPublicKey};
use crate::{Result, ToHex, FromHex, Ss58Codec};
use bitcoin::{Network, PublicKey};
use bip39::{Mnemonic, Language};
use crate::derive::Derive;
use crate::constant::SECP256K1_ENGINE;
use crate::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use byteorder::{BigEndian, ByteOrder};
use bitcoin::util::psbt::raw::Key;
use bitcoin::util::base58;
use bitcoin::util::base58::Error::InvalidLength;

pub struct Bip32DeterministicPrivateKey(ExtendedPrivKey);
pub struct Bip32DeterministicPublicKey(ExtendedPubKey);

#[cfg_attr(tarpaulin, skip)]
fn transform_bip32_error(err: Bip32Error) -> KeyError {
    match err {
        Bip32Error::Ecdsa(_) => KeyError::InvalidEcdsa,
        Bip32Error::RngError(_) => KeyError::OverflowChildNumber,
        Bip32Error::CannotDeriveFromHardenedKey => KeyError::CannotDeriveFromHardenedKey,
        Bip32Error::InvalidChildNumber(_) => KeyError::InvalidChildNumber,
        Bip32Error::InvalidChildNumberFormat => KeyError::InvalidChildNumber,
        Bip32Error::InvalidDerivationPathFormat => KeyError::InvalidDerivationPathFormat,
    }
}

impl Bip32DeterministicPrivateKey {
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let epk =
        ExtendedPrivKey::new_master(Network::Bitcoin, seed)
            .map_err(transform_bip32_error)?;
        Ok(Bip32DeterministicPrivateKey(epk))
    }

    pub fn from_mnemonic(mnemonic: &str) -> Result<Self> {
        let mn = Mnemonic::from_phrase(mnemonic, Language::English)?;
        let seed = bip39::Seed::new(&mn, "");
        let epk = ExtendedPrivKey::new_master(Network::Bitcoin, seed.as_ref())
            .map_err(transform_bip32_error)?;
        Ok(Bip32DeterministicPrivateKey(epk))
    }
}

impl Derive for Bip32DeterministicPrivateKey {
    fn derive(&self, path: &str) -> Result<Self> {
        let extended_key = self.0.clone();
        let mut parts = path.split('/').peekable();
        if *parts.peek().unwrap() == "m" {
            parts.next();
        }
        let ret: std::result::Result<Vec<ChildNumber>, bitcoin::util::bip32::Error> =
            parts.map(str::parse).collect();
        let children_nums = ret.map_err(transform_bip32_error)?;
        let child_key = extended_key.derive_priv(&SECP256K1_ENGINE, &children_nums)?;
        Ok(Bip32DeterministicPrivateKey(child_key))
    }
}

impl Derive for Bip32DeterministicPublicKey {
    fn derive(&self, path: &str) -> Result<Self> {
        let extended_key = self.0.clone();
        let mut parts = path.split('/').peekable();
        if *parts.peek().unwrap() == "m" {
            parts.next();
        }
        let ret: std::result::Result<Vec<ChildNumber>, bitcoin::util::bip32::Error> =
            parts.map(str::parse).collect();
        let children_nums = ret.map_err(transform_bip32_error)?;
        let child_key = extended_key.derive_pub(&SECP256K1_ENGINE, &children_nums)?;
        Ok(Bip32DeterministicPublicKey(child_key))
    }
}

impl DeterministicPrivateKey for Bip32DeterministicPrivateKey {
    type DeterministicPublicKey = Bip32DeterministicPublicKey;
    type PrivateKey = Secp256k1PrivateKey;

    fn from_seed(seed: &[u8]) -> Result<Self> {
        let esk =
            ExtendedPrivKey::new_master(Network::Bitcoin, seed).map_err(transform_bip32_error)?;
        Ok(Bip32DeterministicPrivateKey(esk))
    }

    fn from_mnemonic(mnemonic: &str) -> Result<Self> {
        let mn = Mnemonic::from_phrase(mnemonic, Language::English)?;
        let seed = bip39::Seed::new(&mn, "");
        let esk = ExtendedPrivKey::new_master(Network::Bitcoin, seed.as_bytes())
            .map_err(transform_bip32_error)?;
        Ok(Bip32DeterministicPrivateKey(esk))
    }

    fn private_key(&self) -> Self::PrivateKey {
        Secp256k1PrivateKey::from(self.0.private_key.clone())
    }

    fn deterministic_public_key(&self) -> Self::DeterministicPublicKey {
        let pk = ExtendedPubKey::from_private(&SECP256K1_ENGINE, &self.0);
        Bip32DeterministicPublicKey(pk)
    }
}

impl DeterministicPublicKey for Bip32DeterministicPublicKey {
    type PublicKey = Secp256k1PublicKey;

    fn public_key(&self) -> Self::PublicKey {
        Secp256k1PublicKey::from(self.0.public_key.clone())
    }
}

impl ToString for Bip32DeterministicPublicKey {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl ToString for Bip32DeterministicPrivateKey {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl ToHex for Bip32DeterministicPublicKey {
    fn to_hex(&self) -> String {
        let mut ret = [0; 74];
        let extended_key = self.0;
        ret[0] = extended_key.depth as u8;
        ret[1..5].copy_from_slice(&extended_key.parent_fingerprint[..]);
        BigEndian::write_u32(&mut ret[5..9], u32::from(extended_key.child_number));
        ret[9..41].copy_from_slice(&extended_key.chain_code[..]);
        ret[41..74].copy_from_slice(&extended_key.public_key.key.serialize()[..]);
        hex::encode(ret.to_vec())
    }
}

impl FromHex for Bip32DeterministicPublicKey {
    fn from_hex(hex: &str) -> Result<Self> {
        let data = hex::decode(hex)?;
        if data.len() != 74 {
            return Err(KeyError::InvalidBase58.into());
        }

        let cn_int: u32 = BigEndian::read_u32(&data[5..9]);
        let child_number = ChildNumber::from(cn_int);

        let epk = ExtendedPubKey {
            network: Network::Bitcoin,
            depth: data[0],
            parent_fingerprint: Fingerprint::from(&data[1..5]),
            child_number,
            chain_code: ChainCode::from(&data[9..41]),
            public_key: PublicKey::from_slice(&data[41..74])
                .map_err(|e| base58::Error::Other(e.to_string()))?,
        };
        Ok(Bip32DeterministicPublicKey(epk))
    }
}

impl Ss58Codec for Bip32DeterministicPublicKey {
    fn from_ss58check_with_version(s: &str) -> Result<(Self, Vec<u8>)> {
        let data = base58::from_check(s)?;

        if data.len() != 78 {
            return Err(KeyError::InvalidBase58.into());
        }
        let cn_int: u32 = BigEndian::read_u32(&data[9..13]);
        let child_number: ChildNumber = ChildNumber::from(cn_int);

        let epk = ExtendedPubKey {
            network: Network::Bitcoin,
            depth: data[4],
            parent_fingerprint: Fingerprint::from(&data[5..9]),
            child_number,
            chain_code: ChainCode::from(&data[13..45]),
            public_key: PublicKey::from_slice(&data[45..78])
                .map_err(|e| base58::Error::Other(e.to_string()))?,
        };

        let mut network = [0; 4];
        network.copy_from_slice(&data[0..4]);
        Ok((Bip32DeterministicPublicKey(epk), network.to_vec()))
    }

    fn to_ss58check_with_version(&self, version: &[u8]) -> String {
        let mut ret = [0; 78];
        let extended_key = self.0;
        ret[0..4].copy_from_slice(&version[..]);
        ret[4] = extended_key.depth as u8;
        ret[5..9].copy_from_slice(&extended_key.parent_fingerprint[..]);

        BigEndian::write_u32(&mut ret[9..13], u32::from(extended_key.child_number));

        ret[13..45].copy_from_slice(&extended_key.chain_code[..]);
        ret[45..78].copy_from_slice(&extended_key.public_key.key.serialize()[..]);
        base58::check_encode_slice(&ret[..])
    }
}

impl Ss58Codec for Bip32DeterministicPrivateKey {
    fn from_ss58check_with_version(s: &str) -> Result<(Self, Vec<u8>)> {
        let data = base58::from_check(s)?;

        if data.len() != 78 {
            return Err(InvalidLength(data.len()).into());
        }

        let cn_int: u32 = BigEndian::read_u32(&data[9..13]);
        let child_number: ChildNumber = ChildNumber::from(cn_int);

        let network = Network::Bitcoin;
        let epk = ExtendedPrivKey {
            network,
            depth: data[4],
            parent_fingerprint: Fingerprint::from(&data[5..9]),
            child_number,
            chain_code: ChainCode::from(&data[13..45]),
            private_key: bitcoin::PrivateKey {
                compressed: true,
                network,
                key: secp256k1::SecretKey::from_slice(&data[46..78])
                    .map_err(|e| base58::Error::Other(e.to_string()))?,
            },
        };
        let mut network = [0; 4];
        network.copy_from_slice(&data[0..4]);
        Ok((Bip32DeterministicPrivateKey(epk), network.to_vec()))
    }

    fn to_ss58check_with_version(&self, version: &[u8]) -> String {
        let mut ret = [0; 78];
        let extended_key = &self.0;

        ret[0..4].copy_from_slice(&version[..]);
        ret[4] = extended_key.depth as u8;
        ret[5..9].copy_from_slice(&extended_key.parent_fingerprint[..]);

        BigEndian::write_u32(&mut ret[9..13], u32::from(extended_key.child_number));

        ret[13..45].copy_from_slice(&extended_key.chain_code[..]);
        ret[45] = 0;
        ret[46..78].copy_from_slice(&extended_key.private_key[..]);
        base58::check_encode_slice(&ret[..])
    }
}