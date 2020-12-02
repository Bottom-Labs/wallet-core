#[macro_use]
extern crate failure;
pub mod constant;
pub mod bip32;
pub mod ecc;
pub mod derive;
pub mod secp256k1;
pub mod sr25519;
pub mod subkey;
pub mod rand;

use core::result;

pub type Result<T> = result::Result<T, failure::Error>;

pub trait Ss58Codec: Sized {
    fn from_ss58check(s: &str) -> Result<Self> {
        let (parsed, _) = Self::from_ss58check_with_version(s)?;
        Ok(parsed)
    }

    fn from_ss58check_with_version(s: &str) -> Result<(Self, Vec<u8>)>;
    fn to_ss58check_with_version(&self, version: &[u8]) -> String;
}

pub trait ToHex: Sized {
    fn to_hex(&self) -> String;
}

pub trait FromHex: Sized {
    fn from_hex(hex: &str) -> Result<Self>;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
