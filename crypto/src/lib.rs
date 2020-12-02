pub mod aes;
pub mod kdf;
pub mod scrypt;
pub mod cache_derived_key;
pub mod crypto;

use core::result;

#[macro_use]
extern crate failure;

pub type Result<T> = result::Result<T, failure::Error>;

#[derive(Fail, Debug, PartialOrd, PartialEq)]
pub enum Error {
    #[fail(display = "invalid_ciphertext")]
    InvalidCipherText,
    #[fail(display = "invalid_key_iv_length")]
    InvalidKeyIvLength,
    #[fail(display = "kdf_params_invalid")]
    KdfParamsInvalid,
    #[fail(display = "password_incorrect")]
    PasswordIncorrect,
    #[fail(display = "derived_key_not_matched")]
    DerivedKeyNotMatched,
    #[fail(display = "cached_dk_feature_not_support")]
    CachedDkFeatureNotSupport,
}

pub trait KdfParams: Default {
    fn key() -> String;
    fn validate(&self) -> Result<()>;
    fn generate_derived_key(&self, password: &[u8], out: &mut [u8]);
    fn set_salt(&mut self, salt: &str);
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
