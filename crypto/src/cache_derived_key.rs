use hash::{Sha256d, Hashable};
use crate::{Error, Result};
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheDerivedKey {
    hashed_key: String,
    derived_key: Vec<u8>
}

impl CacheDerivedKey {
    pub fn new(key: &str, derived_key: &[u8]) -> Self {
        CacheDerivedKey {
            hashed_key: Self::hash(key),
            derived_key: derived_key.to_vec()
        }
    }

    fn hash(key: &str) -> String {
        Sha256d::hexlify(key).unwrap()
    }

    pub fn get_derived_key(&self, key: &str) -> Result<Vec<u8>> {
        if self.hashed_key == Self::hash(key) {
            Ok(self.derived_key.clone())
        } else {
            Err(Error::PasswordIncorrect.into())
        }
    }
}