use crate::{Result, Error};
use serde::{Deserialize, Serialize};
use crate::KdfParams;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Pbkdf2Params {
    c: u32,
    prf: String,
    dklen: u32,
    salt: String,
}

impl Default for Pbkdf2Params {
    fn default() -> Self {
        Pbkdf2Params {
            c: 262144,
            prf: "hmac-sha256".to_owned(),
            dklen: 32,
            salt: "".to_owned()
        }
    }
}

impl KdfParams for Pbkdf2Params {
    fn key() -> String {
        "pbkdf2".to_owned()
    }

    fn validate(&self) -> Result<()> {
        if self.dklen == 0
            || self.c == 0
            || self.salt.is_empty()
            || self.prf.is_empty() {
            Err(Error::KdfParamsInvalid.into())
        } else {
            Ok(())
        }
    }

    fn generate_derived_key(&self, password: &[u8], out: &mut [u8]) {
        let salt: Vec<u8> = hex::FromHex::from_hex(&self.salt).unwrap();
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(password, &salt, self.c as usize, out)
    }

    fn set_salt(&mut self, salt: &str) {
        self.salt = salt.to_owned();
    }
}