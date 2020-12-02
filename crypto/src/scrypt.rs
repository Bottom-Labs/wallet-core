use serde::{Serialize, Deserialize};
use crate::KdfParams;
use crate::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScryptParams {
    n: u32,
    p: u32,
    r: u32,
    dklen: u32,
    salt: String,
}

impl Default for ScryptParams {
    fn default() -> Self {
        ScryptParams {
            n: 262144,
            p: 1,
            r: 8,
            dklen: 32,
            salt: "".to_owned(),
        }
    }
}

impl KdfParams for ScryptParams {
    fn key() -> String {
        "scrypt".to_owned()
    }

    fn validate(&self) -> Result<()> {
        if self.dklen == 0
            || self.n == 0
            || self.salt.is_empty()
            || self.p == 0
            || self.r == 0 {
            Err(Error::KdfParamsInvalid.into())
        } else {
            Ok(())
        }
    }

    fn generate_derived_key(&self, password: &[u8], out: &mut [u8]) {
        let salt: Vec<u8> = hex::FromHex::from_hex(&self.salt).unwrap();
        let log_n = (self.n as f64).log2().round();
        let params = scrypt::ScryptParams::new(
            log_n as u8,
            self.r,
            self.p
        ).expect("init scrypt params");
        scrypt::scrypt(password, &salt, &params, out).expect("can not execute scrypt");
    }

    fn set_salt(&mut self, salt: &str) {
        self.salt = salt.to_owned();
    }
}

