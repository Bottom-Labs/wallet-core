
use core::result;
use keystore::{Keystore};

#[macro_use]
extern crate failure;

pub type Result<T> = result::Result<T, failure::Error>;

pub trait TransactionSigner<Input, Output> {
    fn sign_transaction(&mut self, symbol: &str, address: &str, tx: &Input) -> Result<Output>;
}

pub trait MessageSigner<Input, Output> {
    fn sign_message(&mut self, symbol: &str, address: &str, message: &Input) -> Result<Output>;
}

pub trait ChainSigner {
    fn sign_hash(&mut self, data: &[u8], symbol: &str, address: &str, path: Option<&str>) -> Result<Vec<u8>>;
    fn sign_recoverable_hash(&mut self, data: &[u8], symbol: &str, address: &str, path: Option<&str>) -> Result<Vec<u8>>;
}

impl ChainSigner for Keystore {
    fn sign_hash(&mut self, data: &[u8], symbol: &str, address: &str, path: Option<&str>) -> Result<Vec<u8>> {
        let private_key = if path.is_some() {
            self.find_private_key_by_path(symbol, address, path.unwrap())?
        } else {
            self.find_private_key(symbol, address)?
        };
        private_key.sign_recoverable(data)
    }

    fn sign_recoverable_hash(&mut self, data: &[u8], symbol: &str, address: &str, path: Option<&str>) -> Result<Vec<u8>> {
        let private_key = if path.is_some() {
            self.find_private_key_by_path(symbol, address, path.unwrap())?
        } else {
            self.find_private_key(symbol, address)?
        };
        private_key.sign(data)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
