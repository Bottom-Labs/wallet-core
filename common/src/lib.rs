pub mod curve_type;
pub mod coin_info;
pub mod macros;

use rand::{thread_rng, RngCore};
use std::vec;

pub use coin_info::{CoinInfo};

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate failure;

pub type Result<T> = std::result::Result<T, failure::Error>;

pub fn random_iv(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    thread_rng().fill_bytes(&mut v);
    v
}


#[cfg(test)]
mod tests {
    use crate::random_iv;
    #[test]
    fn it_works() {
        let rand = random_iv(32);
        print!("{:?}", rand);
        assert_eq!(32, rand.len());
    }
}
