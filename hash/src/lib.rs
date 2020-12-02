use sha2::Sha256;
use digest::Digest;


pub trait Hashable {
    fn hash(bytes: &[u8]) -> Vec<u8>;
    fn hexlify(hex: &str) -> Option<String> {
        let r = hex::decode(hex);
        match r {
            Ok(bytes) => Some(hex::encode(&Self::hash(&bytes))),
            Err(_) => None
        }
    }
    fn stringify(s: &str) -> String {
        let bytes = s.as_bytes();
        hex::encode(&Self::hash(&bytes))
    }
}

impl Hashable for Sha256 {
    fn hash(bytes: &[u8]) -> Vec<u8> {
        Sha256::digest(&bytes).to_vec()
    }
}

pub struct Keccak256;

impl Hashable for Keccak256 {
    fn hash(bytes: &[u8]) -> Vec<u8> {
        tiny_keccak::keccak256(bytes).to_vec()
    }
}

pub struct Sha256d;

impl Hashable for Sha256d {
    fn hash(bytes: &[u8]) -> Vec<u8> {
        Sha256::hash(&Sha256::hash(&bytes)).to_vec()
    }
}


pub fn digest<T: Hashable>(bytes: &[u8])-> Vec<u8> {
    T::hash(bytes)
}


pub fn sha256d(bytes: &[u8]) -> Vec<u8> {
    digest::<Sha256d>(bytes)
}


#[cfg(test)]
mod tests {
    use crate::{sha256d, Sha256d};
    use crate::Hashable;

    #[test]
    fn sha256_test() {
        let bs = "01020304".as_bytes();
        let rs = hex::encode(sha256d(bs));
        let rs2 = hex::encode(Sha256d::hash(bs));
        let rs3 = Sha256d::hexlify("01020304").unwrap();
        assert_eq!(rs,
                   "26a0f059b048e922a223ff432ce9c87b13df2f25adc8e876a79a15326519fd76");
        assert_eq!(rs2,
                   "26a0f059b048e922a223ff432ce9c87b13df2f25adc8e876a79a15326519fd76");
        assert_eq!(rs3,
                   "8de472e2399610baaa7f84840547cd409434e31f5d3bd71e4d947f283874f9c0");
    }
}
