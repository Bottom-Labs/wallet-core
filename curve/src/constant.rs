use lazy_static::lazy_static;

lazy_static! {
    pub(crate) static ref SECP256K1_ENGINE: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}