use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum CurveType {
    SECP256k1,
    ED25519,
    SubSr25519,
    Curve25519,
    NIST256p1
}