use crate::Result;
use failure::_core::str::FromStr;
use crate::ecc::KeyError;
use failure::_core::convert::TryInto;
use bitcoin::util::bip32::ChildNumber;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DeriveJunction {
    Soft(u32),
    Hard(u32),
}

pub trait Derive: Sized {
    fn derive(&self, path: &str) -> Result<Self>;
}

impl DeriveJunction {
    pub fn soft(index: u32) -> Self {DeriveJunction::Soft(index)}
    pub fn hard(index: u32) -> Self {DeriveJunction::Hard(index)}

    pub fn is_soft(&self) -> bool {
        match self {
            DeriveJunction::Soft(_) => true,
            _ => false,
        }
    }

    pub fn is_hard(&self) -> bool {
        match self {
            DeriveJunction::Hard(_) => true,
            _ => false,
        }
    }
}

impl FromStr for DeriveJunction {
    type Err = failure::Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.chars().last().map_or(false, |c| c == '\'' || c == 'h') {
            Ok(
                DeriveJunction::Hard(
                    s[0..s.len() - 1]
                        .parse()
                        .map_err(|_| KeyError::InvalidChildNumberFormat)?,
                )
            )
        } else {
            Ok(
                DeriveJunction::Soft(
                    s.parse()
                        .map_err(|_| KeyError::InvalidChildNumberFormat)?,
                )
            )
        }
    }
}

impl TryInto<ChildNumber> for DeriveJunction {
    type Error = failure::Error;

    fn try_into(self) -> Result<ChildNumber> {
        if let Ok(num) = match self {
            DeriveJunction::Soft(index) => ChildNumber::from_normal_idx(index),
            DeriveJunction::Hard(index) => ChildNumber::from_hardened_idx(index),
        } {
            Ok(num)
        } else {
            Err(KeyError::InvalidChildNumber.into())
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DerivePath(Vec<DeriveJunction>);

impl FromStr for DerivePath {
    type Err = failure::Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut parts = s.split('/').peekable();
        if *parts.peek().unwrap() == "m" {
            parts.next();
        }
        let ret: Result<Vec<DeriveJunction>> = parts.map(str::parse).collect();
        Ok(DerivePath(ret?))
    }
}

impl ::std::iter::IntoIterator for &DerivePath {
    type Item = DeriveJunction;
    type IntoIter = ::std::vec::IntoIter<DeriveJunction>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.clone().into_iter()
    }
}

impl AsRef<[DeriveJunction]> for DerivePath {
    fn as_ref(&self) -> &[DeriveJunction] {
        &self.0
    }
}

pub fn get_account_path(path: &str) -> Result<String> {
    let mut children: Vec<&str> = path.split('/').collect();
    ensure!(children.len() >= 4, format!("{} path is too short", path));

    while children.len() > 4 {
        children.remove(children.len() - 1);
    }
    Ok(children.join("/"))
}