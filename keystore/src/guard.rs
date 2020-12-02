use crate::Keystore;
use crate::Result;

pub struct KeystoreGuard<'a> {
    keystore: &'a mut Keystore,
}

impl<'a> Drop for KeystoreGuard<'a> {
    fn drop(&mut self) {
        //self.keystore.lock();
    }
}

impl<'a> KeystoreGuard<'a> {
    pub fn unlock_by_password(ks: &mut Keystore, password: &str) -> Result<KeystoreGuard> {

    }

    pub fn unlock_by_derived_key(ks: &mut Keystore, derived_key: &str) -> Result<KeystoreGuard> {

    }
    pub fn keystore_mut(&mut self) -> &mut Keystore {self.keystore}
    pub fn keystore(&self) -> &Keystore {self.keystore()}
}