pub mod aes {
    use crate::{Error, Result};
    use aes_ctr::Aes128Ctr;
    use aes_ctr::stream_cipher::generic_array::GenericArray;
    use aes_ctr::stream_cipher::{NewStreamCipher, SyncStreamCipher};

    pub fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 16 || iv.len() != 16 {
            return Err(Error::InvalidKeyIvLength.into());
        }

        let key = GenericArray::from_slice(key);
        let iv = GenericArray::from_slice(iv);
        let mut cipher = Aes128Ctr::new(key, iv);
        let mut data_cpy = vec![0u8; data.len()];
        data_cpy.copy_from_slice(data);
        cipher.apply_keystream(&mut data_cpy);
        Ok(data_cpy)
    }

    pub fn decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 16 || iv.len() != 16 {
            return Err(Error::InvalidKeyIvLength.into());
        }

        let key = GenericArray::from_slice(key);
        let iv = GenericArray::from_slice(iv);
        let mut cipher = Aes128Ctr::new(key, iv);
        let mut data_cpy = vec![0u8; data.len()];
        data_cpy.copy_from_slice(data);
        cipher.apply_keystream(&mut data_cpy);
        Ok(data_cpy)
    }
}

pub mod cbc {
    extern crate aes_soft;
    extern crate block_modes;
    use aes_soft::Aes128;
    use block_modes::block_padding::Pkcs7;
    use block_modes::{Cbc, BlockMode};
    use crate::Result;
    use crate::Error;

    type Aes128Cbc = Cbc<Aes128, Pkcs7>;

    pub fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes128Cbc::new_var(key, iv)?;
        Ok(cipher.encrypt_vec(data))
    }

    pub fn decrypt(encrypted: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes128Cbc::new_var(key, iv)?;
        cipher
            .decrypt_vec(encrypted)
            .map_err(|_| Error::InvalidCipherText.into())
    }
}

#[cfg(test)]
mod tests {
    use crate::aes::aes::{encrypt, decrypt};
    use bitcoin_hashes::hex::ToHex;

    #[test]
    fn encrypt_test() {
        let data = "TokenCoreX".as_bytes();
        let key = hex::decode("01020304010203040102030401020304").unwrap();
        let iv = hex::decode("01020304010203040102030401020304").unwrap();
        let ret = encrypt(data, &key, &iv).expect("encrypt nopadding data");
        let ret_hex = ret.to_hex();

        assert_eq!("e19e6c5923d33c587cf8", ret_hex);
    }

    #[test]
    fn decrypt_test() {
        let data = "TokenCoreX".as_bytes();
        let encrypted_data = hex::decode("e19e6c5923d33c587cf8").unwrap();
        let key = hex::decode("01020304010203040102030401020304").unwrap();
        let iv = hex::decode("01020304010203040102030401020304").unwrap();
        let ret = decrypt(&encrypted_data, &key, &iv).expect("decrypted data error");

        assert_eq!(
            "TokenCoreX",
            String::from_utf8(ret).expect("decrypted failed")
        );
    }
}