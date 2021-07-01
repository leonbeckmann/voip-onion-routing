use openssl::pkey::{Private, Public};
use openssl::rsa::Rsa;
use openssl::symm::Cipher;

pub(crate) const KEYSIZE: usize = 16;
pub(crate) const IVSIZE: usize = 16;

const DATA_CIPHER: fn() -> Cipher = openssl::symm::Cipher::aes_128_ctr;
const IV_CIPHER: fn() -> Cipher = openssl::symm::Cipher::aes_128_ctr;

#[derive(Debug, Clone)]
pub struct CryptoContext {
    key: Vec<u8>,
}

impl CryptoContext {
    #[allow(clippy::new_without_default)]
    pub fn new(encryption_key: Vec<u8>) -> Self {
        assert_eq!(encryption_key.len(), KEYSIZE);
        Self {
            key: encryption_key,
        }
    }

    pub fn encrypt(&self, iv: &[u8], data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // encrypt data
        let enc_data = openssl::symm::encrypt(DATA_CIPHER(), &self.key, Some(iv), data).unwrap();

        // encrypt iv
        let enc_iv = openssl::symm::encrypt(IV_CIPHER(), &[0; 16], Some(&self.key), iv).unwrap();

        (enc_iv, enc_data)
    }

    pub fn decrypt(&self, iv: &[u8], data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // decrypt iv
        let dec_iv = openssl::symm::decrypt(IV_CIPHER(), &[0; 16], Some(&self.key), iv).unwrap();

        // decrypt data
        let dec_data =
            openssl::symm::decrypt(DATA_CIPHER(), &self.key, Some(&dec_iv), data).unwrap();

        (dec_iv, dec_data)
    }
}

#[derive(Debug)]
pub struct HandshakeCryptoContext {
    private_host_key: Rsa<Private>,
    pub public_host_key: Rsa<Public>,
}

impl HandshakeCryptoContext {
    pub fn new(public_host_key: Rsa<Public>, private_host_key: Rsa<Private>) -> Self {
        Self {
            private_host_key,
            public_host_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::p2p_protocol::onion_tunnel::crypto::{CryptoContext, IVSIZE, KEYSIZE};

    #[test]
    fn unit_test_data_decryptable_32b() {
        let sym_key1 = vec![1; KEYSIZE];
        let sym_key2 = vec![2; KEYSIZE];
        let sym_key3 = vec![3; KEYSIZE];
        let iv = vec![5; IVSIZE];
        let data = b"Some Crypto TextSome Crypto Text".to_vec();

        let crypt1 = CryptoContext::new(sym_key1.clone());
        let crypt2 = CryptoContext::new(sym_key2.clone());
        let crypt3 = CryptoContext::new(sym_key3.clone());

        let (enc_iv, enc_data) = crypt1.encrypt(&iv, &data);
        let (enc_iv, enc_data) = crypt2.encrypt(&enc_iv, &enc_data);
        let (enc_iv, enc_data) = crypt3.encrypt(&enc_iv, &enc_data);

        let (dec_iv, dec_data) = crypt3.decrypt(&enc_iv, &enc_data);
        let (dec_iv, dec_data) = crypt2.decrypt(&dec_iv, &dec_data);
        let (dec_iv, dec_data) = crypt1.decrypt(&dec_iv, &dec_data);

        // Assert dec(enc(data)) == data
        assert_eq!(iv, dec_iv);
        assert_eq!(data, dec_data);
    }

    #[test]
    fn unit_test_data_decryptable_16b() {
        let sym_key1 = vec![1; KEYSIZE];
        let sym_key2 = vec![2; KEYSIZE];
        let sym_key3 = vec![3; KEYSIZE];
        let iv = vec![5; IVSIZE];
        let data = b"Some Crypto Text".to_vec();

        let crypt1 = CryptoContext::new(sym_key1.clone());
        let crypt2 = CryptoContext::new(sym_key2.clone());
        let crypt3 = CryptoContext::new(sym_key3.clone());

        let (enc_iv, enc_data) = crypt1.encrypt(&iv, &data);
        let (enc_iv, enc_data) = crypt2.encrypt(&enc_iv, &enc_data);
        let (enc_iv, enc_data) = crypt3.encrypt(&enc_iv, &enc_data);

        let (dec_iv, dec_data) = crypt3.decrypt(&enc_iv, &enc_data);
        let (dec_iv, dec_data) = crypt2.decrypt(&dec_iv, &dec_data);
        let (dec_iv, dec_data) = crypt1.decrypt(&dec_iv, &dec_data);

        // Assert dec(enc(data)) == data
        assert_eq!(iv, dec_iv);
        assert_eq!(data, dec_data);
    }

    #[test]
    fn unit_test_stable_length_32b() {
        let sym_key = vec![4; KEYSIZE];
        let iv = vec![5; IVSIZE];
        let data = b"Some Crypto TextSome Crypto Text".to_vec();

        let crypt = CryptoContext::new(sym_key.clone());
        let (enc_iv, enc_data) = crypt.encrypt(&iv, &data);

        // Assert length
        assert_eq!(iv.len(), enc_iv.len());
        assert_eq!(data.len(), enc_data.len());
    }

    #[test]
    fn unit_test_stable_length_16b() {
        let sym_key = vec![4; KEYSIZE];
        let iv = vec![5; IVSIZE];
        let data = b"Some Crypto Text".to_vec();

        let crypt = CryptoContext::new(sym_key.clone());
        let (enc_iv, enc_data) = crypt.encrypt(&iv, &data);

        // Assert length
        assert_eq!(iv.len(), enc_iv.len());
        assert_eq!(data.len(), enc_data.len());
    }
}
