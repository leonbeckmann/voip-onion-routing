use openssl::pkey::{Private, Public};
use openssl::rsa::Rsa;

#[derive(Debug, Clone)]
pub struct CryptoContext {}

impl CryptoContext {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {}
    }

    pub fn encrypt(&self, data: &[u8], _iv: &[u8]) -> Vec<u8> {
        // TODO implement
        data.to_vec()
    }

    pub fn decrypt(&self, data: &[u8], _iv: &[u8]) -> Vec<u8> {
        // TODO implement
        data.to_vec()
    }

    pub fn get_iv(&self) -> Vec<u8> {
        vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
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
