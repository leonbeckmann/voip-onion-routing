use openssl::pkey::{Private, Public};
use openssl::rsa::Rsa;

#[derive(Debug, Clone)]
pub struct CryptoContext {}

impl CryptoContext {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {}
    }

    pub fn encrypt(&self, iv: &[u8], data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // TODO implement
        (iv.to_vec(), data.to_vec())
    }

    pub fn decrypt(&self, iv: &[u8], data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // TODO implement
        (iv.to_vec(), data.to_vec())
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
