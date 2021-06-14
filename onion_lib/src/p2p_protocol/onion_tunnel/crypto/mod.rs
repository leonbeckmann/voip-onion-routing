#[derive(Debug, Clone)]
pub struct CryptoContext {}

impl CryptoContext {
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
