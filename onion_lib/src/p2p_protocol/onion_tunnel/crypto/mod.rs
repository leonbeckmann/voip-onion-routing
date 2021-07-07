use std::sync::Arc;

use openssl::derive::Deriver;
use openssl::ec::EcGroup;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sha::sha256;
use openssl::sign::{Signer, Verifier};
use openssl::symm::{Cipher, Crypter, Mode};

use super::fsm::ProtocolError;

pub(crate) const KEYSIZE: usize = 16;
pub(crate) const IVSIZE: usize = 16;

const DATA_CIPHER: fn() -> Cipher = openssl::symm::Cipher::aes_128_ctr;
const IV_CIPHER: fn() -> Cipher = openssl::symm::Cipher::aes_128_ecb;

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
        let enc_iv = encrypt_no_pad(IV_CIPHER(), &self.key, None, iv).unwrap();

        (enc_iv, enc_data)
    }

    pub fn decrypt(&self, iv: &[u8], data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // decrypt iv
        let dec_iv = decrypt_no_pad(IV_CIPHER(), &self.key, None, iv).unwrap();

        // decrypt data
        let dec_data =
            openssl::symm::decrypt(DATA_CIPHER(), &self.key, Some(&dec_iv), data).unwrap();

        (dec_iv, dec_data)
    }
}

#[derive(Debug)]
pub struct HandshakeCryptoConfig {
    private_host_key: Rsa<Private>,
    pub public_host_key: Rsa<Public>,
}

impl HandshakeCryptoConfig {
    pub fn new(public_host_key: Rsa<Public>, private_host_key: Rsa<Private>) -> Self {
        Self {
            private_host_key,
            public_host_key,
        }
    }
}

#[derive(Debug)]
pub struct HandshakeCryptoContext {
    crypto_config: Arc<HandshakeCryptoConfig>,
    ecdh_private_key: PKey<Private>,
    challenge: Vec<u8>,
}

impl HandshakeCryptoContext {
    pub fn new(crypto_config: Arc<HandshakeCryptoConfig>) -> Self {
        // Generate new ECDH key pair
        let ecdh_private_key =
            openssl::ec::EcKey::generate(&EcGroup::from_curve_name(Nid::SECP256K1).unwrap())
                .unwrap();
        let ecdh_private_key = PKey::from_ec_key(ecdh_private_key).unwrap();

        let mut challenge = vec![0; 32];
        openssl::rand::rand_bytes(&mut challenge).expect("Failed to generated random challenge");

        Self {
            crypto_config,
            ecdh_private_key,
            challenge,
        }
    }

    pub fn get_public_key(&mut self) -> Vec<u8> {
        self.ecdh_private_key.public_key_to_der().unwrap()
    }

    pub fn finish_ecdh(&mut self, ecdh_public_key: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        // Returns if the key or the format is invalid
        let receiver_pub = PKey::public_key_from_der(ecdh_public_key)
            .map_err(|_| ProtocolError::HandshakeECDHFailure)?;

        // Derive shared secret
        let mut deriver = Deriver::new(&self.ecdh_private_key).unwrap();
        deriver.set_peer(&receiver_pub).unwrap();
        let shared_secret = deriver.derive_to_vec().unwrap();
        let encryption_key = sha256(&shared_secret);

        Ok(encryption_key.to_vec())
    }

    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        // Sign the data
        let rsa_private = PKey::from_rsa(self.crypto_config.private_host_key.clone()).unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &rsa_private).unwrap();
        signer.update(data).unwrap();

        signer.sign_to_vec().unwrap()
    }

    pub fn verify(&self, signer_key: Rsa<Public>, signature: &[u8], data: &[u8]) -> bool {
        let rsa_public = PKey::from_rsa(signer_key).unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha256(), &rsa_public).unwrap();
        verifier.update(data).unwrap();

        verifier.verify(signature).unwrap()
    }

    pub fn hop_sign(&self, ecdh_public_key_initiator: &[u8]) -> Vec<u8> {
        let mut data = ecdh_public_key_initiator.to_vec();
        data.append(&mut self.ecdh_private_key.public_key_to_der().unwrap());

        self.sign(&data)
    }

    pub fn initiator_verify(
        &self,
        signer_key: Rsa<Public>,
        signature: &[u8],
        ecdh_public_key_hop: &[u8],
    ) -> bool {
        // Verify the data
        let mut data = self.ecdh_private_key.public_key_to_der().unwrap();
        data.append(&mut ecdh_public_key_hop.to_vec());

        self.verify(signer_key, signature, &data)
    }

    pub fn get_challenge(&self) -> &[u8] {
        &self.challenge
    }
}

fn encrypt_no_pad(
    t: Cipher,
    key: &[u8],
    iv: Option<&[u8]>,
    data: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    let mut c = Crypter::new(t, Mode::Encrypt, key, iv)?;
    c.pad(false);
    let mut out = vec![0; data.len() + t.block_size()];
    let count = c.update(data, &mut out)?;
    let rest = c.finalize(&mut out[count..])?;
    out.truncate(count + rest);
    Ok(out)
}

pub fn decrypt_no_pad(
    t: Cipher,
    key: &[u8],
    iv: Option<&[u8]>,
    data: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    let mut c = Crypter::new(t, Mode::Decrypt, key, iv)?;
    c.pad(false);
    let mut out = vec![0; data.len() + t.block_size()];
    let count = c.update(data, &mut out)?;
    let rest = c.finalize(&mut out[count..])?;
    out.truncate(count + rest);
    Ok(out)
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

        let crypt1 = CryptoContext::new(sym_key1);
        let crypt2 = CryptoContext::new(sym_key2);
        let crypt3 = CryptoContext::new(sym_key3);

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

        let crypt1 = CryptoContext::new(sym_key1);
        let crypt2 = CryptoContext::new(sym_key2);
        let crypt3 = CryptoContext::new(sym_key3);

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

        let crypt = CryptoContext::new(sym_key);
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

        let crypt = CryptoContext::new(sym_key);
        let (enc_iv, enc_data) = crypt.encrypt(&iv, &data);

        // Assert length
        assert_eq!(iv.len(), enc_iv.len());
        assert_eq!(data.len(), enc_data.len());
    }
}
