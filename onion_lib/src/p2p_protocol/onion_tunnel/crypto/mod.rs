use std::collections::HashSet;
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

pub(crate) const KEY_SIZE: usize = 16;
pub(crate) const IV_SIZE: usize = 16;
pub(crate) const AUTH_SIZE: usize = 16;
pub(crate) const AUTH_PLACEHOLDER: u8 = 0;

/*
 * Ciphers used for encryption
 *
 * At the endpoints we use aes-gcm as authenticated encryption, while the hops only use aes-ctr.
 * The IVs have also be encrypted to avoid trackable IVs
 */
const DATA_CIPHER: fn() -> Cipher = openssl::symm::Cipher::aes_128_gcm;
const HOP_DATA_CIPHER: fn() -> Cipher = openssl::symm::Cipher::aes_128_ctr;
const IV_CIPHER: fn() -> Cipher = openssl::symm::Cipher::aes_128_ecb;

/*
 * CryptoContext per tunnel per peer, used for all the crypto stuff at a peer
 */
#[derive(Debug, Clone)]
pub struct CryptoContext {
    enc_key: Vec<u8>,
    dec_key: Vec<u8>,
    used_ivs_forward: HashSet<Vec<u8>>,
    used_ivs_backward: HashSet<Vec<u8>>,
}

impl CryptoContext {
    #[allow(clippy::new_without_default)]
    pub fn new(shared_secret: Vec<u8>, is_initiator: bool) -> Self {
        // derive encryption keys via KDF
        let keys = sha256(&shared_secret);
        let (encryption_key, decryption_key) = {
            let (first_key, remainder) = keys.split_at(KEY_SIZE);
            let (second_key, _) = remainder.split_at(KEY_SIZE);
            if is_initiator {
                (first_key.to_vec(), second_key.to_vec())
            } else {
                (second_key.to_vec(), first_key.to_vec())
            }
        };
        assert_eq!(encryption_key.len(), KEY_SIZE);
        assert_eq!(decryption_key.len(), KEY_SIZE);
        Self {
            enc_key: encryption_key,
            dec_key: decryption_key,
            used_ivs_forward: HashSet::new(),
            used_ivs_backward: HashSet::new(),
        }
    }

    pub fn encrypt(
        &mut self,
        iv: Option<&[u8]>,
        data: &[u8],
        start_to_end: bool,
    ) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
        // ensure fresh IV
        let mut iv_store = vec![0; IV_SIZE];
        let iv = if let Some(iv) = iv {
            // iv provided, check if this one is fresh
            if !self.used_ivs_forward.insert(iv.to_vec()) {
                // Handle same IV used multiple times
                log::warn!("Data encryption failed: Received the same IV multiple times");
                return Err(ProtocolError::CryptoFailure);
            }
            iv
        } else {
            // loop until fresh IV found
            loop {
                openssl::rand::rand_bytes(&mut iv_store).expect("Failed to generated random IV");
                if self.used_ivs_forward.insert(iv_store.clone()) {
                    break;
                }
            }
            &iv_store
        };

        // encrypt data
        let enc_data = if start_to_end {
            // this is an endpoint, use aes-gcm for authenticated data, result [auth_tag:u16 | ciphertext]
            debug_assert_eq!(data[0..AUTH_SIZE], vec![AUTH_PLACEHOLDER; AUTH_SIZE]);
            let mut auth_tag = vec![AUTH_PLACEHOLDER; AUTH_SIZE];
            let mut enc_data = openssl::symm::encrypt_aead(
                DATA_CIPHER(),
                &self.enc_key,
                Some(iv),
                &[],
                &data[AUTH_SIZE..],
                &mut auth_tag,
            )
            .unwrap();
            auth_tag.append(&mut enc_data);
            auth_tag
        } else {
            // this is a hop, use ctr
            openssl::symm::encrypt(HOP_DATA_CIPHER(), &self.enc_key, Some(iv), data).unwrap()
        };

        // encrypt iv
        let enc_iv = encrypt_no_pad(IV_CIPHER(), &self.enc_key, None, iv).unwrap();

        Ok((enc_iv, enc_data))
    }

    pub fn decrypt(
        &mut self,
        iv: &[u8],
        data: &[u8],
        start_to_end: bool,
    ) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
        // first decrypt iv to get the IV used for decryption at this node
        let dec_iv = decrypt_no_pad(IV_CIPHER(), &self.dec_key, None, iv).unwrap();

        // check if this IV is fresh and insert it into used IVs
        if !self.used_ivs_backward.insert(dec_iv.clone()) {
            // Handle same IV used multiple times
            log::warn!("Data decryption failed: Received the same IV multiple times");
            return Err(ProtocolError::CryptoFailure);
        }

        // decrypt data
        let dec_data = if start_to_end {
            // receiver endpoint, use aes-gcm
            let mut dec_data = openssl::symm::decrypt_aead(
                DATA_CIPHER(),
                &self.dec_key,
                Some(dec_iv.as_ref()),
                &[],
                &data[AUTH_SIZE..],
                &data[0..AUTH_SIZE],
            )
            .map_err(|_| {
                log::warn!("Data decryption failed: Received invalid auth tag");
                ProtocolError::CryptoFailure
            })?;
            let mut data = vec![AUTH_PLACEHOLDER; AUTH_SIZE];
            data.append(&mut dec_data);
            data
        } else {
            // hop, use aes-ctr
            openssl::symm::decrypt(HOP_DATA_CIPHER(), &self.dec_key, Some(&dec_iv), data).unwrap()
        };

        Ok((dec_iv, dec_data))
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

/*
 * HandshakeCryptoContext holds the identity key pair of the peer and the private ECDHE parameter
 * Used for all the crypto stuff in the handshake
 */
#[derive(Debug)]
pub struct HandshakeCryptoContext {
    crypto_config: Arc<HandshakeCryptoConfig>,
    ecdh_private_key: PKey<Private>,
    challenge: Vec<u8>,
}

impl HandshakeCryptoContext {
    /*
     * Create a new crypto context for the handshake, including ECDHE parameter and challenge creation
     */
    pub fn new(crypto_config: Arc<HandshakeCryptoConfig>) -> Self {
        // Generate new ECDH key pair
        let ecdh_private_key =
            openssl::ec::EcKey::generate(&EcGroup::from_curve_name(Nid::SECP256K1).unwrap())
                .unwrap();
        let ecdh_private_key = PKey::from_ec_key(ecdh_private_key).unwrap();

        // create a fresh challenge for client authentication
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

    /*
     * Finish the ECDHE with remote public param
     */
    pub fn finish_ecdh(&mut self, ecdh_public_key: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        // Returns if the key or the format is invalid
        let receiver_pub = PKey::public_key_from_der(ecdh_public_key)
            .map_err(|_| ProtocolError::HandshakeECDHFailure)?;

        // Derive shared secret
        let mut deriver = Deriver::new(&self.ecdh_private_key).unwrap();
        deriver.set_peer(&receiver_pub).unwrap();
        let shared_secret = deriver.derive_to_vec().unwrap();

        Ok(shared_secret)
    }

    /*
     * Sign data with RSA identity key
     */
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        // Sign the data
        let rsa_private = PKey::from_rsa(self.crypto_config.private_host_key.clone()).unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &rsa_private).unwrap();
        signer.update(data).unwrap();
        signer.sign_to_vec().unwrap()
    }

    /*
     * Verify signature using public RSA identity key
     */
    pub fn verify(&self, signer_key: Rsa<Public>, signature: &[u8], data: &[u8]) -> bool {
        let rsa_public = PKey::from_rsa(signer_key).unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha256(), &rsa_public).unwrap();
        verifier.update(data).unwrap();
        verifier.verify(signature).unwrap()
    }

    /*
     * Sign the handshake parameters [pub_self | challenge | pub_initiator]
     */
    pub fn hop_sign(&mut self, ecdh_public_key_initiator: &[u8]) -> Vec<u8> {
        let mut data = self.ecdh_private_key.public_key_to_der().unwrap();
        data.append(&mut self.challenge.clone());
        data.append(&mut ecdh_public_key_initiator.to_vec());
        self.sign(&data)
    }

    /*
     * Verify the handshake parameter signature
     */
    pub fn initiator_verify(
        &self,
        signer_key: Rsa<Public>,
        signature: &[u8],
        ecdh_public_key_hop: &[u8],
        challenge: &[u8],
    ) -> bool {
        // Verify the signature
        let mut data = ecdh_public_key_hop.to_vec();
        data.append(&mut challenge.to_vec());
        data.append(&mut self.ecdh_private_key.public_key_to_der().unwrap());
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
    use std::sync::Arc;

    use openssl::rsa::Rsa;

    use crate::p2p_protocol::onion_tunnel::{
        crypto::{CryptoContext, AUTH_PLACEHOLDER, AUTH_SIZE, IV_SIZE, KEY_SIZE},
        fsm::ProtocolError,
    };

    use super::{HandshakeCryptoConfig, HandshakeCryptoContext};

    #[test]
    fn unit_test_data_decryptable_32b() {
        let shared_secret1 = vec![1; KEY_SIZE];
        let shared_secret2 = vec![2; KEY_SIZE];
        let shared_secret3 = vec![3; KEY_SIZE];
        let iv = vec![5; IV_SIZE];
        let data = b"Some Crypto TextSome Crypto Text".to_vec();

        let mut crypt1 = CryptoContext::new(shared_secret1.clone(), true);
        let mut crypt2 = CryptoContext::new(shared_secret2.clone(), true);
        let mut crypt3 = CryptoContext::new(shared_secret3.clone(), true);
        let mut crypt4 = CryptoContext::new(shared_secret1, false);
        let mut crypt5 = CryptoContext::new(shared_secret2, false);
        let mut crypt6 = CryptoContext::new(shared_secret3, false);

        let (enc_iv, enc_data) = crypt1.encrypt(Some(&iv), &data, false).unwrap();
        let (enc_iv, enc_data) = crypt2.encrypt(Some(&enc_iv), &enc_data, false).unwrap();
        let (enc_iv, enc_data) = crypt3.encrypt(Some(&enc_iv), &enc_data, false).unwrap();

        let (dec_iv, dec_data) = crypt6.decrypt(&enc_iv, &enc_data, false).unwrap();
        let (dec_iv, dec_data) = crypt5.decrypt(&dec_iv, &dec_data, false).unwrap();
        let (dec_iv, dec_data) = crypt4.decrypt(&dec_iv, &dec_data, false).unwrap();

        // Assert dec(enc(data)) == data
        assert_eq!(iv, dec_iv);
        assert_eq!(data, dec_data);
    }

    #[test]
    fn unit_test_data_decryptable_16b() {
        let shared_secret1 = vec![1; KEY_SIZE];
        let shared_secret2 = vec![2; KEY_SIZE];
        let shared_secret3 = vec![3; KEY_SIZE];
        let iv = vec![5; IV_SIZE];
        let data = b"Some Crypto Text".to_vec();

        let mut crypt1 = CryptoContext::new(shared_secret1.clone(), true);
        let mut crypt2 = CryptoContext::new(shared_secret2.clone(), true);
        let mut crypt3 = CryptoContext::new(shared_secret3.clone(), true);
        let mut crypt4 = CryptoContext::new(shared_secret1, false);
        let mut crypt5 = CryptoContext::new(shared_secret2, false);
        let mut crypt6 = CryptoContext::new(shared_secret3, false);

        let (enc_iv, enc_data) = crypt1.encrypt(Some(&iv), &data, false).unwrap();
        let (enc_iv, enc_data) = crypt2.encrypt(Some(&enc_iv), &enc_data, false).unwrap();
        let (enc_iv, enc_data) = crypt3.encrypt(Some(&enc_iv), &enc_data, false).unwrap();

        let (dec_iv, dec_data) = crypt6.decrypt(&enc_iv, &enc_data, false).unwrap();
        let (dec_iv, dec_data) = crypt5.decrypt(&dec_iv, &dec_data, false).unwrap();
        let (dec_iv, dec_data) = crypt4.decrypt(&dec_iv, &dec_data, false).unwrap();

        // Assert dec(enc(data)) == data
        assert_eq!(iv, dec_iv);
        assert_eq!(data, dec_data);
    }

    #[test]
    fn unit_test_data_decryptable_authenticated() {
        let shared_secret1 = vec![1; KEY_SIZE];
        let shared_secret2 = vec![2; KEY_SIZE];
        let shared_secret3 = vec![3; KEY_SIZE];
        let iv = vec![5; IV_SIZE];
        let mut data = vec![AUTH_PLACEHOLDER; AUTH_SIZE];
        data.append(&mut b"Some Crypto TextSome Crypto Text".to_vec());

        let mut crypt1 = CryptoContext::new(shared_secret1.clone(), true);
        let mut crypt2 = CryptoContext::new(shared_secret2.clone(), true);
        let mut crypt3 = CryptoContext::new(shared_secret3.clone(), true);
        let mut crypt4 = CryptoContext::new(shared_secret1, false);
        let mut crypt5 = CryptoContext::new(shared_secret2, false);
        let mut crypt6 = CryptoContext::new(shared_secret3, false);

        let (enc_iv, enc_data) = crypt1.encrypt(Some(&iv), &data, true).unwrap();
        let (enc_iv, enc_data) = crypt2.encrypt(Some(&enc_iv), &enc_data, false).unwrap();
        let (enc_iv, enc_data) = crypt3.encrypt(Some(&enc_iv), &enc_data, false).unwrap();

        let (dec_iv, dec_data) = crypt6.decrypt(&enc_iv, &enc_data, false).unwrap();
        let (dec_iv, dec_data) = crypt5.decrypt(&dec_iv, &dec_data, false).unwrap();
        let (dec_iv, dec_data) = crypt4.decrypt(&dec_iv, &dec_data, true).unwrap();

        // Assert dec(enc(data)) == data
        assert_eq!(iv, dec_iv);
        assert_eq!(data, dec_data);
    }

    #[test]
    fn unit_test_data_decryptable_authenticated_invalid() {
        let shared_secret1 = vec![1; KEY_SIZE];
        let shared_secret2 = vec![2; KEY_SIZE];
        let shared_secret3 = vec![3; KEY_SIZE];
        let iv = vec![5; IV_SIZE];
        let mut data = vec![AUTH_PLACEHOLDER; AUTH_SIZE];
        data.append(&mut b"Some Crypto TextSome Crypto Text".to_vec());

        let mut crypt1 = CryptoContext::new(shared_secret1, true);
        let mut crypt2 = CryptoContext::new(shared_secret2, true);
        let mut crypt3 = CryptoContext::new(shared_secret3, true);

        let (enc_iv, enc_data) = crypt1.encrypt(Some(&iv), &data, true).unwrap();
        let (enc_iv, enc_data) = crypt2.encrypt(Some(&enc_iv), &enc_data, false).unwrap();
        let mut enc_data = enc_data;
        enc_data[33] += 1;
        let (enc_iv, enc_data) = crypt3.encrypt(Some(&enc_iv), &enc_data, false).unwrap();

        let (dec_iv, dec_data) = crypt3.decrypt(&enc_iv, &enc_data, false).unwrap();
        let (dec_iv, dec_data) = crypt2.decrypt(&dec_iv, &dec_data, false).unwrap();
        let res = crypt1.decrypt(&dec_iv, &dec_data, true);

        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), ProtocolError::CryptoFailure);
    }

    #[test]
    fn unit_test_detect_iv_manipulation() {
        let shared_secret = vec![1; KEY_SIZE];
        let iv = vec![5; IV_SIZE];
        let mut data = vec![AUTH_PLACEHOLDER; AUTH_SIZE];
        data.append(&mut b"Some Crypto TextSome Crypto Text".to_vec());

        let mut crypt = CryptoContext::new(shared_secret, true);

        let (enc_iv, enc_data) = crypt.encrypt(Some(&iv), &data, false).unwrap();
        let res = crypt.encrypt(Some(&iv), &data, false);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), ProtocolError::CryptoFailure);

        let (_, dec_data) = crypt.decrypt(&enc_iv, &enc_data, false).unwrap();
        let res = crypt.decrypt(&enc_iv, &dec_data, false);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), ProtocolError::CryptoFailure);
    }

    #[test]
    fn unit_test_stable_length_32b() {
        let shared_secret = vec![4; KEY_SIZE];
        let iv = vec![5; IV_SIZE];
        let data = b"Some Crypto TextSome Crypto Text".to_vec();

        let mut crypt = CryptoContext::new(shared_secret, true);
        let (enc_iv, enc_data) = crypt.encrypt(Some(&iv), &data, false).unwrap();

        // Assert length
        assert_eq!(iv.len(), enc_iv.len());
        assert_eq!(data.len(), enc_data.len());
    }

    #[test]
    fn unit_test_stable_length_16b() {
        let shared_secret = vec![4; KEY_SIZE];
        let iv = vec![5; IV_SIZE];
        let data = b"Some Crypto Text".to_vec();

        let mut crypt = CryptoContext::new(shared_secret, true);
        let (enc_iv, enc_data) = crypt.encrypt(Some(&iv), &data, false).unwrap();

        // Assert length
        assert_eq!(iv.len(), enc_iv.len());
        assert_eq!(data.len(), enc_data.len());
    }

    #[test]
    fn unit_test_valid_signature() {
        let keypair = Rsa::generate(2048).unwrap();

        let crypto_config = Arc::new(HandshakeCryptoConfig::new(
            Rsa::public_key_from_der(&keypair.public_key_to_der().unwrap()).unwrap(),
            keypair.clone(),
        ));
        let crypto_context = HandshakeCryptoContext::new(crypto_config.clone());

        let data = b"Some data to sign";
        let signature = crypto_context.sign(data);

        assert!(crypto_context.verify(crypto_config.public_host_key.clone(), &signature, data));
    }

    #[test]
    fn unit_test_invalid_signature() {
        let keypair = Rsa::generate(2048).unwrap();

        let crypto_config = Arc::new(HandshakeCryptoConfig::new(
            Rsa::public_key_from_der(&keypair.public_key_to_der().unwrap()).unwrap(),
            keypair.clone(),
        ));
        let crypto_context = HandshakeCryptoContext::new(crypto_config.clone());

        let data = b"Some data to sign";
        let mut signature = crypto_context.sign(data);
        signature[0] += 1;

        assert!(!crypto_context.verify(crypto_config.public_host_key.clone(), &signature, data));
    }
}
