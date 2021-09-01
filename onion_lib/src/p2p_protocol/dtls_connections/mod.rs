use openssl::pkey::Private;
use openssl::rsa::Rsa;
use openssl::x509::X509;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct DtlsConfig {
    pki_root_cert: X509,
    local_peer_identity_cert: X509,
    black_list_time: Duration,
    private_host_key: Rsa<Private>,
}

impl DtlsConfig {
    pub fn new(
        pki_root_cert: X509,
        local_peer_identity_cert: X509,
        black_list_time: Duration,
        private_host_key: Rsa<Private>,
    ) -> Self {
        Self {
            pki_root_cert,
            local_peer_identity_cert,
            black_list_time,
            private_host_key,
        }
    }
}
