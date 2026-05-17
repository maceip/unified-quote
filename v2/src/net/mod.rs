pub mod acme;
pub mod attested_tls;
pub mod ct;
pub mod tls;

#[cfg(unix)]
pub mod vsock;

#[cfg(not(unix))]
pub mod vsock {
    use anyhow::Result;

    pub const VSOCK_PORT: u32 = 9384;

    fn unsupported() -> anyhow::Error {
        anyhow::anyhow!("vsock networking is only available on Unix/Linux TEE hosts")
    }

    pub fn setup_loopback() -> Result<()> {
        Err(unsupported())
    }

    pub fn bridge_vsock_to_loopback(_loopback_port: u16) -> Result<()> {
        Err(unsupported())
    }

    pub fn bridge_tcp_to_vsock(_listen_port: u16, _enclave_cid: u32) -> Result<()> {
        Err(unsupported())
    }

    pub fn serve_vsock(_attestation_json: &str) -> Result<()> {
        Err(unsupported())
    }

    #[allow(unused_variables)]
    pub fn serve_tls_vsock(
        _tls_config: std::sync::Arc<rustls::ServerConfig>,
        _attestation_json: &str,
        _eat_cbor: &[u8],
        _kms_private_key: Option<Vec<u8>>,
    ) -> Result<()> {
        Err(unsupported())
    }
}
