//! vsock networking for Nitro Enclaves.
//!
//! TLS terminates INSIDE the enclave. The host never sees plaintext.
//!
//! Architecture (following Evervault/Turnkey pattern):
//!   Verifier → TCP:443 → [Parent: tcp-to-vsock bridge] → vsock →
//!     [Enclave: vsock-to-loopback bridge] → 127.0.0.1:443 →
//!       rustls TLS termination → attestation JSON
//!
//! Two commands:
//!   bountynet enclave  — runs inside the enclave (vsock listener + TLS server)
//!   bountynet proxy    — runs on the parent (TCP:443 → vsock bridge)

use anyhow::Result;
use std::io::{Read, Write};

/// vsock port for the bridge
pub const VSOCK_PORT: u32 = 9384;

/// KMS state held by the enclave for the lifetime of the server.
/// The RSA keypair is generated once; attestation documents are refreshed per-request.
#[cfg(feature = "nitro")]
pub struct KmsState {
    pub nsm: std::sync::Arc<crate::tee::nitro::NitroProvider>,
    pub report_data: [u8; 64],
    pub rsa_pub_der: Vec<u8>,
    pub rsa_priv_der: Vec<u8>,
}

/// Set up loopback interface inside the enclave.
/// Nitro Enclaves have no network interfaces by default.
pub fn setup_loopback() -> Result<()> {
    let status = std::process::Command::new("ifconfig")
        .args(["lo", "127.0.0.1", "up"])
        .status();

    match status {
        Ok(s) if s.success() => {
            eprintln!("[bountynet/vsock] Loopback interface up");
            Ok(())
        }
        _ => {
            // ifconfig might not exist in minimal images — try ip command
            let status2 = std::process::Command::new("ip")
                .args(["link", "set", "lo", "up"])
                .status();
            match status2 {
                Ok(s) if s.success() => {
                    let _ = std::process::Command::new("ip")
                        .args(["addr", "add", "127.0.0.1/8", "dev", "lo"])
                        .status();
                    eprintln!("[bountynet/vsock] Loopback interface up (via ip)");
                    Ok(())
                }
                _ => {
                    eprintln!("[bountynet/vsock] WARNING: could not set up loopback");
                    Ok(()) // Continue anyway — vsock direct serving still works
                }
            }
        }
    }
}

/// Bridge: vsock → TCP loopback.
/// Runs inside the enclave. Accepts vsock connections from the parent
/// and forwards them to the TLS server on 127.0.0.1:443.
pub fn bridge_vsock_to_loopback(loopback_port: u16) -> Result<()> {
    let fd = create_vsock_listener()?;
    eprintln!("[bountynet/vsock] Bridge listening: vsock:{VSOCK_PORT} → 127.0.0.1:{loopback_port}");

    loop {
        let client_fd = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if client_fd < 0 {
            eprintln!("[bountynet/vsock] Accept failed");
            continue;
        }

        let loopback_port = loopback_port;
        std::thread::spawn(move || {
            if let Err(e) = pipe_vsock_to_tcp(client_fd, loopback_port) {
                eprintln!("[bountynet/vsock] Pipe error: {e}");
            }
        });
    }
}

/// Bridge: TCP → vsock.
/// Runs on the parent instance. Accepts TCP connections on a port
/// and forwards them to the enclave's vsock.
pub fn bridge_tcp_to_vsock(listen_port: u16, enclave_cid: u32) -> Result<()> {
    let listener = std::net::TcpListener::bind(format!("0.0.0.0:{listen_port}"))?;
    eprintln!("[bountynet/vsock] Proxy listening: TCP:{listen_port} → vsock CID {enclave_cid}:{VSOCK_PORT}");

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[bountynet/vsock] TCP accept error: {e}");
                continue;
            }
        };

        let cid = enclave_cid;
        std::thread::spawn(move || {
            if let Err(e) = pipe_tcp_to_vsock(stream, cid) {
                eprintln!("[bountynet/vsock] Proxy pipe error: {e}");
            }
        });
    }

    Ok(())
}

/// Serve attestation JSON directly over vsock (simple mode, no TLS).
/// Used as a fallback when loopback is not available.
pub fn serve_vsock(attestation_json: &str) -> Result<()> {
    let fd = create_vsock_listener()?;
    eprintln!("[bountynet/vsock] Serving attestation on vsock port {VSOCK_PORT}");

    loop {
        let client_fd = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if client_fd < 0 {
            continue;
        }

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            attestation_json.len(),
            attestation_json
        );

        let bytes = response.as_bytes();
        let mut written = 0;
        while written < bytes.len() {
            let n = unsafe {
                libc::write(
                    client_fd,
                    bytes[written..].as_ptr() as *const libc::c_void,
                    bytes.len() - written,
                )
            };
            if n <= 0 {
                break;
            }
            written += n as usize;
        }
        unsafe { libc::close(client_fd) };
    }
}

/// TLS server directly on vsock. No loopback needed.
/// Each vsock connection gets a rustls TLS handshake.
/// The parent proxy forwards raw TCP bytes from the verifier.
///
/// Routes:
///   GET  /                → attestation JSON (static, from boot)
///   GET  /eat             → EAT token CBOR bytes (application/eat+cbor)
///   GET  /kms-attestation → fresh attestation document (< 5 min old, for KMS)
///   POST /kms-unwrap      → decrypt CiphertextForRecipient with enclave RSA key
///   POST /tls-cert        → hot-swap TLS certificate (PEM cert + key, for ACME)
#[allow(unused_variables)]
pub fn serve_tls_vsock(
    tls_config: std::sync::Arc<rustls::ServerConfig>,
    attestation_json: &str,
    eat_cbor: &[u8],
    kms_private_key: Option<Vec<u8>>,
    #[cfg(feature = "nitro")] kms_state: Option<std::sync::Arc<KmsState>>,
) -> Result<()> {
    let fd = create_vsock_listener()?;
    let kms_key = std::sync::Arc::new(kms_private_key);
    let eat_bytes = std::sync::Arc::new(eat_cbor.to_vec());
    // Hot-swappable TLS config — ACME updates this after provisioning a real cert
    let live_config: std::sync::Arc<std::sync::RwLock<std::sync::Arc<rustls::ServerConfig>>> =
        std::sync::Arc::new(std::sync::RwLock::new(tls_config));
    #[cfg(feature = "nitro")]
    let kms_state_arc = kms_state;
    eprintln!("[bountynet/vsock] TLS+vsock listening on port {VSOCK_PORT}");
    eprintln!(
        "[bountynet/vsock] EAT endpoint: GET /eat ({} bytes)",
        eat_bytes.len()
    );
    if kms_key.is_some() {
        eprintln!("[bountynet/vsock] KMS endpoints: GET /kms-attestation, POST /kms-unwrap");
    }

    loop {
        let client_fd = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if client_fd < 0 {
            eprintln!("[bountynet/vsock] Accept failed");
            continue;
        }

        // Read current TLS config (may have been hot-swapped by ACME)
        let config = live_config.read().unwrap().clone();
        let live_cfg = live_config.clone();
        let body = attestation_json.to_string();
        let eat_body = eat_bytes.clone();
        let kms_key = kms_key.clone();
        #[cfg(feature = "nitro")]
        let kms_st = kms_state_arc.clone();
        std::thread::spawn(move || {
            use std::io::{Read, Write};

            // Wrap vsock fd as a File for Read/Write
            let vsock_stream = unsafe { std::fs::File::from_raw_fd(client_fd) };
            let vsock_read = match vsock_stream.try_clone() {
                Ok(f) => f,
                Err(_) => return,
            };

            // Create a ReadWrite wrapper for rustls
            let stream = VsockStream {
                read: vsock_read,
                write: vsock_stream,
            };

            // TLS handshake on the vsock connection
            let conn = match rustls::ServerConnection::new(config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[bountynet/vsock] TLS conn: {e}");
                    return;
                }
            };
            let mut tls = rustls::StreamOwned::new(conn, stream);

            // Read the full HTTP request (headers + body).
            // TLS may deliver headers and body in separate records,
            // so read until we have Content-Length bytes of body.
            let mut buf = vec![0u8; 32768];
            let mut total = 0;
            loop {
                let n = match tls.read(&mut buf[total..]) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                total += n;
                // Check if we have the full request (headers + body)
                let so_far = &buf[..total];
                if let Some(hdr_end) = so_far.windows(4).position(|w| w == b"\r\n\r\n") {
                    let hdr = String::from_utf8_lossy(&so_far[..hdr_end]);
                    let content_len = hdr
                        .lines()
                        .find_map(|l| {
                            l.strip_prefix("Content-Length: ")
                                .or_else(|| l.strip_prefix("content-length: "))
                        })
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    let body_start = hdr_end + 4;
                    if total >= body_start + content_len {
                        break; // Got everything
                    }
                }
                if total >= buf.len() {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&buf[..total]);

            // Parse method and path from first line
            let first_line = request.lines().next().unwrap_or("");
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            let method = parts.first().copied().unwrap_or("");
            let path = parts.get(1).copied().unwrap_or("/");

            // /eat gets a binary response — everything else stays text.
            // We split the response path so the CBOR bytes never pass
            // through the String-based response builder.
            if method == "GET" && path == "/eat" {
                let header = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/eat+cbor\r\n\
                     Content-Length: {}\r\n\
                     Access-Control-Allow-Origin: *\r\n\
                     \r\n",
                    eat_body.len()
                );
                let _ = tls.write_all(header.as_bytes());
                let _ = tls.write_all(&eat_body);
                let _ = tls.conn.send_close_notify();
                let _ = tls.flush();
                return;
            }

            let response = match (method, path) {
                #[cfg(feature = "nitro")]
                ("GET", "/kms-attestation") => handle_kms_attestation(&kms_st),
                ("POST", "/kms-unwrap") => handle_kms_unwrap(&request, &kms_key),
                ("POST", "/tls-cert") => handle_tls_cert_swap(&request, &live_cfg),
                ("POST", "/acme-challenge") => handle_acme_challenge(&request, &live_cfg),
                _ => {
                    // Default: serve attestation JSON
                    format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: application/json\r\n\
                         Content-Length: {}\r\n\
                         Access-Control-Allow-Origin: *\r\n\
                         \r\n\
                         {}",
                        body.len(),
                        body
                    )
                }
            };

            let _ = tls.write_all(response.as_bytes());
            let _ = tls.conn.send_close_notify();
            let _ = tls.flush();
        });
    }
}

/// Handle GET /kms-attestation: generate a fresh attestation document.
/// KMS rejects documents older than 5 minutes, so the parent must call
/// this endpoint immediately before each `aws kms decrypt --recipient` call.
///
/// Response: JSON { "attestation_document_b64": "<base64>" }
#[cfg(feature = "nitro")]
fn handle_kms_attestation(kms_state: &Option<std::sync::Arc<KmsState>>) -> String {
    let state = match kms_state {
        Some(s) => s,
        None => return http_response(400, "KMS state not available"),
    };

    match state
        .nsm
        .fresh_attestation(&state.report_data, &state.rsa_pub_der)
    {
        Ok(doc) => {
            use base64::Engine;
            let doc_b64 = base64::engine::general_purpose::STANDARD.encode(&doc);
            eprintln!("[bountynet/vsock] Fresh attestation: {} bytes", doc.len());
            let json = format!("{{\"attestation_document_b64\":\"{doc_b64}\"}}");
            format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 \r\n\
                 {}",
                json.len(),
                json
            )
        }
        Err(e) => {
            eprintln!("[bountynet/vsock] Fresh attestation failed: {e}");
            http_response(500, &format!("attestation refresh failed: {e}"))
        }
    }
}

/// Handle POST /kms-unwrap: decrypt CiphertextForRecipient with the enclave's RSA key.
///
/// Request body: base64-encoded CiphertextForRecipient from KMS.
/// Response: base64-encoded plaintext (the decrypted secret).
///
/// Flow:
///   1. Parent calls `aws kms decrypt --recipient ...` → gets CiphertextForRecipient
///   2. Parent sends it here via `curl -X POST https://.../kms-unwrap -d <base64>`
///   3. Enclave decrypts with RSA private key → returns plaintext
/// Handle POST /tls-cert: hot-swap the TLS certificate (normal mode).
/// Body: PEM cert chain + private key concatenated.
fn handle_tls_cert_swap(
    request: &str,
    live_config: &std::sync::Arc<std::sync::RwLock<std::sync::Arc<rustls::ServerConfig>>>,
) -> String {
    swap_tls_config(request, live_config, false)
}

/// Handle POST /acme-challenge: install ACME challenge cert with acme-tls/1 ALPN.
/// Body: PEM cert chain + private key concatenated.
fn handle_acme_challenge(
    request: &str,
    live_config: &std::sync::Arc<std::sync::RwLock<std::sync::Arc<rustls::ServerConfig>>>,
) -> String {
    swap_tls_config(request, live_config, true)
}

fn swap_tls_config(
    request: &str,
    live_config: &std::sync::Arc<std::sync::RwLock<std::sync::Arc<rustls::ServerConfig>>>,
    acme_alpn: bool,
) -> String {
    let body = match request.find("\r\n\r\n") {
        Some(pos) => &request[pos + 4..],
        None => return http_response(400, "malformed request"),
    };

    if body.is_empty() {
        return http_response(400, "empty body — send PEM cert + key");
    }

    // For ACME challenge certs, use unchecked config (acmeIdentifier is a critical
    // extension that rustls doesn't recognize). Normal certs use standard validation.
    let config_result = if acme_alpn {
        crate::net::tls::make_server_config_unchecked(body.as_bytes(), body.as_bytes())
    } else {
        crate::net::tls::make_server_config(body.as_bytes(), body.as_bytes())
    };
    match config_result {
        Ok(mut new_config) => {
            if acme_alpn {
                // Accept both acme-tls/1 (for LE validation) and h2/http1.1 (for our own POST /tls-cert)
                new_config.alpn_protocols = vec![b"acme-tls/1".to_vec(), b"http/1.1".to_vec()];
                eprintln!(
                    "[bountynet/vsock] ACME challenge cert installed (alpn: acme-tls/1 + http/1.1)"
                );
            } else {
                eprintln!("[bountynet/vsock] TLS cert hot-swapped");
            }
            let mut guard = live_config.write().unwrap();
            *guard = std::sync::Arc::new(new_config);
            http_response(200, "cert installed")
        }
        Err(e) => {
            eprintln!("[bountynet/vsock] TLS cert swap failed: {e}");
            http_response(400, &format!("invalid cert/key: {e}"))
        }
    }
}

fn handle_kms_unwrap(request: &str, kms_key: &Option<Vec<u8>>) -> String {
    let kms_key = match kms_key {
        Some(k) => k,
        None => {
            return http_response(400, "KMS key not available (not a Nitro enclave?)");
        }
    };

    // Extract body after the \r\n\r\n header separator
    let body = match request.find("\r\n\r\n") {
        Some(pos) => request[pos + 4..].trim(),
        None => {
            return http_response(400, "malformed request");
        }
    };

    if body.is_empty() {
        return http_response(400, "empty body — send base64(CiphertextForRecipient)");
    }

    // Decode base64 ciphertext
    use base64::Engine;
    let ciphertext = match base64::engine::general_purpose::STANDARD.decode(body) {
        Ok(c) => c,
        Err(e) => {
            return http_response(400, &format!("base64 decode error: {e}"));
        }
    };

    // Decrypt with RSA-OAEP-SHA256
    #[cfg(feature = "nitro")]
    {
        match crate::tee::nitro::kms_decrypt(kms_key, &ciphertext) {
            Ok(plaintext) => {
                let b64 = base64::engine::general_purpose::STANDARD.encode(&plaintext);
                eprintln!(
                    "[bountynet/vsock] KMS unwrap: {} bytes decrypted",
                    plaintext.len()
                );
                http_response(200, &b64)
            }
            Err(e) => {
                eprintln!("[bountynet/vsock] KMS unwrap failed: {e}");
                http_response(500, &format!("decrypt failed: {e}"))
            }
        }
    }
    #[cfg(not(feature = "nitro"))]
    {
        http_response(400, "KMS unwrap requires nitro feature")
    }
}

fn http_response(status: u16, body: &str) -> String {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        500 => "Internal Server Error",
        _ => "Error",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        body.len(),
        body
    )
}

/// Wrapper to give a vsock fd both Read and Write via separate cloned fds.
struct VsockStream {
    read: std::fs::File,
    write: std::fs::File,
}

impl std::io::Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read.read(buf)
    }
}

impl std::io::Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.write.flush()
    }
}

// --- Internal helpers ---

fn create_vsock_listener() -> Result<i32> {
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        anyhow::bail!(
            "Failed to create vsock socket: {}",
            std::io::Error::last_os_error()
        );
    }

    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as _;
    addr.svm_port = VSOCK_PORT;
    addr.svm_cid = libc::VMADDR_CID_ANY;

    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as u32,
        )
    };
    if ret < 0 {
        anyhow::bail!("Failed to bind vsock: {}", std::io::Error::last_os_error());
    }

    let ret = unsafe { libc::listen(fd, 5) };
    if ret < 0 {
        anyhow::bail!(
            "Failed to listen on vsock: {}",
            std::io::Error::last_os_error()
        );
    }

    Ok(fd)
}

fn pipe_vsock_to_tcp(vsock_fd: i32, loopback_port: u16) -> Result<()> {
    let tcp = std::net::TcpStream::connect(format!("127.0.0.1:{loopback_port}"))?;
    let mut tcp_read = tcp.try_clone()?;
    let mut tcp_write = tcp;

    // vsock fd → safe File wrapper
    let vsock_file = unsafe { std::fs::File::from_raw_fd(vsock_fd) };
    let mut vsock_read = vsock_file.try_clone()?;
    let mut vsock_write = vsock_file;

    // Bidirectional pipe: vsock ↔ tcp
    let handle = std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            let n = match vsock_read.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if tcp_write.write_all(&buf[..n]).is_err() {
                break;
            }
        }
    });

    let mut buf = [0u8; 8192];
    loop {
        let n = match tcp_read.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if vsock_write.write_all(&buf[..n]).is_err() {
            break;
        }
    }

    let _ = handle.join();
    Ok(())
}

use std::os::unix::io::FromRawFd;

fn pipe_tcp_to_vsock(tcp: std::net::TcpStream, enclave_cid: u32) -> Result<()> {
    // Connect to enclave vsock
    let vsock_fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if vsock_fd < 0 {
        anyhow::bail!("vsock socket failed");
    }

    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as _;
    addr.svm_port = VSOCK_PORT;
    addr.svm_cid = enclave_cid;

    let ret = unsafe {
        libc::connect(
            vsock_fd,
            &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as u32,
        )
    };
    if ret < 0 {
        unsafe { libc::close(vsock_fd) };
        anyhow::bail!(
            "vsock connect to CID {enclave_cid} failed: {}",
            std::io::Error::last_os_error()
        );
    }

    let vsock_file = unsafe { std::fs::File::from_raw_fd(vsock_fd) };
    let mut vsock_read = vsock_file.try_clone()?;
    let mut vsock_write = vsock_file;

    let mut tcp_read = tcp.try_clone()?;
    let mut tcp_write = tcp;

    // Bidirectional pipe: tcp ↔ vsock
    let handle = std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            let n = match tcp_read.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if vsock_write.write_all(&buf[..n]).is_err() {
                break;
            }
        }
    });

    let mut buf = [0u8; 8192];
    loop {
        let n = match vsock_read.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if tcp_write.write_all(&buf[..n]).is_err() {
            break;
        }
    }

    let _ = handle.join();
    Ok(())
}
