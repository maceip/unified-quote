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
//!   uq enclave  — runs inside the enclave (vsock listener + TLS server)
//!   uq proxy    — runs on the parent (TCP:443 → vsock bridge)

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
            eprintln!("[uq/vsock] Loopback interface up");
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
                    eprintln!("[uq/vsock] Loopback interface up (via ip)");
                    Ok(())
                }
                _ => {
                    eprintln!("[uq/vsock] WARNING: could not set up loopback");
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
    eprintln!("[uq/vsock] Bridge listening: vsock:{VSOCK_PORT} → 127.0.0.1:{loopback_port}");

    loop {
        let client_fd = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if client_fd < 0 {
            eprintln!("[uq/vsock] Accept failed");
            continue;
        }

        let loopback_port = loopback_port;
        std::thread::spawn(move || {
            if let Err(e) = pipe_vsock_to_tcp(client_fd, loopback_port) {
                eprintln!("[uq/vsock] Pipe error: {e}");
            }
        });
    }
}

/// Bridge: TCP → vsock.
/// Runs on the parent instance. Accepts TCP connections on a port
/// and forwards them to the enclave's vsock.
pub fn bridge_tcp_to_vsock(listen_port: u16, enclave_cid: u32) -> Result<()> {
    let listener = std::net::TcpListener::bind(format!("0.0.0.0:{listen_port}"))?;
    eprintln!(
        "[uq/vsock] Proxy listening: TCP:{listen_port} → vsock CID {enclave_cid}:{VSOCK_PORT}"
    );

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[uq/vsock] TCP accept error: {e}");
                continue;
            }
        };

        let cid = enclave_cid;
        std::thread::spawn(move || {
            if let Err(e) = pipe_tcp_to_vsock(stream, cid) {
                eprintln!("[uq/vsock] Proxy pipe error: {e}");
            }
        });
    }

    Ok(())
}

/// Serve attestation JSON directly over vsock (simple mode, no TLS).
/// Used as a fallback when loopback is not available.
pub fn serve_vsock(attestation_json: &str) -> Result<()> {
    let fd = create_vsock_listener()?;
    eprintln!("[uq/vsock] Serving attestation on vsock port {VSOCK_PORT}");

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
/// Administration is unavailable on this unauthenticated public listener.
/// No route exports decrypted KMS plaintext or accepts TLS key replacement.
#[allow(unused_variables)]
pub fn serve_tls_vsock(
    tls_config: std::sync::Arc<rustls::ServerConfig>,
    attestation_json: &str,
    eat_cbor: &[u8],
    _kms_private_key: Option<Vec<u8>>,
    #[cfg(feature = "nitro")] kms_state: Option<std::sync::Arc<KmsState>>,
) -> Result<()> {
    let fd = create_vsock_listener()?;
    let eat_bytes = std::sync::Arc::new(eat_cbor.to_vec());
    #[cfg(feature = "nitro")]
    let kms_state_arc = kms_state;
    eprintln!("[uq/vsock] TLS+vsock listening on port {VSOCK_PORT}");
    eprintln!(
        "[uq/vsock] EAT endpoint: GET /eat ({} bytes)",
        eat_bytes.len()
    );
    eprintln!(
        "[uq/vsock] Public evidence routes only; KMS unwrap and TLS administration are disabled"
    );

    loop {
        let client_fd = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if client_fd < 0 {
            eprintln!("[uq/vsock] Accept failed");
            continue;
        }

        let config = tls_config.clone();
        let body = attestation_json.to_string();
        let eat_body = eat_bytes.clone();
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
                    eprintln!("[uq/vsock] TLS conn: {e}");
                    return;
                }
            };
            let mut tls = rustls::StreamOwned::new(conn, stream);

            // Only read bounded headers: every admitted route is read-only and
            // accepts no body. Close each connection after one response.
            let mut buf = vec![0u8; MAX_HTTP_HEADER_BYTES];
            let mut total = 0;
            while total < buf.len() {
                match tls.read(&mut buf[total..]) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => total += n,
                }
                if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let route = match evidence_route(&buf[..total]) {
                Ok(route) => route,
                Err((status, detail)) => {
                    let _ = tls.write_all(http_response(status, detail).as_bytes());
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                    return;
                }
            };

            // /eat gets a binary response — everything else stays text.
            // We split the response path so the CBOR bytes never pass
            // through the String-based response builder.
            if route == EvidenceRoute::Eat {
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

            let response = match route {
                #[cfg(feature = "nitro")]
                EvidenceRoute::KmsAttestation => handle_kms_attestation(&kms_st),
                #[cfg(not(feature = "nitro"))]
                EvidenceRoute::KmsAttestation => http_response(404, "KMS evidence is unavailable"),
                EvidenceRoute::Summary => format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(), body
                ),
                EvidenceRoute::Eat => unreachable!("binary EAT handled above"),
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
            eprintln!("[uq/vsock] Fresh attestation: {} bytes", doc.len());
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
            eprintln!("[uq/vsock] Fresh attestation failed: {e}");
            http_response(500, &format!("attestation refresh failed: {e}"))
        }
    }
}

const MAX_HTTP_HEADER_BYTES: usize = 32 * 1024;

#[derive(Debug, PartialEq, Eq)]
enum EvidenceRoute {
    Summary,
    Eat,
    KmsAttestation,
}

/// Parse the complete public request before selecting a read-only handler.
/// The public socket has no client authentication, so it cannot authorize key
/// installation, challenge installation, or plaintext release.
fn evidence_route(request: &[u8]) -> Result<EvidenceRoute, (u16, &'static str)> {
    let bad = (400, "invalid read-only HTTP request");
    if request.len() > MAX_HTTP_HEADER_BYTES {
        return Err(bad);
    }
    let end = request
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(bad)?;
    let header = std::str::from_utf8(&request[..end]).map_err(|_| bad)?;
    let mut lines = header.split("\r\n");
    let mut first = lines.next().ok_or(bad)?.split(' ');
    let method = first.next().ok_or(bad)?;
    let path = first.next().ok_or(bad)?;
    if first.next() != Some("HTTP/1.1")
        || first.next().is_some()
        || path.contains(['?', '#'])
        || !path.starts_with('/')
    {
        return Err(bad);
    }
    let mut host_count = 0;
    let mut length_count = 0;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(bad)?;
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || value.bytes().any(|b| b < 0x20 && b != b'\t')
        {
            return Err(bad);
        }
        if name.eq_ignore_ascii_case("host") {
            host_count += 1;
            if value.trim().is_empty() {
                return Err(bad);
            }
        } else if name.eq_ignore_ascii_case("content-length") {
            length_count += 1;
            if value.trim() != "0" {
                return Err(bad);
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(bad);
        }
    }
    if host_count != 1 || length_count > 1 || request.len() != end + 4 {
        return Err(bad);
    }
    if matches!(path, "/kms-unwrap" | "/tls-cert" | "/acme-challenge") {
        return Err((
            403,
            "administration and plaintext release are disabled on the public evidence listener",
        ));
    }
    if method != "GET" {
        return Err((405, "only read-only evidence requests are supported"));
    }
    match path {
        "/" => Ok(EvidenceRoute::Summary),
        "/eat" => Ok(EvidenceRoute::Eat),
        "/kms-attestation" => Ok(EvidenceRoute::KmsAttestation),
        _ => Err((404, "unknown evidence route")),
    }
}

fn http_response(status: u16, body: &str) -> String {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "Error",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: text/plain\r\n\
         Connection: close\r\n\
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

#[cfg(test)]
mod admission_boundary_tests {
    use super::*;

    #[test]
    fn public_listener_never_authorizes_secret_release_or_tls_mutation() {
        for path in ["/kms-unwrap", "/tls-cert", "/acme-challenge"] {
            for method in ["GET", "POST", "PUT"] {
                let request = format!("{method} {path} HTTP/1.1\r\nHost: enclave\r\n\r\n");
                assert_eq!(evidence_route(request.as_bytes()).unwrap_err().0, 403);
            }
            let request =
                format!("POST {path} HTTP/1.1\r\nHost: enclave\r\nContent-Length: 6\r\n\r\nsecret");
            assert!(evidence_route(request.as_bytes()).is_err());
        }
    }

    #[test]
    fn public_evidence_routes_are_explicit_and_read_only() {
        for (path, expected) in [
            ("/", EvidenceRoute::Summary),
            ("/eat", EvidenceRoute::Eat),
            ("/kms-attestation", EvidenceRoute::KmsAttestation),
        ] {
            let request = format!("GET {path} HTTP/1.1\r\nHost: enclave\r\n\r\n");
            assert_eq!(evidence_route(request.as_bytes()).unwrap(), expected);
        }
        assert_eq!(
            evidence_route(b"POST / HTTP/1.1\r\nHost: enclave\r\n\r\n")
                .unwrap_err()
                .0,
            405
        );
        assert_eq!(
            evidence_route(b"GET /unknown HTTP/1.1\r\nHost: enclave\r\n\r\n")
                .unwrap_err()
                .0,
            404
        );
    }

    #[test]
    fn ambiguous_framing_and_targets_are_rejected() {
        for request in [
            "GET /eat HTTP/1.1\r\nHost: first\r\nHost: second\r\n\r\n",
            "GET /eat HTTP/1.1\r\nHost: enclave\r\nContent-Length: 0\r\ncontent-length: 0\r\n\r\n",
            "GET /eat HTTP/1.1\r\nHost: enclave\r\nTransfer-Encoding: chunked\r\n\r\n",
            "GET /eat?x HTTP/1.1\r\nHost: enclave\r\n\r\n",
            "GET /eat#x HTTP/1.1\r\nHost: enclave\r\n\r\n",
            "GET /eat HTTP/1.1\r\nHost: enclave\r\n\r\nPOST /tls-cert HTTP/1.1\r\n\r\n",
            "GET /eat HTTP/1.1\r\nHost: enclave\r\nContent-Length : 0\r\n\r\n",
            "GET /eat HTTP/1.1\r\nHost: enclave",
        ] {
            assert!(evidence_route(request.as_bytes()).is_err(), "{request:?}");
        }
    }
}
