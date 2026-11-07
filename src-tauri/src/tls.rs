//! Live TLS inspection: performs a real handshake with rustls, records the presented chain and
//! reports whether it validates against the operating system's trust store (falling back to
//! Mozilla's roots), including hostname checks. Untrusted chains are still shown.

use crate::model::TlsInspectionResult;
use crate::util::*;
use crate::x509;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct Recorder {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    chain: Mutex<Vec<Vec<u8>>>,
    error: Mutex<Option<String>>,
}

impl ServerCertVerifier for Recorder {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain = vec![end_entity.to_vec()];
        chain.extend(intermediates.iter().map(|c| c.to_vec()));
        *self.chain.lock().unwrap() = chain;
        if let Err(err) = self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp, now) {
            *self.error.lock().unwrap() = Some(describe_error(&err));
        }
        // Continue the handshake so untrusted servers can still be inspected; nothing is sent.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn describe_error(err: &rustls::Error) -> String {
    use rustls::CertificateError as C;
    match err {
        rustls::Error::InvalidCertificate(c) => match c {
            C::UnknownIssuer => "the chain does not lead to a trusted root (unknown issuer / self-signed)".into(),
            C::Expired | C::ExpiredContext { .. } => "the server certificate has expired".into(),
            C::NotValidYet | C::NotValidYetContext { .. } => "the server certificate is not valid yet".into(),
            C::NotValidForName | C::NotValidForNameContext { .. } => "the certificate is not valid for this hostname".into(),
            C::Revoked => "the certificate has been revoked".into(),
            C::BadSignature => "a certificate in the chain has an invalid signature".into(),
            C::InvalidPurpose | C::InvalidPurposeContext { .. } => "the certificate is not valid for TLS server authentication".into(),
            other => {
                // webpki errors arrive wrapped as Other(OtherError(Name)); show a sentence.
                let raw = format!("{other:?}");
                let name = raw.trim_start_matches("Other(OtherError(").trim_end_matches(')');
                match name {
                    "CaUsedAsEndEntity" => "the server presented a CA certificate as its own certificate".into(),
                    "EndEntityUsedAsCa" => "an end-entity certificate is used as an issuing CA in the chain".into(),
                    "UnsupportedSignatureAlgorithm" | "UnsupportedSignatureAlgorithmForPublicKey" => "the chain uses a signature algorithm that is not accepted".into(),
                    "PathLenConstraintViolated" => "the chain violates a CA path length constraint".into(),
                    "NameConstraintViolation" => "the certificate violates its issuer's name constraints".into(),
                    "UnknownIssuer" => "the chain does not lead to a trusted root (unknown issuer / self-signed)".into(),
                    n => format!("certificate rejected ({n})"),
                }
            }
        },
        other => other.to_string(),
    }
}

fn root_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = roots.add(cert);
    }
    if roots.is_empty() {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    roots
}

/// Splits "https://host:8443/path", "host:443", "[::1]:443" or "host" into (host, port).
pub fn parse_target(input: &str, default_port: u16) -> Res<(String, u16)> {
    let mut s = input.trim();
    for prefix in ["https://", "http://", "ldaps://", "tls://"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest;
        }
    }
    let s = s.split(['/', '?', '#']).next().unwrap_or("");
    let s = s.rsplit('@').next().unwrap_or(s);
    if s.is_empty() {
        return Err("enter a hostname".into());
    }
    if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or("invalid IPv6 address")?;
        let port = after.strip_prefix(':').map(|p| p.parse::<u16>().map_err(|_| "invalid port")).transpose()?.unwrap_or(default_port);
        return Ok((host.to_string(), port));
    }
    if s.matches(':').count() == 1 {
        let (host, port) = s.split_once(':').unwrap();
        let port = port.parse::<u16>().map_err(|_| format!("'{port}' is not a valid port"))?;
        return Ok((host.to_string(), port));
    }
    Ok((s.to_string(), default_port))
}

pub fn inspect(target: &str, port: u16, timeout_secs: u64) -> Res<TlsInspectionResult> {
    let (host, port) = parse_target(target, port)?;
    if port == 0 {
        return Err("port must be between 1 and 65535".into());
    }
    let timeout = Duration::from_secs(timeout_secs.clamp(2, 60));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(root_store()), provider.clone()).build().map_err(|err| format!("cannot initialise TLS verifier: {err}"))?;
    let recorder = Arc::new(Recorder { inner, chain: Mutex::new(vec![]), error: Mutex::new(None) });
    let mut config =
        ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().map_err(e)?.dangerous().with_custom_certificate_verifier(recorder.clone()).with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let server_name = ServerName::try_from(host.clone()).map_err(|_| format!("'{host}' is not a valid hostname or IP address"))?;

    let addr = (host.as_str(), port).to_socket_addrs().map_err(|err| format!("cannot resolve {host}: {err}"))?.next().ok_or_else(|| format!("{host} did not resolve to an address"))?;
    let started = Instant::now();
    let mut sock = TcpStream::connect_timeout(&addr, timeout).map_err(|err| format!("cannot connect to {host}:{port} ({addr}): {err}"))?;
    sock.set_read_timeout(Some(timeout)).ok();
    sock.set_write_timeout(Some(timeout)).ok();
    let mut conn = ClientConnection::new(Arc::new(config), server_name).map_err(e)?;
    while conn.is_handshaking() {
        if let Err(err) = conn.complete_io(&mut sock) {
            let chain_seen = !recorder.chain.lock().unwrap().is_empty();
            let hint = if err.kind() == std::io::ErrorKind::WouldBlock || err.kind() == std::io::ErrorKind::TimedOut {
                "timed out waiting for the server (is this a TLS port?)".to_string()
            } else {
                err.to_string()
            };
            if !chain_seen {
                return Err(format!("TLS handshake with {host}:{port} failed: {hint}"));
            }
            break;
        }
        if started.elapsed() > timeout {
            return Err(format!("TLS handshake with {host}:{port} timed out"));
        }
    }
    let handshake_ms = started.elapsed().as_millis() as u64;
    let protocol = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLS 1.3".to_string(),
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLS 1.2".to_string(),
        Some(v) => format!("{v:?}"),
        None => "unknown".into(),
    };
    let cipher_suite = conn.negotiated_cipher_suite().map(|s| format!("{:?}", s.suite())).unwrap_or_else(|| "unknown".into());
    let alpn = conn.alpn_protocol().map(|p| String::from_utf8_lossy(p).to_string());
    conn.send_close_notify();
    let _ = conn.write_tls(&mut sock);
    let _ = sock.flush();

    let chain = recorder.chain.lock().unwrap().clone();
    if chain.is_empty() {
        return Err(format!("{host}:{port} did not present a certificate"));
    }
    let certificates = chain.iter().map(|c| x509::parse_certificate(c)).collect::<Res<Vec<_>>>()?;
    let verification_error = recorder.error.lock().unwrap().clone();
    let hostname_matches = !verification_error.as_deref().is_some_and(|m| m.contains("hostname"));
    Ok(TlsInspectionResult {
        host,
        port,
        address: addr.to_string(),
        protocol,
        cipher_suite,
        alpn,
        trusted: verification_error.is_none(),
        verification_error,
        hostname_matches,
        certificates,
        handshake_ms,
        inspected_at: fmt_ts(now_ts()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_parsing() {
        assert_eq!(parse_target("https://example.com:8443/x?y", 443).unwrap(), ("example.com".into(), 8443));
        assert_eq!(parse_target("example.com", 443).unwrap(), ("example.com".into(), 443));
        assert_eq!(parse_target("[::1]:9443", 443).unwrap(), ("::1".into(), 9443));
        assert_eq!(parse_target("::1", 443).unwrap(), ("::1".into(), 443));
        assert!(parse_target("host:notaport", 443).is_err());
        assert!(parse_target("  ", 443).is_err());
    }
}
