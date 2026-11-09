//! Whether this machine can reach a server port: the TCP check `Test-NetConnection -Port` makes on
//! Windows, available on every platform. The name is resolved to all its addresses, and each is
//! tried in turn until one accepts a TCP connection. The result says which address answered, from
//! which local address and interface, and how long it took; or, when nothing answered, why.
//!
//! No ICMP ping and no trace route: a port test needs neither, and both need privileges or tools
//! that differ by platform.

use crate::tls::parse_target;
use crate::util::{Res, fmt_ts, now_ts};
use serde::Serialize;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// At most this many resolved addresses are tried, so an unreachable name with many addresses
/// does not keep the caller waiting for one timeout per address.
const MAX_ATTEMPTS: usize = 4;

#[derive(Serialize, Debug, Clone)]
pub struct ConnectAttempt {
    pub address: String,
    pub succeeded: bool,
    pub error: Option<String>,
    pub elapsed_ms: u64,
}

#[derive(Serialize, Debug, Clone)]
pub struct ConnectionTest {
    /// The host as given (without scheme, path or port).
    pub computer_name: String,
    pub remote_port: u16,
    /// Every address the name resolved to, in the order the resolver gave them.
    pub name_resolution: Vec<String>,
    pub resolve_ms: u64,
    /// The address that accepted the connection, else the first one tried.
    pub remote_address: Option<String>,
    /// The local address the connection left from.
    pub source_address: Option<String>,
    /// The network interface holding the source address (e.g. en0, or utun3 for a VPN).
    pub interface_alias: Option<String>,
    pub tcp_test_succeeded: bool,
    pub tcp_ms: Option<u64>,
    pub attempts: Vec<ConnectAttempt>,
    /// "name-resolution", "refused", "timed-out", "unreachable" or "error".
    pub failure: Option<String>,
    /// What the failure most likely means, in a sentence.
    pub hint: Option<String>,
    pub tested_at: String,
}

fn classify(err: &std::io::Error) -> &'static str {
    match err.kind() {
        ErrorKind::ConnectionRefused => "refused",
        ErrorKind::TimedOut | ErrorKind::WouldBlock => "timed-out",
        ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable | ErrorKind::AddrNotAvailable => "unreachable",
        _ => "error",
    }
}

fn hint_for(failure: &str, host: &str, port: u16, timeout: Duration) -> String {
    match failure {
        "name-resolution" => format!("{host} could not be resolved to an address. Check the spelling, your DNS settings, or whether the name only resolves on a VPN."),
        "refused" => format!("The host answered, but nothing accepts connections on port {port} (or a firewall rejected them)."),
        "timed-out" => format!("No answer within {} s. A firewall may be dropping the traffic, the host may be down, or you may need a VPN or proxy to reach it.", timeout.as_secs()),
        "unreachable" => "There is no network route to the host from this machine. Check your network connection or VPN.".to_string(),
        _ => format!("The connection to {host}:{port} failed."),
    }
}

/// Tests a TCP connection to `target` (a host, host:port or URL; a port in it wins over `port`).
pub fn test(target: &str, port: u16, timeout_secs: u64) -> Res<ConnectionTest> {
    let (host, port) = parse_target(target, port)?;
    if port == 0 {
        return Err("port must be between 1 and 65535".into());
    }
    let timeout = Duration::from_secs(timeout_secs.clamp(1, 60));
    let tested_at = fmt_ts(now_ts());

    let started = Instant::now();
    let resolved = (host.as_str(), port).to_socket_addrs();
    let resolve_ms = started.elapsed().as_millis() as u64;
    let mut addrs: Vec<SocketAddr> = Vec::new();
    if let Ok(found) = resolved {
        for a in found {
            if !addrs.contains(&a) {
                addrs.push(a);
            }
        }
    }
    let name_resolution: Vec<String> = addrs.iter().map(|a| a.ip().to_string()).collect();
    if addrs.is_empty() {
        return Ok(ConnectionTest {
            hint: Some(hint_for("name-resolution", &host, port, timeout)),
            computer_name: host,
            remote_port: port,
            name_resolution,
            resolve_ms,
            remote_address: None,
            source_address: None,
            interface_alias: None,
            tcp_test_succeeded: false,
            tcp_ms: None,
            attempts: vec![],
            failure: Some("name-resolution".into()),
            tested_at,
        });
    }

    let mut attempts = Vec::new();
    let mut kinds: Vec<&'static str> = Vec::new();
    for addr in addrs.iter().take(MAX_ATTEMPTS) {
        let t = Instant::now();
        match TcpStream::connect_timeout(addr, timeout) {
            Ok(sock) => {
                let elapsed_ms = t.elapsed().as_millis() as u64;
                attempts.push(ConnectAttempt { address: addr.ip().to_string(), succeeded: true, error: None, elapsed_ms });
                let source = sock.local_addr().ok().map(|a| a.ip());
                let _ = sock.shutdown(std::net::Shutdown::Both);
                return Ok(ConnectionTest {
                    computer_name: host,
                    remote_port: port,
                    name_resolution,
                    resolve_ms,
                    remote_address: Some(addr.ip().to_string()),
                    source_address: source.map(|ip| ip.to_string()),
                    interface_alias: source.and_then(interface_of),
                    tcp_test_succeeded: true,
                    tcp_ms: Some(elapsed_ms),
                    attempts,
                    failure: None,
                    hint: None,
                    tested_at,
                });
            }
            Err(err) => {
                kinds.push(classify(&err));
                attempts.push(ConnectAttempt { address: addr.ip().to_string(), succeeded: false, error: Some(err.to_string()), elapsed_ms: t.elapsed().as_millis() as u64 });
            }
        }
    }
    // A refusal from any address says more than a timeout from another: the host is up.
    let failure = if kinds.contains(&"refused") { "refused" } else { kinds.first().copied().unwrap_or("error") };
    Ok(ConnectionTest {
        hint: Some(hint_for(failure, &host, port, timeout)),
        computer_name: host,
        remote_port: port,
        name_resolution,
        resolve_ms,
        remote_address: Some(addrs[0].ip().to_string()),
        source_address: None,
        interface_alias: None,
        tcp_test_succeeded: false,
        tcp_ms: None,
        attempts,
        failure: Some(failure.into()),
        tested_at,
    })
}

/// The name of the interface that holds `ip`, from the system's interface list.
#[cfg(unix)]
fn interface_of(ip: IpAddr) -> Option<String> {
    use std::ffi::CStr;
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list we only read and then free with freeifaddrs.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }
    let mut found = None;
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list getifaddrs returned, valid until freeifaddrs.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: ifa_addr is non-null and points at a sockaddr whose family says how to read it.
        let family = i32::from(unsafe { (*ifa.ifa_addr).sa_family });
        let addr = match family {
            libc::AF_INET => {
                // SAFETY: the family is AF_INET, so the sockaddr is a sockaddr_in.
                let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                IpAddr::from(u32::from_be(sin.sin_addr.s_addr).to_be_bytes())
            }
            libc::AF_INET6 => {
                // SAFETY: the family is AF_INET6, so the sockaddr is a sockaddr_in6.
                let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                IpAddr::from(sin6.sin6_addr.s6_addr)
            }
            _ => continue,
        };
        if addr == ip && !ifa.ifa_name.is_null() {
            // SAFETY: ifa_name is a NUL-terminated C string owned by the list.
            found = Some(unsafe { CStr::from_ptr(ifa.ifa_name) }.to_string_lossy().into_owned());
            break;
        }
    }
    // SAFETY: `head` came from getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(head) };
    found
}

#[cfg(not(unix))]
fn interface_of(_ip: IpAddr) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn an_open_port_succeeds_with_its_address_source_and_interface() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let r = test("127.0.0.1", port, 5).unwrap();
        assert!(r.tcp_test_succeeded, "{r:?}");
        assert_eq!(r.computer_name, "127.0.0.1");
        assert_eq!(r.remote_port, port);
        assert_eq!(r.remote_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(r.source_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(r.name_resolution, vec!["127.0.0.1".to_string()]);
        assert!(r.tcp_ms.is_some() && r.failure.is_none() && r.hint.is_none());
        #[cfg(unix)]
        assert!(r.interface_alias.as_deref().is_some_and(|n| n.starts_with("lo")), "loopback interface: {:?}", r.interface_alias);
    }

    #[test]
    fn a_port_in_the_address_wins_over_the_port_argument() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let r = test(&format!("https://127.0.0.1:{port}/health"), 1, 5).unwrap();
        assert!(r.tcp_test_succeeded);
        assert_eq!(r.remote_port, port);
    }

    #[test]
    fn a_closed_port_is_refused_and_says_the_host_answered() {
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let r = test("127.0.0.1", port, 5).unwrap();
        assert!(!r.tcp_test_succeeded);
        assert_eq!(r.failure.as_deref(), Some("refused"));
        assert!(r.hint.as_deref().unwrap().contains("nothing accepts connections"));
        assert_eq!(r.remote_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(r.attempts.len(), 1);
        assert!(r.attempts[0].error.is_some());
    }

    #[test]
    fn a_name_that_does_not_resolve_is_reported_not_raised() {
        // .invalid never resolves (RFC 6761).
        let r = test("no-such-host.invalid", 443, 5).unwrap();
        assert!(!r.tcp_test_succeeded);
        assert_eq!(r.failure.as_deref(), Some("name-resolution"));
        assert!(r.name_resolution.is_empty() && r.attempts.is_empty() && r.remote_address.is_none());
    }

    /// Needs the internet: `cargo test --lib netcheck -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn reaches_a_public_server() {
        let r = test("example.com", 443, 10).unwrap();
        println!("{r:#?}");
        assert!(r.tcp_test_succeeded, "{r:?}");
        assert!(!r.name_resolution.is_empty() && r.source_address.is_some());
    }

    #[test]
    fn a_bad_port_or_empty_host_is_an_error() {
        assert!(test("", 443, 5).is_err());
        assert!(test("example.com", 0, 5).is_err());
        assert!(test("example.com:99999", 443, 5).is_err());
    }
}
