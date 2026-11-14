//! Detects the external command-line tools Keystore Studio's workflows refer to (the terminal
//! hints, the keytool migration command, OpenSSL interop notes) without ever running the
//! user's own crypto through them — the engine itself is self-contained Rust.

use serde::Serialize;
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// `-version`/`version` is near-instant; this only guards against a broken install hanging the probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Serialize)]
pub struct ToolStatus {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub available: bool,
    /// First line of the tool's own version output, when it could be run.
    pub version: Option<String>,
    /// Where it was found on PATH.
    pub path: Option<String>,
}

struct ToolSpec {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    /// Binary names to look for, tried in order (e.g. a versioned fallback).
    binaries: &'static [&'static str],
    version_args: &'static [&'static str],
}

const TOOLS: &[ToolSpec] = &[
    ToolSpec { id: "java", name: "Java Runtime", description: "Runs keytool and any JVM-based tooling you invoke from the terminal.", binaries: &["java"], version_args: &["-version"] },
    ToolSpec {
        id: "keytool",
        name: "keytool",
        description: "The JDK's own keystore tool. Ships with the Java Runtime; useful for interop and migration commands.",
        binaries: &["keytool"],
        version_args: &["-version"],
    },
    ToolSpec {
        id: "openssl",
        name: "OpenSSL",
        description: "Industry-standard crypto CLI, handy for cross-checking certificates, keys and PKCS#12 files from the terminal.",
        binaries: &["openssl"],
        version_args: &["version"],
    },
];

/// The extra PATH entries the built-in terminal adds, since GUI apps on macOS and Linux start
/// with a minimal PATH that is missing Homebrew and other common tool locations.
fn search_path() -> String {
    let path = std::env::var("PATH").unwrap_or_default();
    let mut parts: Vec<String> = path.split(platform_sep()).filter(|p| !p.is_empty()).map(String::from).collect();
    for extra in extra_path_dirs() {
        if !parts.iter().any(|p| p == extra) {
            parts.push(extra.to_string());
        }
    }
    parts.join(platform_sep())
}

#[cfg(windows)]
fn platform_sep() -> &'static str {
    ";"
}
#[cfg(not(windows))]
fn platform_sep() -> &'static str {
    ":"
}

#[cfg(windows)]
fn extra_path_dirs() -> &'static [&'static str] {
    &[]
}
#[cfg(not(windows))]
fn extra_path_dirs() -> &'static [&'static str] {
    &["/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
}

/// Finds a binary on `path_env` without shelling out to `which`/`where`, so detection works the
/// same on every platform and never depends on a shell being available.
fn find_on_path(binary: &str, path_env: &str) -> Option<String> {
    #[cfg(windows)]
    let candidates: Vec<String> = {
        let ext = std::env::var("PATHEXT").unwrap_or_else(|_| ".EXE;.BAT;.CMD".into());
        if binary.contains('.') { vec![binary.to_string()] } else { ext.split(';').filter(|e| !e.is_empty()).map(|e| format!("{binary}{e}")).collect() }
    };
    #[cfg(not(windows))]
    let candidates: Vec<String> = vec![binary.to_string()];

    for dir in path_env.split(platform_sep()).filter(|p| !p.is_empty()) {
        for name in &candidates {
            let full = std::path::Path::new(dir).join(name);
            if full.is_file() {
                return Some(full.to_string_lossy().into_owned());
            }
        }
    }
    None
}

/// Reads a pipe to the end on its own thread, so draining stdout and stderr can run concurrently
/// with waiting for the process — reading them in sequence after the process exits risks a
/// deadlock if one pipe fills its buffer before the process writes to (and closes) the other.
fn read_to_end_async<R: Read + Send + 'static>(mut r: R) -> std::sync::mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = r.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    rx
}

/// Waits for `child` to exit, killing it if it outlives `PROBE_TIMEOUT` — a broken install must
/// not hang the whole status check.
fn wait_with_timeout(child: &mut Child) -> bool {
    let deadline = Instant::now() + PROBE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return false,
        }
    }
}

/// Runs `binary version_args` with a short timeout and returns the first non-empty line of
/// whichever stream the tool wrote its version to (java and openssl both vary by version).
fn probe_version(exe_path: &str, args: &[&str], path_env: &str) -> Option<String> {
    #[allow(unused_mut)]
    let mut cmd = Command::new(exe_path);
    cmd.args(args).env("PATH", path_env).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = cmd.spawn().ok()?;
    let stdout_rx = read_to_end_async(child.stdout.take()?);
    let stderr_rx = read_to_end_async(child.stderr.take()?);
    if !wait_with_timeout(&mut child) {
        return None;
    }
    let stdout = stdout_rx.recv_timeout(Duration::from_secs(1)).unwrap_or_default();
    let stderr = stderr_rx.recv_timeout(Duration::from_secs(1)).unwrap_or_default();
    let text = if !stdout.is_empty() { stdout } else { stderr };
    String::from_utf8_lossy(&text).lines().map(str::trim).find(|l| !l.is_empty()).map(str::to_string)
}

pub fn status() -> Vec<ToolStatus> {
    let path_env = search_path();
    TOOLS
        .iter()
        .map(|spec| {
            let found = spec.binaries.iter().find_map(|b| find_on_path(b, &path_env));
            let version = found.as_deref().and_then(|exe| probe_version(exe, spec.version_args, &path_env));
            ToolStatus { id: spec.id, name: spec.name, description: spec.description, available: found.is_some(), version, path: found }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn finds_a_binary_known_to_exist_on_unix() {
        let path_env = search_path();
        let found = find_on_path("sh", &path_env).expect("/bin/sh should be found on PATH");
        assert!(found.ends_with("sh"));
    }

    #[test]
    fn missing_binary_is_not_found() {
        let path_env = search_path();
        assert!(find_on_path("definitely-not-a-real-binary-xyz", &path_env).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn probe_version_reads_output_and_times_out_on_a_hanging_process() {
        let path_env = search_path();
        let echo = find_on_path("echo", &path_env).expect("echo should be on PATH");
        assert_eq!(probe_version(&echo, &["1.2.3"], &path_env), Some("1.2.3".to_string()));

        let sleep = find_on_path("sleep", &path_env).expect("sleep should be on PATH");
        let started = Instant::now();
        assert_eq!(probe_version(&sleep, &["30"], &path_env), None);
        assert!(started.elapsed() < Duration::from_secs(10), "did not time out promptly");
    }

    #[test]
    fn status_always_reports_every_known_tool() {
        let results = status();
        assert_eq!(results.len(), TOOLS.len());
        for (spec, result) in TOOLS.iter().zip(results.iter()) {
            assert_eq!(spec.id, result.id);
            assert_eq!(result.available, result.path.is_some());
        }
    }
}
