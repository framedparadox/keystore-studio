//! The built-in terminal: runs one shell command at a time in a tracked working directory.
//! stdin is closed (so tools that prompt — e.g. keytool without -storepass — fail fast instead of
//! hanging), output is capped, and commands are killed after a timeout.

use crate::util::Res;
use serde::Serialize;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MARKER: &str = "__XKS_CWD__";
const MAX_OUTPUT: usize = 512 * 1024;

#[derive(Serialize)]
pub struct TerminalOutput {
    pub stdout: String,
    pub stderr: String,
    pub code: i32,
    pub cwd: String,
    pub timed_out: bool,
    pub truncated: bool,
}

fn read_capped<R: Read + Send + 'static>(mut r: R) -> std::thread::JoinHandle<(Vec<u8>, bool)> {
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        let mut truncated = false;
        while let Ok(n) = r.read(&mut buf) {
            if n == 0 {
                break;
            }
            if out.len() < MAX_OUTPUT {
                out.extend_from_slice(&buf[..n.min(MAX_OUTPUT - out.len())]);
            } else {
                truncated = true;
            }
        }
        (out, truncated)
    })
}

pub fn run(command: &str, cwd: Option<String>, timeout_secs: u64) -> Res<TerminalOutput> {
    let start_dir = cwd.filter(|c| std::path::Path::new(c).is_dir()).or_else(|| dirs::home_dir().map(|h| h.to_string_lossy().to_string())).unwrap_or_else(|| ".".to_string());

    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        let script = format!("{command} & set XKS_STATUS=!ERRORLEVEL! & echo {MARKER}!CD! & exit /b !XKS_STATUS!");
        c.args(["/V:ON", "/C", &script]);
        c
    } else {
        let mut c = Command::new("/bin/sh");
        let script = format!("{command}\n__xks_status=$?\nprintf '\\n{MARKER}%s\\n' \"$PWD\"\nexit $__xks_status");
        c.args(["-c", &script]);
        // GUI apps on macOS start with a minimal PATH; add the usual tool locations.
        let path = std::env::var("PATH").unwrap_or_default();
        let extra = ["/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"];
        let mut parts: Vec<String> = path.split(':').filter(|p| !p.is_empty()).map(String::from).collect();
        for x in extra {
            if !parts.iter().any(|p| p == x) {
                parts.push(x.to_string());
            }
        }
        c.env("PATH", parts.join(":"));
        c
    };
    let mut child = cmd.current_dir(&start_dir).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|err| format!("failed to start shell: {err}"))?;
    let out_handle = read_capped(child.stdout.take().unwrap());
    let err_handle = read_capped(child.stderr.take().unwrap());

    let deadline = Instant::now() + Duration::from_secs(timeout_secs.clamp(1, 3600));
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() >= deadline => {
                timed_out = true;
                let _ = child.kill();
                break child.wait().ok();
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(err) => return Err(format!("failed waiting for command: {err}")),
        }
    };
    let (stdout_bytes, out_trunc) = out_handle.join().unwrap_or_default();
    let (stderr_bytes, err_trunc) = err_handle.join().unwrap_or_default();

    let mut stdout = String::from_utf8_lossy(&stdout_bytes).to_string();
    let mut new_cwd = start_dir;
    if let Some(idx) = stdout.rfind(MARKER) {
        let found = stdout[idx + MARKER.len()..].trim().to_string();
        if !found.is_empty() {
            new_cwd = found;
        }
        stdout.truncate(idx);
        while stdout.ends_with('\n') || stdout.ends_with('\r') {
            stdout.pop();
        }
    }
    let mut stderr = String::from_utf8_lossy(&stderr_bytes).to_string();
    if timed_out {
        stderr.push_str(&format!("\n[xkeystore] command stopped after {timeout_secs}s (interactive or long-running commands are not supported)"));
    }
    Ok(TerminalOutput { stdout, stderr, code: status.and_then(|s| s.code()).unwrap_or(-1), cwd: new_cwd, timed_out, truncated: out_trunc || err_trunc })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn tracks_cwd_exit_code_and_timeout() {
        let r = run("cd /tmp && echo hi", None, 10).unwrap();
        assert_eq!(r.stdout, "hi");
        assert_eq!(r.cwd, "/tmp");
        assert_eq!(r.code, 0);
        let r = run("exit 3", Some("/tmp".into()), 10).unwrap();
        assert_eq!(r.code, 3);
        let r = run("read x; echo got:$x", None, 10).unwrap();
        assert_eq!(r.stdout, "got:");
        let r = run("sleep 5", None, 1).unwrap();
        assert!(r.timed_out);
    }
}
