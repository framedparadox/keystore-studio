//! The built-in terminal: runs one shell command at a time in a tracked working directory.
//! stdin is closed (so tools that prompt — e.g. keytool without -storepass — fail fast instead of
//! hanging), output is capped, and commands are killed after a timeout.
//!
//! Each command runs in a process group of its own. On timeout the whole group is killed, not just
//! the shell: killing the shell alone left `sleep 100 | cat` or `openssl s_server` running, and
//! because they held the output pipes open, the call did not return until they exited by
//! themselves, however long that took.

use crate::util::Res;
use serde::Serialize;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MARKER: &str = "__XKS_CWD__";
const MAX_OUTPUT: usize = 512 * 1024;
/// How long to keep reading output after the shell has exited. A command left running in the
/// background (`server &`) keeps the pipes open; its later output is not waited for.
const DRAIN_GRACE: Duration = Duration::from_millis(1500);

#[derive(Serialize)]
pub struct TerminalOutput {
    pub stdout: String,
    pub stderr: String,
    pub code: i32,
    pub cwd: String,
    pub timed_out: bool,
    pub truncated: bool,
}

/// Output collected so far by a reader thread, readable while the thread still runs.
#[derive(Default)]
struct Captured {
    bytes: Vec<u8>,
    truncated: bool,
    done: bool,
}

fn read_capped<R: Read + Send + 'static>(mut r: R) -> Arc<Mutex<Captured>> {
    let shared = Arc::new(Mutex::new(Captured::default()));
    let sink = shared.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        while let Ok(n) = r.read(&mut buf) {
            if n == 0 {
                break;
            }
            let Ok(mut out) = sink.lock() else { break };
            if out.bytes.len() < MAX_OUTPUT {
                let room = MAX_OUTPUT - out.bytes.len();
                out.bytes.extend_from_slice(&buf[..n.min(room)]);
                if n > room {
                    out.truncated = true;
                }
            } else {
                out.truncated = true;
            }
        }
        if let Ok(mut out) = sink.lock() {
            out.done = true;
        }
    });
    shared
}

/// Waits until both readers reached end of file, or until `deadline`.
fn drain(readers: [&Arc<Mutex<Captured>>; 2], deadline: Instant) {
    while Instant::now() < deadline {
        if readers.iter().all(|r| r.lock().map(|c| c.done).unwrap_or(true)) {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn take(r: &Arc<Mutex<Captured>>) -> (Vec<u8>, bool) {
    r.lock().map(|mut c| (std::mem::take(&mut c.bytes), c.truncated)).unwrap_or_default()
}

/// Stops the command and everything it started.
fn kill_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        // The child leads its own process group (see `process_group(0)`), so its pid is the
        // group id. Signalling the negative id reaches every process in the group.
        if let Ok(pgid) = libc::pid_t::try_from(child.id()) {
            // SAFETY: killpg only sends a signal; it touches no memory of ours.
            unsafe {
                libc::killpg(pgid, libc::SIGKILL);
            }
        }
    }
    #[cfg(windows)]
    {
        // /T ends the whole tree the shell started, /F without asking it to close.
        let _ = Command::new("taskkill").args(["/PID", &child.id().to_string(), "/T", "/F"]).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
    let _ = child.kill();
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
        // Its own process group, so a timeout can stop everything the command started.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            c.process_group(0);
        }
        c
    };
    let mut child = cmd.current_dir(&start_dir).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|err| format!("failed to start shell: {err}"))?;
    let out = read_capped(child.stdout.take().ok_or("the shell has no output pipe")?);
    let err = read_capped(child.stderr.take().ok_or("the shell has no error pipe")?);

    let deadline = Instant::now() + Duration::from_secs(timeout_secs.clamp(1, 3600));
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() >= deadline => {
                timed_out = true;
                kill_tree(&mut child);
                break child.wait().ok();
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(e) => {
                kill_tree(&mut child);
                return Err(format!("failed waiting for command: {e}"));
            }
        }
    };
    drain([&out, &err], Instant::now() + DRAIN_GRACE);
    let (stdout_bytes, out_trunc) = take(&out);
    let (stderr_bytes, err_trunc) = take(&err);

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

    #[test]
    fn a_timeout_stops_the_whole_pipeline_and_returns_promptly() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("still-running");
        // The shell's children hold the output pipe; killing only the shell left them running
        // and kept the call waiting for them.
        let started = Instant::now();
        let r = run(&format!("sleep 4 | cat; touch '{}'", marker.display()), None, 1).unwrap();
        assert!(r.timed_out);
        assert!(started.elapsed() < Duration::from_secs(3), "returned after {:?}", started.elapsed());
        std::thread::sleep(Duration::from_secs(4));
        assert!(!marker.exists(), "the command kept running after its timeout");
    }

    #[test]
    fn a_command_left_in_the_background_does_not_hold_the_terminal() {
        let started = Instant::now();
        let r = run("sleep 20 & echo started", None, 30).unwrap();
        assert!(!r.timed_out);
        assert_eq!(r.code, 0);
        assert_eq!(r.stdout, "started");
        assert!(started.elapsed() < Duration::from_secs(5), "returned after {:?}", started.elapsed());
    }

    #[test]
    fn output_is_capped() {
        let r = run("head -c 600000 /dev/zero | tr '\\0' a", None, 20).unwrap();
        assert!(r.truncated);
        assert_eq!(r.stdout.len(), MAX_OUTPUT);
    }
}
