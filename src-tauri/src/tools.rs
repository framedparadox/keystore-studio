//! Detects the external command-line tools Keystore Studio's workflows refer to (the terminal
//! hints, keytool and ssh-keygen commands, the Bouncy Castle provider keytool needs for BKS, UBER
//! and BCFKS) without ever running the user's own crypto through them: the engine itself is
//! self-contained Rust.

use serde::Serialize;
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
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
    /// The family the Tools page lists it under: `java`, `openssl` or `ssh`.
    pub group: &'static str,
    /// What in Keystore Studio refers to the tool.
    pub used_by: &'static [&'static str],
    pub available: bool,
    /// The version number alone (`21.0.2`, `3.0.13`, `9.6p1`), parsed from the tool's own output.
    /// None when the output could not be read or did not hold a version.
    pub version: Option<String>,
    /// Who built it (`OpenJDK`, `Temurin`, `LibreSSL` …), when the version output says so.
    pub vendor: Option<String>,
    /// The first line of the tool's version output, unparsed, for the details panel.
    pub version_line: Option<String>,
    /// Where it was found.
    pub path: Option<String>,
    /// How it was found: `path` (on PATH), `detected` (a well-known install location that is not
    /// on PATH), or `custom` (the location the user chose). None when it was not found.
    pub source: Option<&'static str>,
    /// The location the user chose for this tool, echoed back; set even when nothing was found there.
    pub custom_location: Option<String>,
}

/// How a tool is found.
enum Kind {
    /// A program on PATH. `version_from` names a sibling program that reports the version when the
    /// tool itself has no version flag (ssh-keygen: `ssh -V`).
    Binary { binaries: &'static [&'static str], version_args: &'static [&'static str], version_from: Option<&'static str> },
    /// The Bouncy Castle provider jar, which is a file, not a program.
    BcprovJar,
}

struct ToolSpec {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    group: &'static str,
    used_by: &'static [&'static str],
    kind: Kind,
}

const fn bin(binaries: &'static [&'static str], version_args: &'static [&'static str]) -> Kind {
    Kind::Binary { binaries, version_args, version_from: None }
}

const TOOLS: &[ToolSpec] = &[
    ToolSpec {
        id: "java",
        name: "Java Runtime",
        description: "Runs keytool, jarsigner and any JVM-based tooling you invoke from the terminal.",
        group: "java",
        used_by: &["Terminal commands for keytool and jarsigner"],
        kind: bin(&["java"], &["-version"]),
    },
    ToolSpec {
        id: "keytool",
        name: "keytool",
        description: "The JDK's own keystore tool. Ships with the Java Runtime.",
        group: "java",
        used_by: &["keytool commands shown by Convert and the terminal hints", "keytool -importkeystore migrations"],
        kind: bin(&["keytool"], &["-version"]),
    },
    ToolSpec {
        id: "jarsigner",
        name: "jarsigner",
        description: "Verifies the JAR signatures Keystore Studio writes. Ships with the JDK.",
        group: "java",
        used_by: &["Verifying signed JARs (CA & Signing → JAR)"],
        kind: bin(&["jarsigner"], &["-version"]),
    },
    ToolSpec {
        id: "bcprov",
        name: "Bouncy Castle provider",
        description: "bcprov.jar lets keytool read and write BKS, UBER and BCFKS. Keystore Studio itself does not need it.",
        group: "java",
        used_by: &["keytool commands for BKS, UBER and BCFKS (-providerpath bcprov.jar)"],
        kind: Kind::BcprovJar,
    },
    ToolSpec {
        id: "openssl",
        name: "OpenSSL",
        description: "Industry-standard crypto CLI, handy for cross-checking certificates, keys and PKCS#12 files.",
        group: "openssl",
        used_by: &["openssl commands shown by Convert, Examine and the terminal hints"],
        kind: bin(&["openssl"], &["version"]),
    },
    ToolSpec {
        id: "ssh-keygen",
        name: "ssh-keygen",
        description: "OpenSSH's key tool. Reads the OpenSSH and SSH2 keys Keystore Studio writes.",
        group: "ssh",
        used_by: &["ssh-keygen commands shown when converting OpenSSH and SSH2 keys"],
        kind: Kind::Binary { binaries: &["ssh-keygen"], version_args: &["-V"], version_from: Some("ssh") },
    },
    ToolSpec {
        id: "puttygen",
        name: "PuTTYgen",
        description: "Converts between PuTTY .ppk files and OpenSSH keys, which Keystore Studio reads and writes.",
        group: "ssh",
        used_by: &["Turning a .ppk into an OpenSSH key before opening it here"],
        kind: bin(&["puttygen"], &["--version"]),
    },
];

/// The Bouncy Castle provider jar: `BCPROV_JAR`, then the places package managers and Maven put
/// it. Returns the path and the version in its file name (`bcprov-jdk18on-1.80.jar` → `1.80`).
fn find_bcprov(custom: Option<&Path>) -> Option<(String, Option<String>)> {
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Some(custom) = custom {
        // The user's choice only: a jar, or a folder holding one.
        if custom.is_file() {
            candidates.push(custom.to_path_buf());
        } else if let Ok(read) = std::fs::read_dir(custom) {
            candidates.extend(read.flatten().map(|e| e.path()));
        }
        return pick_bcprov(candidates);
    }
    if let Some(p) = std::env::var_os("BCPROV_JAR") {
        candidates.push(p.into());
    }
    for dir in ["/usr/share/java", "/usr/local/share/java", "/opt/homebrew/share/java"] {
        if let Ok(read) = std::fs::read_dir(dir) {
            candidates.extend(read.flatten().map(|e| e.path()));
        }
    }
    if let Some(home) = dirs::home_dir() {
        let root = home.join(".m2/repository/org/bouncycastle");
        for artifact in std::fs::read_dir(root).into_iter().flatten().flatten().filter(|d| d.file_name().to_string_lossy().starts_with("bcprov")) {
            for version in std::fs::read_dir(artifact.path()).into_iter().flatten().flatten() {
                candidates.extend(std::fs::read_dir(version.path()).into_iter().flatten().flatten().map(|e| e.path()));
            }
        }
    }
    pick_bcprov(candidates)
}

fn pick_bcprov(candidates: Vec<std::path::PathBuf>) -> Option<(String, Option<String>)> {
    let mut jars: Vec<std::path::PathBuf> = candidates
        .into_iter()
        .filter(|p| p.is_file())
        .filter(|p| p.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).is_some_and(|n| n.starts_with("bcprov") && n.ends_with(".jar") && !n.contains("sources") && !n.contains("javadoc")))
        .collect();
    // The newest version sorts last.
    jars.sort();
    let jar = jars.pop()?;
    let name = jar.file_stem()?.to_string_lossy().into_owned();
    let version = name.rsplit('-').next().filter(|v| v.chars().next().is_some_and(|c| c.is_ascii_digit())).map(String::from);
    Some((jar.to_string_lossy().into_owned(), version))
}

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
    probe_lines(exe_path, args, path_env)?.into_iter().next()
}

/// Runs the tool like [`probe_version`] and returns every non-empty line of its version output.
fn probe_lines(exe_path: &str, args: &[&str], path_env: &str) -> Option<Vec<String>> {
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
    let lines: Vec<String> = String::from_utf8_lossy(&text).lines()
        .map(str::trim)
        // A JVM prints `Picked up JAVA_TOOL_OPTIONS: …` (or _JAVA_OPTIONS) before its version.
        .filter(|l| !l.is_empty() && !l.starts_with("Picked up "))
        .map(str::to_string)
        .collect();
    (!lines.is_empty()).then_some(lines)
}

/// Folders a tool is often installed in without being on PATH: a JDK under JAVA_HOME or the
/// platform's JVM folder, OpenSSL and OpenSSH from Git for Windows, PuTTY's own folder, Homebrew's
/// keg-only openssl. Searched after PATH, so PATH wins when both have it.
fn well_known_dirs(tool_group: &str) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    let children_bin = |root: &Path, suffix: &[&str]| -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = std::fs::read_dir(root)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| suffix.iter().fold(e.path(), |p, s| p.join(s)))
            .filter(|p| p.is_dir())
            .collect();
        // Newest version (by name) first.
        out.sort();
        out.reverse();
        out
    };
    if tool_group == "java" {
        if let Some(home) = std::env::var_os("JAVA_HOME") {
            found.push(PathBuf::from(home).join("bin"));
        }
        #[cfg(target_os = "macos")]
        {
            found.extend(children_bin(Path::new("/Library/Java/JavaVirtualMachines"), &["Contents", "Home", "bin"]));
            found.push("/opt/homebrew/opt/openjdk/bin".into());
            found.push("/usr/local/opt/openjdk/bin".into());
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            found.extend(children_bin(Path::new("/usr/lib/jvm"), &["bin"]));
            found.extend(children_bin(Path::new("/opt/java"), &["bin"]));
        }
        #[cfg(windows)]
        for root in [r"C:\Program Files\Java", r"C:\Program Files\Eclipse Adoptium", r"C:\Program Files\Microsoft", r"C:\Program Files\Zulu", r"C:\Program Files\Amazon Corretto"] {
            found.extend(children_bin(Path::new(root), &["bin"]));
        }
        if let Some(home) = dirs::home_dir() {
            found.extend(children_bin(&home.join(".sdkman/candidates/java"), &["bin"]));
            #[cfg(target_os = "macos")]
            found.extend(children_bin(&home.join("Library/Java/JavaVirtualMachines"), &["Contents", "Home", "bin"]));
        }
    }
    if tool_group == "openssl" {
        #[cfg(target_os = "macos")]
        {
            found.push("/opt/homebrew/opt/openssl/bin".into());
            found.push("/usr/local/opt/openssl/bin".into());
        }
        #[cfg(windows)]
        for d in [r"C:\Program Files\OpenSSL-Win64\bin", r"C:\Program Files\OpenSSL\bin", r"C:\Program Files\Git\usr\bin", r"C:\Program Files\Git\mingw64\bin"] {
            found.push(d.into());
        }
    }
    if tool_group == "ssh" {
        #[cfg(windows)]
        for d in [r"C:\Windows\System32\OpenSSH", r"C:\Program Files\OpenSSH", r"C:\Program Files\PuTTY", r"C:\Program Files (x86)\PuTTY", r"C:\Program Files\Git\usr\bin"] {
            found.push(d.into());
        }
    }
    found.into_iter().filter(|d| d.is_dir()).collect()
}

/// Looks for `binary` in a location the user chose: the program itself, a folder holding it, or
/// a folder whose `bin` holds it (a JDK or OpenSSL install root).
fn find_in_custom(binary: &str, custom: &Path) -> Option<String> {
    if custom.is_file() {
        let stem = custom.file_stem().map(|s| s.to_string_lossy().to_ascii_lowercase());
        return (stem.as_deref() == Some(binary)).then(|| custom.to_string_lossy().into_owned());
    }
    let joined = [custom.to_path_buf(), custom.join("bin")].iter().map(|d| d.to_string_lossy().into_owned()).collect::<Vec<_>>().join(platform_sep());
    find_on_path(binary, &joined)
}

/// Splits a tool's first version line into (version, vendor). Returns (None, None) for output that
/// holds no version number, so the page shows nothing rather than a guess.
fn parse_version(id: &str, line: &str) -> (Option<String>, Option<String>) {
    let quoted = || line.split('"').nth(1).map(str::to_string);
    let first_number = |text: &str| {
        text.split(|c: char| c.is_whitespace() || c == ',' || c == '_' || c == '"')
            .find(|w| (w.chars().next().is_some_and(|c| c.is_ascii_digit()) && w.contains('.')) || (w.len() >= 2 && w.chars().all(|c| c.is_ascii_digit())))
            .map(|w| w.trim_end_matches(['.', ':', ')']).to_string())
    };
    let lower = line.to_ascii_lowercase();
    match id {
        "java" => {
            // `openjdk version "21.0.2" 2024-01-16`, `java version "1.8.0_392"`.
            let vendor = if lower.starts_with("openjdk") { Some("OpenJDK") } else if lower.starts_with("java") { Some("Oracle Java") } else { None };
            (quoted().filter(|v| v.chars().next().is_some_and(|c| c.is_ascii_digit())), vendor.map(String::from))
        }
        "keytool" | "jarsigner" => (line.strip_prefix(id).map(str::trim).and_then(first_number), None),
        "openssl" => {
            // `OpenSSL 3.0.13 30 Jan 2024 (Library: …)`, `LibreSSL 3.3.6`.
            let vendor = line.split_whitespace().next().filter(|w| w.eq_ignore_ascii_case("openssl") || w.eq_ignore_ascii_case("libressl") || w.eq_ignore_ascii_case("boringssl"));
            (line.split_whitespace().nth(1).filter(|v| v.chars().next().is_some_and(|c| c.is_ascii_digit())).map(String::from), vendor.map(String::from))
        }
        "ssh-keygen" => {
            // `OpenSSH_9.6p1 Ubuntu-3ubuntu13, OpenSSL 3.0.13 30 Jan 2024`, `OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2`.
            let word = line.split([' ', ',']).next().unwrap_or("");
            let version = word.rsplit('_').next().filter(|v| v.chars().next().is_some_and(|c| c.is_ascii_digit())).map(String::from);
            (version, word.starts_with("OpenSSH").then(|| "OpenSSH".to_string()))
        }
        // `puttygen: Release 0.81`, `puttygen: Development snapshot 2024-…`.
        "puttygen" => (lower.contains("release").then(|| first_number(line)).flatten(), None),
        _ => (first_number(line), None),
    }
}

/// The JVM's vendor from the second line of `java -version` (`OpenJDK Runtime Environment Temurin-21…`).
fn java_vendor(exe: &str, path_env: &str) -> Option<String> {
    let lines = probe_lines(exe, &["-version"], path_env)?;
    let runtime = lines.get(1)?;
    ["Temurin", "Zulu", "Corretto", "Microsoft", "GraalVM", "Homebrew", "Red_Hat", "SapMachine", "JetBrains", "Liberica"]
        .iter()
        .find(|v| runtime.contains(*v))
        .map(|v| v.replace('_', " "))
}

/// The user's chosen location for a tool, made absolute and trimmed. Empty means "detect".
fn custom_for<'a>(overrides: &'a HashMap<String, String>, id: &str) -> Option<&'a str> {
    overrides.get(id).map(|s| s.trim()).filter(|s| !s.is_empty())
}

pub fn status(overrides: &HashMap<String, String>) -> Vec<ToolStatus> {
    let path_env = search_path();
    TOOLS
        .iter()
        .map(|spec| {
            let custom = custom_for(overrides, spec.id);
            let (found, source, version_line): (Option<String>, Option<&'static str>, Option<String>) = match &spec.kind {
                Kind::Binary { binaries, version_args, version_from } => {
                    let (found, source) = match custom {
                        Some(c) => (binaries.iter().find_map(|b| find_in_custom(b, Path::new(c))), Some("custom")),
                        None => match binaries.iter().find_map(|b| find_on_path(b, &path_env)) {
                            Some(p) => (Some(p), Some("path")),
                            None => {
                                let known = well_known_dirs(spec.group).iter().map(|d| d.to_string_lossy().into_owned()).collect::<Vec<_>>().join(platform_sep());
                                (binaries.iter().find_map(|b| find_on_path(b, &known)), Some("detected"))
                            }
                        },
                    };
                    let version_line = match (version_from, found.as_deref()) {
                        // The sibling (ssh for ssh-keygen) is looked for next to the tool first.
                        (Some(sibling), Some(exe)) => {
                            let dir = Path::new(exe).parent().map(|d| d.to_string_lossy().into_owned()).unwrap_or_default();
                            find_on_path(sibling, &dir).or_else(|| find_on_path(sibling, &path_env)).and_then(|s| probe_version(&s, version_args, &path_env))
                        }
                        (None, Some(exe)) => probe_version(exe, version_args, &path_env),
                        _ => None,
                    };
                    (found, source, version_line)
                }
                Kind::BcprovJar => match find_bcprov(custom.map(Path::new)) {
                    Some((path, version)) => (Some(path), Some(if custom.is_some() { "custom" } else { "detected" }), version),
                    None => (None, None, None),
                },
            };
            let (version, mut vendor) = match (&spec.kind, version_line.as_deref()) {
                (Kind::BcprovJar, Some(v)) => (Some(v.to_string()), Some("Bouncy Castle".to_string())),
                (_, Some(line)) => parse_version(spec.id, line),
                _ => (None, None),
            };
            if spec.id == "java"
                && let Some(exe) = found.as_deref()
                && let Some(v) = java_vendor(exe, &path_env)
            {
                vendor = Some(v);
            }
            ToolStatus {
                id: spec.id,
                name: spec.name,
                description: spec.description,
                group: spec.group,
                used_by: spec.used_by,
                available: found.is_some(),
                version,
                vendor,
                version_line: if matches!(spec.kind, Kind::BcprovJar) { None } else { version_line },
                source: found.as_ref().and(source),
                path: found,
                custom_location: custom.map(String::from),
            }
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
        let results = status(&HashMap::new());
        assert_eq!(results.len(), TOOLS.len());
        for (spec, result) in TOOLS.iter().zip(results.iter()) {
            assert_eq!(spec.id, result.id);
            assert_eq!(result.available, result.path.is_some());
            assert_eq!(result.available, result.source.is_some());
            assert!(["java", "openssl", "ssh"].contains(&result.group), "{}", result.id);
            assert!(!result.used_by.is_empty(), "{}", result.id);
        }
    }

    #[test]
    fn parses_versions_and_vendors_from_real_output() {
        assert_eq!(parse_version("java", r#"openjdk version "21.0.2" 2024-01-16"#), (Some("21.0.2".into()), Some("OpenJDK".into())));
        assert_eq!(parse_version("java", r#"java version "1.8.0_392""#), (Some("1.8.0_392".into()), Some("Oracle Java".into())));
        assert_eq!(parse_version("keytool", "keytool 21.0.2"), (Some("21.0.2".into()), None));
        assert_eq!(parse_version("keytool", "Illegal option:  -version"), (None, None));
        assert_eq!(parse_version("openssl", "OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)"), (Some("3.0.13".into()), Some("OpenSSL".into())));
        assert_eq!(parse_version("openssl", "LibreSSL 3.3.6"), (Some("3.3.6".into()), Some("LibreSSL".into())));
        assert_eq!(parse_version("ssh-keygen", "OpenSSH_9.6p1 Ubuntu-3ubuntu13, OpenSSL 3.0.13 30 Jan 2024"), (Some("9.6p1".into()), Some("OpenSSH".into())));
        assert_eq!(parse_version("ssh-keygen", "OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2"), (Some("9.5p1".into()), Some("OpenSSH".into())));
        assert_eq!(parse_version("puttygen", "puttygen: Release 0.81"), (Some("0.81".into()), None));
        assert_eq!(parse_version("puttygen", "puttygen: Development snapshot"), (None, None));
    }

    #[cfg(unix)]
    #[test]
    fn a_custom_location_is_searched_alone() {
        let dir = std::env::temp_dir().join(format!("ks-tools-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        let mut overrides = HashMap::new();
        overrides.insert("openssl".to_string(), dir.to_string_lossy().into_owned());
        let openssl = status(&overrides).into_iter().find(|t| t.id == "openssl").unwrap();
        // Nothing there: not found, even when openssl is on PATH.
        assert!(!openssl.available);
        assert_eq!(openssl.custom_location.as_deref(), Some(dir.to_string_lossy().as_ref()));
        let sh = find_on_path("sh", &search_path()).unwrap();
        std::fs::copy(&sh, dir.join("bin/sh")).unwrap();
        assert!(find_in_custom("sh", &dir).is_some_and(|p| p.ends_with("bin/sh")));
        assert!(find_in_custom("sh", &dir.join("bin/sh")).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
