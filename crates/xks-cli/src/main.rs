mod io_helpers;

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use xks_core::cert::{self, CertSpec, CertTemplate as CoreTemplate, Subject};
use xks_core::keys::{KeyAlg as CoreKeyAlg, KeyMaterial};
use xks_core::{ca, chain, classify, jks, password, pem as pem_mod, pkcs12, presets};

use io_helpers::*;

#[derive(Parser)]
#[command(
    name = "xks",
    version,
    about = "Certificate, key and keystore tool — no Java, no OpenSSL required",
    long_about = "xks generates keys and certificates, runs a small CA, and converts between \
PEM, PKCS#12 (.pfx/.p12), JKS and DER — all in pure Rust. It never shells out to `openssl` or \
`keytool`, though its PKCS#12/JKS output is designed to be read by both."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum KeyAlgArg {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcP256,
    EcP384,
    Ed25519,
}

impl From<KeyAlgArg> for CoreKeyAlg {
    fn from(v: KeyAlgArg) -> Self {
        match v {
            KeyAlgArg::Rsa2048 => CoreKeyAlg::Rsa2048,
            KeyAlgArg::Rsa3072 => CoreKeyAlg::Rsa3072,
            KeyAlgArg::Rsa4096 => CoreKeyAlg::Rsa4096,
            KeyAlgArg::EcP256 => CoreKeyAlg::EcP256,
            KeyAlgArg::EcP384 => CoreKeyAlg::EcP384,
            KeyAlgArg::Ed25519 => CoreKeyAlg::Ed25519,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum TemplateArg {
    Server,
    Client,
    CodeSigning,
    Email,
    RootCa,
    IssuingCa,
}

impl From<TemplateArg> for CoreTemplate {
    fn from(v: TemplateArg) -> Self {
        match v {
            TemplateArg::Server => CoreTemplate::ServerAuth,
            TemplateArg::Client => CoreTemplate::ClientAuth,
            TemplateArg::CodeSigning => CoreTemplate::CodeSigning,
            TemplateArg::Email => CoreTemplate::EmailProtection,
            TemplateArg::RootCa => CoreTemplate::RootCa,
            TemplateArg::IssuingCa => CoreTemplate::IntermediateCa,
        }
    }
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
enum ConvertFormat {
    Pkcs12,
    Jks,
    Pem,
    Der,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new private key (PKCS#8 PEM, unencrypted).
    Keygen {
        #[arg(long, value_enum)]
        alg: KeyAlgArg,
        #[arg(short, long)]
        out: PathBuf,
    },

    /// Issue a self-signed certificate for an existing key.
    Selfsign {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        cn: String,
        #[arg(long)]
        org: Option<String>,
        /// Comma-separated DNS names / IP addresses.
        #[arg(long)]
        san: Option<String>,
        #[arg(long, default_value_t = 365)]
        days: i64,
        #[arg(long, value_enum, default_value = "server")]
        template: TemplateArg,
        /// CA path length constraint (root-ca/issuing-ca templates only).
        #[arg(long)]
        path_len: Option<u8>,
        #[arg(short, long)]
        out: PathBuf,
    },

    /// Create a PKCS#10 certificate signing request.
    Csr {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        cn: String,
        #[arg(long)]
        org: Option<String>,
        #[arg(long)]
        san: Option<String>,
        #[arg(short, long)]
        out: PathBuf,
    },

    /// Certificate-authority operations: issue from a CSR, issue without
    /// one (e.g. an issuing CA under a root), or publish a CRL.
    #[command(subcommand)]
    Ca(CaCommand),

    /// Convert between PEM, PKCS#12 (.pfx/.p12), JKS and DER.
    Convert {
        #[arg(long, value_enum)]
        from: ConvertFormat,
        #[arg(long, value_enum)]
        to: ConvertFormat,
        /// Input file (for from=pem this is the cert; pair it with --key).
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long)]
        cert: Option<PathBuf>,
        #[arg(long)]
        chain: Option<String>,
        #[arg(long)]
        alias: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        password_file: Option<PathBuf>,
        /// Use legacy 3DES/SHA-1 encryption for PKCS#12 output, for very
        /// old Java/hardware that rejects the modern AES scheme.
        #[arg(long)]
        legacy: bool,
        /// Write separate key/cert/chain files instead of one bundle
        /// (to=pem only).
        #[arg(long)]
        separate: bool,
        #[arg(short, long)]
        out: PathBuf,
    },

    /// Build a certificate-only truststore (no private keys).
    Truststore {
        /// Comma-separated list of alias=path pairs, e.g. root=ca.pem.
        #[arg(long)]
        certs: String,
        #[arg(long, value_enum)]
        format: ConvertFormat,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        password_file: Option<PathBuf>,
        #[arg(short, long)]
        out: PathBuf,
    },

    /// Show what a file contains and why it would (or wouldn't) pass
    /// validation — the inspector behind "Identity detail".
    Inspect {
        file: PathBuf,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        password_file: Option<PathBuf>,
    },

    /// Run the same chain diagnostics `inspect` uses, standalone.
    Validate {
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        chain: Option<String>,
        #[arg(long)]
        key: Option<PathBuf>,
    },

    /// Generate a strong random password and print its strength.
    Genpassword {
        #[arg(long, default_value_t = 24)]
        length: usize,
    },

    /// Show the recommended output format and an equivalent reference
    /// command for a deployment target (nginx, Java, Node, IIS, ...).
    Preset {
        #[arg(long)]
        alias: String,
        #[arg(long, default_value = "out")]
        out_prefix: String,
    },
}

#[derive(Subcommand)]
enum CaCommand {
    /// Sign a CSR, applying the given template's policy (the CA decides
    /// key usage / EKU / CA bits — never the requester).
    Issue {
        #[arg(long)]
        csr: PathBuf,
        #[arg(long)]
        ca_cert: PathBuf,
        #[arg(long)]
        ca_key: PathBuf,
        #[arg(long, value_enum, default_value = "server")]
        template: TemplateArg,
        #[arg(long, default_value_t = 365)]
        days: i64,
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Issue a certificate for an existing key without a CSR (e.g. an
    /// issuing CA under a root CA).
    Sign {
        #[arg(long)]
        subject_key: PathBuf,
        #[arg(long)]
        cn: String,
        #[arg(long)]
        san: Option<String>,
        #[arg(long)]
        ca_cert: PathBuf,
        #[arg(long)]
        ca_key: PathBuf,
        #[arg(long, value_enum, default_value = "issuing-ca")]
        template: TemplateArg,
        #[arg(long, default_value_t = 1825)]
        days: i64,
        #[arg(long)]
        path_len: Option<u8>,
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Publish a CRL listing revoked certificate serials.
    Crl {
        #[arg(long)]
        ca_cert: PathBuf,
        #[arg(long)]
        ca_key: PathBuf,
        #[arg(long)]
        crl_number: u64,
        #[arg(long, default_value_t = 7)]
        days: i64,
        /// Comma-separated hex serial numbers to revoke, e.g.
        /// "01A2B3,0C0D".
        #[arg(long)]
        revoke: Option<String>,
        #[arg(short, long)]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen { alg, out } => cmd_keygen(alg, &out),
        Command::Selfsign { key, cn, org, san, days, template, path_len, out } => {
            cmd_selfsign(&key, cn, org, san, days, template, path_len, &out)
        }
        Command::Csr { key, cn, org, san, out } => cmd_csr(&key, cn, org, san, &out),
        Command::Ca(sub) => cmd_ca(sub),
        Command::Convert {
            from, to, input, key, cert, chain, alias, password, password_file, legacy, separate, out,
        } => cmd_convert(
            from, to, input, key, cert, chain, alias, password, password_file, legacy, separate, &out,
        ),
        Command::Truststore { certs, format, password, password_file, out } => {
            cmd_truststore(certs, format, password, password_file, &out)
        }
        Command::Inspect { file, password, password_file } => {
            cmd_inspect(&file, password, password_file)
        }
        Command::Validate { cert, chain, key } => cmd_validate(&cert, chain, key),
        Command::Genpassword { length } => cmd_genpassword(length),
        Command::Preset { alias, out_prefix } => cmd_preset(alias, out_prefix),
    }
}

fn parse_sans(san: Option<String>) -> Vec<String> {
    san.map(|s| s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect())
        .unwrap_or_default()
}

fn cmd_keygen(alg: KeyAlgArg, out: &std::path::Path) -> Result<()> {
    let key = KeyMaterial::generate(alg.into()).context("generating key")?;
    write_out(out, key.to_pkcs8_pem().as_bytes())
}

#[allow(clippy::too_many_arguments)]
fn cmd_selfsign(
    key_path: &std::path::Path,
    cn: String,
    org: Option<String>,
    san: Option<String>,
    days: i64,
    template: TemplateArg,
    path_len: Option<u8>,
    out: &std::path::Path,
) -> Result<()> {
    let key = read_key(key_path)?;
    let mut subject = Subject::new(cn);
    subject.organization = org;
    let spec = CertSpec {
        subject,
        sans: parse_sans(san),
        validity_days: days,
        template: template.into(),
        path_len_constraint: path_len,
    };
    let issued = cert::self_signed(&spec, &key).context("issuing self-signed certificate")?;
    write_out(out, issued.pem().as_bytes())
}

fn cmd_csr(
    key_path: &std::path::Path,
    cn: String,
    org: Option<String>,
    san: Option<String>,
    out: &std::path::Path,
) -> Result<()> {
    let key = read_key(key_path)?;
    let mut dn = xks_core::cert::Subject::new(cn);
    dn.organization = org;
    let mut params = rcgen::CertificateParams::new(parse_sans(san))
        .context("building CSR parameters")?;
    params.distinguished_name = dn_to_rcgen(&dn);
    let kp = key.to_rcgen_keypair()?;
    let csr = params.serialize_request(&kp).context("serializing CSR")?;
    write_out(out, csr.pem().context("encoding CSR as PEM")?.as_bytes())
}

/// Small shim: `Subject::to_distinguished_name` is private to xks-core, so
/// rebuild the same thing here from its public fields.
fn dn_to_rcgen(s: &xks_core::cert::Subject) -> rcgen::DistinguishedName {
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, s.common_name.as_str());
    if let Some(o) = &s.organization {
        dn.push(rcgen::DnType::OrganizationName, o.as_str());
    }
    dn
}

fn cmd_ca(sub: CaCommand) -> Result<()> {
    match sub {
        CaCommand::Issue { csr, ca_cert, ca_key, template, days, out } => {
            let csr_pem = std::fs::read_to_string(&csr).context("reading CSR")?;
            let ca_cert_pem = std::fs::read_to_string(&ca_cert).context("reading CA certificate")?;
            let ca_key_material = read_key(&ca_key)?;
            let issued = cert::issue_from_csr(&csr_pem, template.into(), days, &ca_cert_pem, &ca_key_material)
                .context("issuing certificate from CSR")?;
            write_out(&out, issued.pem().as_bytes())
        }
        CaCommand::Sign { subject_key, cn, san, ca_cert, ca_key, template, days, path_len, out } => {
            let subject_key_material = read_key(&subject_key)?;
            let ca_cert_pem = std::fs::read_to_string(&ca_cert).context("reading CA certificate")?;
            let ca_key_material = read_key(&ca_key)?;
            let spec = CertSpec {
                subject: Subject::new(cn),
                sans: parse_sans(san),
                validity_days: days,
                template: template.into(),
                path_len_constraint: path_len,
            };
            let issued = cert::issue_leaf(&spec, &subject_key_material, &ca_cert_pem, &ca_key_material)
                .context("issuing certificate")?;
            write_out(&out, issued.pem().as_bytes())
        }
        CaCommand::Crl { ca_cert, ca_key, crl_number, days, revoke, out } => {
            let ca_cert_pem = std::fs::read_to_string(&ca_cert).context("reading CA certificate")?;
            let ca_key_material = read_key(&ca_key)?;
            let mut entries = Vec::new();
            if let Some(list) = revoke {
                for hex_serial in list.split(',') {
                    let hex_serial = hex_serial.trim();
                    if hex_serial.is_empty() {
                        continue;
                    }
                    let serial = decode_hex(hex_serial)
                        .with_context(|| format!("parsing serial '{hex_serial}'"))?;
                    entries.push(ca::RevokedEntry {
                        serial,
                        reason: None,
                        revoked_at_unix: time::OffsetDateTime::now_utc().unix_timestamp(),
                    });
                }
            }
            let crl_der = ca::build_crl(&ca_cert_pem, &ca_key_material, crl_number, days, &entries)
                .context("building CRL")?;
            write_out(&out, &pem::encode(&pem::Pem::new("X509 CRL", crl_der)).into_bytes())
        }
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        bail!("hex string must have an even number of digits");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(Into::into))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn cmd_convert(
    from: ConvertFormat,
    to: ConvertFormat,
    input: Option<PathBuf>,
    key: Option<PathBuf>,
    cert: Option<PathBuf>,
    chain_arg: Option<String>,
    alias: Option<String>,
    password: Option<String>,
    password_file: Option<PathBuf>,
    legacy: bool,
    separate: bool,
    out: &std::path::Path,
) -> Result<()> {
    let alias = alias.unwrap_or_else(|| "xkeystore".to_string());

    // Gather (key, leaf_der, chain_der) regardless of source format.
    let (key_material, leaf_der, chain_der): (Option<KeyMaterial>, Vec<u8>, Vec<Vec<u8>>) = match from {
        ConvertFormat::Pem => {
            let key_material = key.as_deref().map(read_key).transpose()?;
            let cert_path = cert.as_deref().context("--cert is required when --from pem")?;
            let leaf = read_one_cert(cert_path)?;
            let chain = read_chain(chain_arg.as_deref())?;
            (key_material, leaf, chain)
        }
        ConvertFormat::Pkcs12 => {
            let input = input.context("--input is required when --from pkcs12")?;
            let data = std::fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
            let pw = resolve_password(password.as_deref(), password_file.as_deref(), "PKCS#12 password")?;
            let bundle = pkcs12::import_pfx(&data, &pw).context("reading PKCS#12 file")?;
            let entry = bundle.entries.into_iter().next().context("PKCS#12 file has no entries")?;
            let mut certs = entry.certs.into_iter();
            let leaf = certs.next().context("PKCS#12 entry has no certificate")?;
            (entry.key, leaf, certs.collect())
        }
        ConvertFormat::Jks => {
            let input = input.context("--input is required when --from jks")?;
            let data = std::fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
            let pw = resolve_password(password.as_deref(), password_file.as_deref(), "JKS password")?;
            let bundle = jks::import_jks(&data, &pw).context("reading JKS file")?;
            let entry = bundle.entries.into_iter().next().context("JKS file has no entries")?;
            let mut certs = entry.certs.into_iter();
            let leaf = certs.next().context("JKS entry has no certificate")?;
            (entry.key, leaf, certs.collect())
        }
        ConvertFormat::Der => {
            let input = input.context("--input is required when --from der")?;
            let leaf = std::fs::read(&input)?;
            (None, leaf, Vec::new())
        }
    };

    match to {
        ConvertFormat::Pkcs12 => {
            let key_material = key_material.context("a private key is required to build a PKCS#12 file")?;
            let pw = resolve_password(password.as_deref(), password_file.as_deref(), "new PKCS#12 password")?;
            let encryption = if legacy {
                pkcs12::PfxEncryption::LegacyCompatible
            } else {
                pkcs12::PfxEncryption::Modern
            };
            let bytes = pkcs12::export_pfx(&pw, &alias, &key_material, &leaf_der, &chain_der, encryption)
                .context("building PKCS#12 file")?;
            write_out(out, &bytes)
        }
        ConvertFormat::Jks => {
            let key_material = key_material.context("a private key is required to build a JKS file")?;
            let pw = resolve_password(password.as_deref(), password_file.as_deref(), "new JKS password")?;
            let bytes = jks::export_jks(&pw, &alias, &key_material, &leaf_der, &chain_der)
                .context("building JKS file")?;
            write_out(out, &bytes)
        }
        ConvertFormat::Pem => {
            if separate {
                let sep = pem_mod::export_separate(key_material.as_ref(), &leaf_der, &chain_der);
                let stem = out.with_extension("");
                if let Some(k) = &sep.key_pem {
                    write_out(&stem.with_extension("key"), k.as_bytes())?;
                }
                write_out(&stem.with_extension("crt"), sep.cert_pem.as_bytes())?;
                if !chain_der.is_empty() {
                    write_out(&stem.with_extension("chain.crt"), sep.chain_pem.as_bytes())?;
                }
                Ok(())
            } else {
                let bundle = pem_mod::export_bundle(key_material.as_ref(), &leaf_der, &chain_der);
                write_out(out, bundle.as_bytes())
            }
        }
        ConvertFormat::Der => write_out(out, &leaf_der),
    }
}

fn cmd_truststore(
    certs_arg: String,
    format: ConvertFormat,
    password: Option<String>,
    password_file: Option<PathBuf>,
    out: &std::path::Path,
) -> Result<()> {
    let mut certs = Vec::new();
    for pair in certs_arg.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (alias, path) = pair
            .split_once('=')
            .with_context(|| format!("expected alias=path, got '{pair}'"))?;
        certs.push((alias.to_string(), read_one_cert(std::path::Path::new(path))?));
    }
    let pw = resolve_password(password.as_deref(), password_file.as_deref(), "truststore password")?;
    let bytes = match format {
        ConvertFormat::Pkcs12 => {
            pkcs12::export_truststore_pfx(&pw, &certs, pkcs12::PfxEncryption::Modern)?
        }
        ConvertFormat::Jks => jks::export_truststore_jks(&pw, &certs)?,
        _ => bail!("truststore format must be pkcs12 or jks"),
    };
    write_out(out, &bytes)
}

fn cmd_inspect(file: &std::path::Path, password: Option<String>, password_file: Option<PathBuf>) -> Result<()> {
    let data = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let kind = classify::detect_kind(&data);
    println!("detected format: {kind:?}");

    let pw = if matches!(kind, classify::DetectedKind::Pkcs12 | classify::DetectedKind::Jks) {
        Some(resolve_password(password.as_deref(), password_file.as_deref(), "password")?)
    } else {
        None
    };

    let classified = classify::classify(&data, pw.as_deref())?;
    if classified.needs_password {
        println!("this file is password-protected; re-run with --password to inspect its contents");
        return Ok(());
    }

    for (i, cert_der) in classified.certs.iter().enumerate() {
        let info = cert::parse_cert_info(cert_der)?;
        println!("\ncertificate #{i}:");
        println!("  subject: {}", info.subject);
        println!("  issuer: {}", info.issuer);
        println!("  serial: {}", info.serial_hex);
        println!("  public key: {} ({:?} bits)", info.public_key_kind, info.public_key_bits);
        println!("  is CA: {}", info.is_ca);
        println!("  SANs: {}", info.sans.join(", "));
        println!("  SHA-256 fingerprint: {}", info.sha256_fingerprint_hex);
    }
    println!("\n{} private key(s) found", classified.keys.len());
    Ok(())
}

fn cmd_validate(cert_path: &std::path::Path, chain_arg: Option<String>, key_path: Option<PathBuf>) -> Result<()> {
    let leaf = read_one_cert(cert_path)?;
    let chain_der = read_chain(chain_arg.as_deref())?;

    if let Some(key_path) = &key_path {
        let key = read_key(key_path)?;
        let matches = chain::key_matches_cert(&key, &leaf)?;
        println!("key matches certificate: {matches}");
    }

    let findings = chain::validate_chain(&leaf, &chain_der)?;
    if findings.is_empty() {
        println!("no issues found");
    }
    for f in findings {
        println!("[{:?}] {} ({})", f.severity, f.message, f.code);
        if let Some(hint) = f.fix_hint {
            println!("    fix: {hint}");
        }
    }
    Ok(())
}

fn cmd_genpassword(length: usize) -> Result<()> {
    let pw = password::generate(length);
    let assessment = password::assess(&pw, &[]);
    println!("{pw}");
    eprintln!("strength: {}", assessment.strength.label());
    Ok(())
}

fn cmd_preset(alias: String, out_prefix: String) -> Result<()> {
    for &target in presets::DeploymentTarget::all() {
        let p = presets::preview(target, &alias, &out_prefix);
        println!("== {} ==", target.label());
        println!("{}", p.summary);
        println!("recommended format: {}", target.recommended_format());
        println!("files: {}", p.files.join(", "));
        println!("{}\n", p.equivalent_command);
    }
    Ok(())
}
