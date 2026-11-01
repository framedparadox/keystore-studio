//! Deployment presets: for a given target platform, describe which output
//! format to use and show the *equivalent* OpenSSL/keytool invocation as
//! reference text. This is deliberately a string template, never a
//! subprocess call — the whole point of this app is that you don't need
//! OpenSSL or a JVM installed to get the file you need, but showing the
//! command a reader might already know builds trust that the output is
//! the standard thing, not some bespoke format.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeploymentTarget {
    Nginx,
    ApacheHttpd,
    JavaGeneric,
    MuleSoft,
    NodeExpress,
    WindowsIis,
    MacosKeychain,
}

impl DeploymentTarget {
    pub fn all() -> &'static [DeploymentTarget] {
        &[
            DeploymentTarget::Nginx,
            DeploymentTarget::ApacheHttpd,
            DeploymentTarget::JavaGeneric,
            DeploymentTarget::MuleSoft,
            DeploymentTarget::NodeExpress,
            DeploymentTarget::WindowsIis,
            DeploymentTarget::MacosKeychain,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            DeploymentTarget::Nginx => "nginx",
            DeploymentTarget::ApacheHttpd => "Apache httpd",
            DeploymentTarget::JavaGeneric => "Java (generic)",
            DeploymentTarget::MuleSoft => "MuleSoft",
            DeploymentTarget::NodeExpress => "Node.js / Express",
            DeploymentTarget::WindowsIis => "Windows / IIS",
            DeploymentTarget::MacosKeychain => "macOS Keychain",
        }
    }

    pub fn recommended_format(&self) -> &'static str {
        match self {
            DeploymentTarget::Nginx | DeploymentTarget::ApacheHttpd | DeploymentTarget::NodeExpress => {
                "PEM (separate key/cert/chain files)"
            }
            DeploymentTarget::JavaGeneric | DeploymentTarget::MuleSoft => "PKCS#12 (or JKS for legacy apps)",
            DeploymentTarget::WindowsIis | DeploymentTarget::MacosKeychain => "PKCS#12 (.pfx)",
        }
    }
}

pub struct Preset {
    pub target: DeploymentTarget,
    pub summary: String,
    pub files: Vec<String>,
    /// Reference-only equivalent command line; xkeystore never runs this.
    pub equivalent_command: String,
}

/// Build the preview for `target`, given the alias/filenames the export
/// wizard is about to write. `out_prefix` is the base filename chosen by
/// the user (e.g. "svc" for "svc.key"/"svc.crt"/"svc-chain.crt").
pub fn preview(target: DeploymentTarget, alias: &str, out_prefix: &str) -> Preset {
    match target {
        DeploymentTarget::Nginx => Preset {
            target,
            summary: "nginx wants the leaf certificate and the chain concatenated into one file, and the private key as a separate, unencrypted PEM file.".into(),
            files: vec![format!("{out_prefix}.key"), format!("{out_prefix}.fullchain.pem")],
            equivalent_command: format!(
                "# reference only — xkeystore writes these files directly, no OpenSSL involved\n\
                 cat {out_prefix}.crt {out_prefix}.chain.crt > {out_prefix}.fullchain.pem\n\
                 # nginx.conf:\n\
                 #   ssl_certificate     {out_prefix}.fullchain.pem;\n\
                 #   ssl_certificate_key {out_prefix}.key;"
            ),
        },
        DeploymentTarget::ApacheHttpd => Preset {
            target,
            summary: "Apache httpd (mod_ssl) takes the key, leaf cert and chain as three separate files.".into(),
            files: vec![
                format!("{out_prefix}.key"),
                format!("{out_prefix}.crt"),
                format!("{out_prefix}.chain.crt"),
            ],
            equivalent_command: format!(
                "# httpd.conf:\n\
                 #   SSLCertificateFile      {out_prefix}.crt\n\
                 #   SSLCertificateKeyFile   {out_prefix}.key\n\
                 #   SSLCertificateChainFile {out_prefix}.chain.crt"
            ),
        },
        DeploymentTarget::JavaGeneric => Preset {
            target,
            summary: "Most Java servers (Tomcat, Spring Boot, generic JSSE) load a PKCS#12 keystore directly — no JKS conversion needed since Java 9.".into(),
            files: vec![format!("{out_prefix}.p12")],
            equivalent_command: format!(
                "# equivalent of what this app just did, for reference:\n\
                 keytool -importkeystore -srckeystore {out_prefix}.p12 -srcstoretype PKCS12 \\\n\
                 \t-destkeystore {out_prefix}.jks -deststoretype JKS -alias {alias}"
            ),
        },
        DeploymentTarget::MuleSoft => Preset {
            target,
            summary: "MuleSoft's TLS context (both Mule 3 and 4) reads a PKCS#12 or JKS keystore from the classpath or an absolute path.".into(),
            files: vec![format!("{out_prefix}.p12")],
            equivalent_command: format!(
                "<tls:context>\n\
                 \t<tls:key-store path=\"{out_prefix}.p12\" type=\"pkcs12\"\n\
                 \t\t alias=\"{alias}\" keyPassword=\"...\" password=\"...\"/>\n\
                 </tls:context>"
            ),
        },
        DeploymentTarget::NodeExpress => Preset {
            target,
            summary: "Node's https/tls modules take PEM key/cert/ca directly — no keystore container needed at all.".into(),
            files: vec![format!("{out_prefix}.key"), format!("{out_prefix}.crt"), format!("{out_prefix}.chain.crt")],
            equivalent_command: format!(
                "const https = require('node:https');\n\
                 https.createServer({{\n\
                 \tkey:  fs.readFileSync('{out_prefix}.key'),\n\
                 \tcert: fs.readFileSync('{out_prefix}.crt'),\n\
                 \tca:   fs.readFileSync('{out_prefix}.chain.crt'),\n\
                 }}, app).listen(443);"
            ),
        },
        DeploymentTarget::WindowsIis => Preset {
            target,
            summary: "IIS imports a PFX (PKCS#12) directly through the Server Certificates MMC snap-in or PowerShell.".into(),
            files: vec![format!("{out_prefix}.pfx")],
            equivalent_command: format!(
                "# reference only — equivalent PowerShell:\n\
                 Import-PfxCertificate -FilePath {out_prefix}.pfx \\\n\
                 \t-CertStoreLocation Cert:\\LocalMachine\\My -Password (Read-Host -AsSecureString)"
            ),
        },
        DeploymentTarget::MacosKeychain => Preset {
            target,
            summary: "macOS Keychain Access (and `security` on the command line) imports a PFX directly.".into(),
            files: vec![format!("{out_prefix}.pfx")],
            equivalent_command: format!(
                "# reference only — equivalent `security` invocation:\n\
                 security import {out_prefix}.pfx -k ~/Library/Keychains/login.keychain-db -P <password>"
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_target_has_a_non_empty_preview() {
        for &target in DeploymentTarget::all() {
            let p = preview(target, "myalias", "svc");
            assert!(!p.summary.is_empty());
            assert!(!p.files.is_empty());
            assert!(!p.equivalent_command.is_empty());
        }
    }
}
