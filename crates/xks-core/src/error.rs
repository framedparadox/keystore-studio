use thiserror::Error;

/// The single error type for the whole engine. CLI and GUI both convert this
/// into their own presentation (exit code / toast), so messages here are
/// written for a human reading a dialog box, not a Rust backtrace.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    #[error("could not parse key material: {0}")]
    KeyParse(String),

    #[error("certificate generation failed: {0}")]
    CertGeneration(String),

    #[error("could not parse certificate: {0}")]
    CertParse(String),

    #[error("could not parse certificate signing request: {0}")]
    CsrParse(String),

    #[error("PKCS#12 error: {0}")]
    Pkcs12(String),

    #[error("JKS error: {0}")]
    Jks(String),

    #[error("PEM error: {0}")]
    Pem(String),

    #[error("the supplied password is incorrect, or the file is not a keystore this app recognizes")]
    WrongPassword,

    #[error("unsupported or unrecognized file format")]
    UnknownFormat,

    #[error("the private key and certificate do not form a matching pair (public keys differ)")]
    KeyCertMismatch,

    #[error("no private key is present; this operation requires one")]
    MissingPrivateKey,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, CoreError>;

impl From<rcgen::Error> for CoreError {
    fn from(e: rcgen::Error) -> Self {
        CoreError::CertGeneration(e.to_string())
    }
}
