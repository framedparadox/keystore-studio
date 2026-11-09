//! Keystore Studio: native keystore and X.509 workbench.
//!
//! The modules below are the engine: keystore codecs, X.509, CMS, keys and the operations built
//! on them. They depend on no GUI toolkit and can be used on their own.
//!
//! The Tauri command layer lives in `commands` behind the default `tauri-app` feature. Building
//! with `--no-default-features` gives the engine alone, which is how the fuzz targets link it.

pub mod bks;
pub mod cms;
pub mod convert;
pub mod detect;
pub mod dh;
pub mod entry;
pub mod export;
mod ffdhe;
pub mod jar;
pub mod javaser;
pub mod jks;
pub mod jwt;
pub mod keys;
pub mod keystore;
pub mod model;
pub mod netcheck;
pub mod oids;
pub mod ops;
pub mod pbe;
pub mod pkcs12;
pub mod terminal;
pub mod tls;
pub mod tsa;
pub mod util;
pub mod vault;
pub mod x509;

#[cfg(feature = "tauri-app")]
mod commands;
#[cfg(feature = "tauri-app")]
pub use commands::{DataSource, run};
