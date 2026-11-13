fn main() {
    // `tauri_build::build()` generates the app context and panics without the Tauri plumbing, so
    // skip it when the crate is built as the bare engine (`--no-default-features`), which is how
    // the fuzz targets link it. A build script cannot use `#[cfg(feature = …)]` — it is compiled
    // for the host before features apply — so read the variable Cargo sets instead.
    if std::env::var_os("CARGO_FEATURE_TAURI_APP").is_some() {
        tauri_build::build();
    }
}
