//! The widest door in the app: whatever a user drops on the window or picks in a dialog reaches
//! `examine`, which sniffs the type and then parses it. Anything reachable from here is reachable
//! from a file someone was sent.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A password is supplied so the encrypted paths are reachable too; it will almost never be
    // right, which is itself the interesting case (wrong-password handling must not panic).
    let _ = keystore_studio_lib::detect::examine(data, Some("fuzz"));
    let _ = keystore_studio_lib::detect::examine(data, None);
});
