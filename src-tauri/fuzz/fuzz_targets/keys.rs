//! Key loading: PKCS#8, encrypted PKCS#8, PKCS#1 and SEC1, in DER or PEM, plus public key
//! parsing. Reached whenever a user imports a key file.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = xkeystore_lib::keys::PrivateKey::from_bytes(data, Some("fuzz"));
    let _ = xkeystore_lib::keys::PrivateKey::from_pkcs8_der(data);
    let _ = xkeystore_lib::keys::public_key_info(data);
    let _ = xkeystore_lib::pbe::decrypt_pkcs8("fuzz", data);
});
