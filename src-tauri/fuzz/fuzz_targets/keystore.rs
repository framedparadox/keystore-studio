//! Keystore decoding: PKCS#12, JKS, JCEKS, BKS, UBER and BCFKS, including their password-based decryption, MAC
//! checks, Java serialization reader and nested safe contents.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    let empty = HashMap::new();
    let _ = keystore_studio_lib::keystore::decode(data, "fuzz", &empty);
    // Reach the individual codecs directly as well: `decode` dispatches on content sniffing, so
    // a file that fails to sniff would never exercise them.
    let _ = keystore_studio_lib::pkcs12::decode(data, "fuzz");
    let _ = keystore_studio_lib::jks::decode(data, "fuzz", &empty);
    let _ = keystore_studio_lib::bks::decode(data, "fuzz", &empty);
    let _ = keystore_studio_lib::bks::decode_uber(data, "fuzz", &empty);
    let _ = keystore_studio_lib::bcfks::decode(data, "fuzz", &empty);
});
