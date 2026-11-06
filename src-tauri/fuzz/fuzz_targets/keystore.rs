//! Keystore decoding: PKCS#12, JKS and JCEKS, including their password-based decryption, MAC
//! checks, Java serialization reader and nested safe contents.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    let empty = HashMap::new();
    let _ = xkeystore_lib::keystore::decode(data, "fuzz", &empty);
    // Reach the individual codecs directly as well: `decode` dispatches on content sniffing, so
    // a file that fails to sniff would never exercise them.
    let _ = xkeystore_lib::pkcs12::decode(data, "fuzz");
    let _ = xkeystore_lib::jks::decode(data, "fuzz", &empty);
});
