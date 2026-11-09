//! CMS / PKCS#7 verification, including the RFC 3161 timestamp token reader. Both parse data that
//! arrives as a file.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(der) = keystore_studio_lib::cms::cms_der_from_bytes(data) {
        let _ = keystore_studio_lib::cms::verify(&der, Some(b"content"), &[]);
        let _ = keystore_studio_lib::cms::certificates_from_pkcs7(&der);
    }
    let _ = keystore_studio_lib::tsa::verify_token(data, b"signature");
});
