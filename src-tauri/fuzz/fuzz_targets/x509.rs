//! Certificate, CSR and CRL parsing, plus the chain builder and DN renderer.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = keystore_studio_lib::x509::parse_certificate(data);
    let _ = keystore_studio_lib::x509::parse_csr(data);
    let _ = keystore_studio_lib::x509::parse_crl(data, None);
    // name_der_to_string is infallible by signature, so a panic here is the only way it can fail.
    let _ = keystore_studio_lib::x509::name_der_to_string(data);
    if let Ok(certs) = keystore_studio_lib::x509::certificates_from_bytes(data) {
        let _ = keystore_studio_lib::x509::order_bundle(&certs);
    }
});
