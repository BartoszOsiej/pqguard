#![no_main]
use libfuzzer_sys::fuzz_target;
use pqguard::crypto;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 32 {
        let shared_secret = &data[..32];
        let salt = &data[32..64.min(data.len())];
        let _ = crypto::derive_key(shared_secret, salt);
    }
});
