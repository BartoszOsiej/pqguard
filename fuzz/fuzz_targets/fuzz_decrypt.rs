#![no_main]
use libfuzzer_sys::fuzz_target;
use pqguard::crypto;

fuzz_target!(|data: &[u8]| {
    // Try to decrypt arbitrary data — should never panic
    // Use a dummy key/nonce to exercise the decryption path
    if data.len() >= 44 {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let _ = crypto::symmetric_decrypt(&key, &nonce, data);
    }
});
