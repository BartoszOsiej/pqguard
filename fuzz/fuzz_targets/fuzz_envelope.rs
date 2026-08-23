#![no_main]
use libfuzzer_sys::fuzz_target;
use pqguard::crypto::SealedEnvelope;

fuzz_target!(|data: &[u8]| {
    // Fuzz the envelope parser — should never panic
    let _ = SealedEnvelope::from_bytes(data);
});
