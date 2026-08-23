use criterion::{criterion_group, criterion_main, Criterion};
use pqguard::crypto;

fn bench_keygen(c: &mut Criterion) {
    c.bench_function("ML-KEM-768 keygen", |b| {
        b.iter(|| {
            crypto::generate_kem_keypair().unwrap();
        });
    });
}

fn bench_encapsulate(c: &mut Criterion) {
    let (_dk, ek) = crypto::generate_kem_keypair().unwrap();
    c.bench_function("ML-KEM-768 encapsulate", |b| {
        b.iter(|| {
            crypto::kem_encapsulate(&ek).unwrap();
        });
    });
}

fn bench_decapsulate(c: &mut Criterion) {
    let (dk, ek) = crypto::generate_kem_keypair().unwrap();
    let (_ss, ct) = crypto::kem_encapsulate(&ek).unwrap();
    c.bench_function("ML-KEM-768 decapsulate", |b| {
        b.iter(|| {
            crypto::kem_decapsulate(&dk, &ct).unwrap();
        });
    });
}

fn bench_full_cycle(c: &mut Criterion) {
    c.bench_function("full encrypt cycle (1KB)", |b| {
        let (_dk, ek) = crypto::generate_kem_keypair().unwrap();
        let plaintext = vec![0xABu8; 1024];
        b.iter(|| {
            let salt = crypto::generate_salt();
            let nonce = crypto::generate_nonce();
            let (_ss, _ct) = crypto::kem_encapsulate(&ek).unwrap();
            let key = crypto::derive_key(&_ss, &salt).unwrap();
            let _enc = crypto::symmetric_encrypt(&key, &nonce, &plaintext).unwrap();
        });
    });
}

fn bench_aes_encrypt(c: &mut Criterion) {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let data = vec![0u8; 1024 * 1024]; // 1MB
    c.bench_function("AES-256-GCM encrypt 1MB", |b| {
        b.iter(|| {
            crypto::symmetric_encrypt(&key, &nonce, &data).unwrap();
        });
    });
}

fn bench_aes_decrypt(c: &mut Criterion) {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let data = vec![0u8; 1024 * 1024];
    let ct = crypto::symmetric_encrypt(&key, &nonce, &data).unwrap();
    c.bench_function("AES-256-GCM decrypt 1MB", |b| {
        b.iter(|| {
            crypto::symmetric_decrypt(&key, &nonce, &ct).unwrap();
        });
    });
}

fn bench_derive_key(c: &mut Criterion) {
    let ss = vec![0u8; 32];
    let salt = [0u8; 32];
    c.bench_function("HKDF-SHA256 derive key", |b| {
        b.iter(|| {
            crypto::derive_key(&ss, &salt).unwrap();
        });
    });
}

criterion_group!(
    benches,
    bench_keygen,
    bench_encapsulate,
    bench_decapsulate,
    bench_full_cycle,
    bench_aes_encrypt,
    bench_aes_decrypt,
    bench_derive_key,
);
criterion_main!(benches);
