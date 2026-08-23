use anyhow::{bail, Result};
use colored::*;
use std::fs;
use std::path::PathBuf;

use crate::crypto;
use crate::keyfile;

pub fn encrypt_file(
    input_path: &str,
    recipient_pubkey_path: &str,
    output_path: Option<&str>,
    _sender_key_path: Option<&str>,
) -> Result<PathBuf> {
    let plaintext = fs::read(input_path)?;
    if plaintext.is_empty() {
        bail!("Input file is empty");
    }

    let recipient_pk = keyfile::load_public_key(recipient_pubkey_path)?;
    let salt = crypto::generate_salt();
    let nonce = crypto::generate_nonce();

    let (shared_secret, kem_ciphertext) = crypto::kem_encapsulate(&recipient_pk)?;
    let symmetric_key = crypto::derive_key(&shared_secret, &salt)?;
    let encrypted_data = crypto::symmetric_encrypt(&symmetric_key, &nonce, &plaintext)?;

    let data_len = encrypted_data.len();
    let envelope = crypto::SealedEnvelope {
        kem_ciphertext,
        symmetric_nonce: nonce,
        salt,
        encrypted_data,
    };

    let envelope_bytes = envelope.to_bytes();
    let out_path = match output_path {
        Some(p) => PathBuf::from(p),
        None => {
            let mut p = PathBuf::from(input_path);
            p.set_extension("pqg");
            p
        }
    };

    fs::write(&out_path, &envelope_bytes)?;

    let ratio = (data_len as f64 / plaintext.len() as f64) * 100.0;
    println!(
        "   {} {} bytes → {} bytes ({:.1}%)",
        "Size:".dimmed(),
        plaintext.len(),
        data_len,
        ratio
    );
    println!("   {} {}", "KEM:".dimmed(), crypto::KEM_ALG);
    println!("   {} {}", "Cipher:".dimmed(), crypto::SYMMETRIC_ALG);

    Ok(out_path)
}

pub fn verify_file(input_path: &str) -> Result<()> {
    let data = fs::read(input_path)?;
    match crypto::SealedEnvelope::from_bytes(&data) {
        Ok(envelope) => {
            println!("{}", "✅ Valid pqguard file".green().bold());
            println!(
                "   {} {} bytes",
                "KEM ciphertext:".dimmed(),
                envelope.kem_ciphertext.len()
            );
            println!(
                "   {} {} bytes",
                "Encrypted data:".dimmed(),
                envelope.encrypted_data.len()
            );
            Ok(())
        }
        Err(e) => {
            println!("{}", format!("❌ Invalid: {}", e).red().bold());
            bail!("Verification failed");
        }
    }
}
