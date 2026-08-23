use anyhow::{bail, Result};
use base64::Engine;
use colored::*;
use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto;

/// Key file format:
/// Line 1: "PQGUARD-PUBLIC-KEY" or "PQGUARD-PRIVATE-KEY"
/// Line 2: algorithm identifier
/// Line 3: base64-encoded key data
/// Line 4: optional metadata (name, created_at)
struct KeyHeader {
    key_type: String,
    algorithm: String,
    key_data: Vec<u8>,
    name: String,
}

fn parse_key_file(path: &str) -> Result<KeyHeader> {
    let content = fs::read_to_string(path)?;
    let lines: Vec<&str> = content.lines().collect();

    if lines.len() < 3 {
        bail!("Invalid key file format");
    }

    let key_type = lines[0].trim().to_string();
    if !key_type.starts_with("PQGUARD-") {
        bail!("Not a pqguard key file");
    }

    let algorithm = lines[1].trim().to_string();
    let key_data = base64::engine::general_purpose::STANDARD.decode(lines[2].trim())?;

    let name = if lines.len() > 3 {
        lines[3].trim().to_string()
    } else {
        "unknown".to_string()
    };

    Ok(KeyHeader {
        key_type,
        algorithm,
        key_data,
        name,
    })
}

/// Generate a new keypair and save to files
pub fn generate_keypair(output_dir: &str, name: &str) -> Result<(PathBuf, PathBuf)> {
    let (pk, sk) = crypto::generate_kem_keypair()?;

    let output_path = Path::new(output_dir);

    let pk_filename = format!("{}.pqg.pub", name);
    let sk_filename = format!("{}.pqg.key", name);

    let pk_path = output_path.join(&pk_filename);
    let sk_path = output_path.join(&sk_filename);

    // Write public key
    let pk_b64 = base64::engine::general_purpose::STANDARD.encode(&pk);
    let pk_content = format!(
        "PQGUARD-PUBLIC-KEY\n{}\n{}\n{}",
        crypto::KEM_ALG,
        pk_b64,
        name
    );
    fs::write(&pk_path, pk_content)?;

    // Write secret key
    let sk_b64 = base64::engine::general_purpose::STANDARD.encode(&sk);
    let sk_content = format!(
        "PQGUARD-PRIVATE-KEY\n{}\n{}\n{}",
        crypto::KEM_ALG,
        sk_b64,
        name
    );
    fs::write(&sk_path, sk_content)?;

    // Make private key readable only by owner
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&sk_path, fs::Permissions::from_mode(0o600))?;
    }

    Ok((pk_path, sk_path))
}

/// Show information about a key file
pub fn show_key_info(path: &str) -> Result<()> {
    let header = parse_key_file(path)?;

    println!("{}", "📋 Key Information".cyan().bold());
    println!("   {} {}", "Type:".dimmed(), header.key_type);
    println!("   {} {}", "Algorithm:".dimmed(), header.algorithm);
    println!("   {} {} bits", "Size:".dimmed(), header.key_data.len() * 8);
    println!("   {} {}", "Name:".dimmed(), header.name);
    println!("   {} {}", "File:".dimmed(), path);

    if header.key_type.contains("PRIVATE") {
        println!();
        println!("{}", "⚠️  This is a PRIVATE KEY — keep it secret!".yellow());
    }

    Ok(())
}

/// Load a public key from file
pub fn load_public_key(path: &str) -> Result<Vec<u8>> {
    let header = parse_key_file(path)?;
    if !header.key_type.contains("PUBLIC") {
        bail!("Expected public key, got {}", header.key_type);
    }
    Ok(header.key_data)
}

/// Load a secret key from file
pub fn load_secret_key(path: &str) -> Result<Vec<u8>> {
    let header = parse_key_file(path)?;
    if !header.key_type.contains("PRIVATE") {
        bail!("Expected private key, got {}", header.key_type);
    }
    Ok(header.key_data)
}
