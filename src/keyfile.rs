pub use crate::keygen::{load_public_key, load_secret_key};

/// Encode raw bytes as base64 (for in-memory key exchange)
pub fn encode_key(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Decode base64 string back to raw bytes
pub fn decode_key(encoded: &str) -> Result<Vec<u8>, anyhow::Error> {
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.decode(encoded.trim())?)
}
