use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{bail, Result};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand::RngCore;
use sha2::Sha256;

pub const KEM_ALG: &str = "ML-KEM-768";
pub const SYMMETRIC_ALG: &str = "AES-256-GCM";
pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

type DkType = <MlKem768 as KemCore>::DecapsulationKey;
type EkType = <MlKem768 as KemCore>::EncapsulationKey;
type CtType = ml_kem::Ciphertext<MlKem768>;

pub struct SealedEnvelope {
    pub kem_ciphertext: Vec<u8>,
    pub symmetric_nonce: [u8; NONCE_LEN],
    pub salt: [u8; SALT_LEN],
    pub encrypted_data: Vec<u8>,
}

impl SealedEnvelope {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(b"PQGR");
        out.push(1);
        out.extend_from_slice(&(self.kem_ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.kem_ciphertext);
        out.extend_from_slice(&self.symmetric_nonce);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&(self.encrypted_data.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.encrypted_data);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 + 1 + 4 + NONCE_LEN + SALT_LEN + 8 {
            bail!("File too small to be a valid pqguard file");
        }
        let mut pos = 0;
        if &data[0..4] != b"PQGR" {
            bail!("Not a pqguard file");
        }
        pos += 4;
        let version = data[pos];
        if version != 1 {
            bail!("Unsupported version");
        }
        pos += 1;
        let kem_len = u32::from_le_bytes(data[pos..pos + 4].try_into()?) as usize;
        pos += 4;
        if pos + kem_len > data.len() {
            bail!("Truncated KEM ciphertext");
        }
        let kem_ciphertext = data[pos..pos + kem_len].to_vec();
        pos += kem_len;
        if pos + NONCE_LEN > data.len() {
            bail!("Truncated nonce");
        }
        let mut symmetric_nonce = [0u8; NONCE_LEN];
        symmetric_nonce.copy_from_slice(&data[pos..pos + NONCE_LEN]);
        pos += NONCE_LEN;
        if pos + SALT_LEN > data.len() {
            bail!("Truncated salt");
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&data[pos..pos + SALT_LEN]);
        pos += SALT_LEN;
        if pos + 8 > data.len() {
            bail!("Truncated data length");
        }
        let data_len = u64::from_le_bytes(data[pos..pos + 8].try_into()?) as usize;
        pos += 8;
        if pos + data_len > data.len() {
            bail!("Truncated encrypted data");
        }
        let encrypted_data = data[pos..pos + data_len].to_vec();
        Ok(SealedEnvelope {
            kem_ciphertext,
            symmetric_nonce,
            salt,
            encrypted_data,
        })
    }
}

pub fn generate_kem_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let (dk, ek) = MlKem768::generate(&mut OsRng);
    // Return (encapsulation_key, decapsulation_key) — (public, private)
    Ok((ek.as_bytes().to_vec(), dk.as_bytes().to_vec()))
}

pub fn kem_encapsulate(encapsulation_key_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let encoded_ek: Encoded<EkType> = encapsulation_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid encapsulation key length"))?;
    let ek = EkType::from_bytes(&encoded_ek);
    let (ct, ss) = ek
        .encapsulate(&mut OsRng)
        .map_err(|_| anyhow::anyhow!("Encapsulation failed"))?;
    Ok((ss.to_vec(), ct.to_vec()))
}

pub fn kem_decapsulate(decapsulation_key_bytes: &[u8], ciphertext_bytes: &[u8]) -> Result<Vec<u8>> {
    let encoded_dk: Encoded<DkType> = decapsulation_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid decapsulation key length"))?;
    let dk = DkType::from_bytes(&encoded_dk);
    // CtType is Array<u8, Size> — use try_from directly
    let ct: CtType = ciphertext_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid ciphertext length"))?;
    let ss = dk
        .decapsulate(&ct)
        .map_err(|_| anyhow::anyhow!("Decapsulation failed"))?;
    Ok(ss.to_vec())
}

pub fn derive_key(shared_secret: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut key = [0u8; KEY_LEN];
    hk.expand(b"pqguard-aes256gcm", &mut key)
        .map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;
    Ok(key)
}

pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn symmetric_encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    data: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("{}", e))?;
    cipher
        .encrypt(Nonce::from_slice(nonce), data)
        .map_err(|e| anyhow::anyhow!("{}", e))
}

pub fn symmetric_decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("{}", e))?;
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
}
