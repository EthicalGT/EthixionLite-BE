use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use serde::de::DeserializeOwned;

use serde::Serialize;

/// Encrypt any serializable data (arrays, objects, etc.)
pub fn encrypt_data<T: Serialize>(data: &T, key_b64: &str) -> Result<(String, String), String> {
    // Decode base64 key
    let key_bytes = general_purpose::STANDARD
        .decode(key_b64)
        .map_err(|_| "Invalid base64 key")?;
    if key_bytes.len() != 32 {
        return Err("Key must be 32 bytes for AES-256".to_string());
    }

    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes));

    // Serialize data to JSON bytes
    let serialized =
        serde_json::to_vec(data).map_err(|e| format!("Serialization failed: {}", e))?;

    // Generate random 12-byte nonce
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, serialized.as_ref())
        .map_err(|_| "Encryption failed".to_string())?;

    Ok((
        general_purpose::STANDARD.encode(&ciphertext),
        general_purpose::STANDARD.encode(&nonce_bytes),
    ))
}

/// Decrypt data back into original type
pub fn decrypt_data<T: serde::de::DeserializeOwned>(
    cipher_b64: &str,
    nonce_b64: &str,
    key_b64: &str,
) -> Result<T, String> {
    let key_bytes = general_purpose::STANDARD
        .decode(key_b64)
        .map_err(|_| "Invalid key")?;
    if key_bytes.len() != 32 {
        return Err("Key must be 32 bytes".into());
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));

    let nonce_bytes = general_purpose::STANDARD
        .decode(nonce_b64)
        .map_err(|_| "Invalid nonce")?;
    if nonce_bytes.len() != 12 {
        return Err("Nonce must be 12 bytes".into());
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = general_purpose::STANDARD
        .decode(cipher_b64)
        .map_err(|_| "Invalid ciphertext")?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "Decryption failed")?;
    let data = serde_json::from_slice(&plaintext).map_err(|_| "Deserialization failed")?;
    Ok(data)
}

/// Generate a random AES-256 key (base64-encoded)
pub fn generate_aes256_key() -> String {
    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    general_purpose::STANDARD.encode(&key_bytes)
}
