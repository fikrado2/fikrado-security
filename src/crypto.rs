use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};
use std::env;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

/// Derives a stable 32-byte machine entropy key matching the legacy Python implementation.
pub fn get_machine_key() -> [u8; 32] {
    let computer_name = env::var("COMPUTERNAME")
        .or_else(|_| env::var("HOSTNAME"))
        .unwrap_or_else(|_| "FikradoSecurityPC".to_string());
    let processor = env::var("PROCESSOR_IDENTIFIER")
        .or_else(|_| env::var("PROCESSOR_ARCHITECTURE"))
        .unwrap_or_else(|_| "FikradoSecurityMachineKey".to_string());

    let seed = format!("{}{}{}", computer_name, computer_name, processor);
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&hasher.finalize());
    key
}

/// Encrypts bytes using Windows DPAPI (CryptProtectData).
pub fn dpapi_encrypt(data: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let mut in_blob = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        let success = CryptProtectData(
            &mut in_blob,
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        );

        if success == 0 {
            return Err("CryptProtectData failed".to_string());
        }

        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let result = slice.to_vec();
        LocalFree(out_blob.pbData as _);
        Ok(result)
    }
}

/// Decrypts bytes using Windows DPAPI (CryptUnprotectData).
pub fn dpapi_decrypt(data: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let mut in_blob = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        let success = CryptUnprotectData(
            &mut in_blob,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        );

        if success == 0 {
            return Err("CryptUnprotectData failed".to_string());
        }

        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let result = slice.to_vec();
        LocalFree(out_blob.pbData as _);
        Ok(result)
    }
}

/// Encrypts a sensitive string (like an AI API key) using Windows DPAPI.
/// Returns "dpapi:<base64>" matching Python Fikrado Security.
pub fn encrypt_secret(plain: &str) -> String {
    if plain.is_empty() {
        return String::new();
    }
    match dpapi_encrypt(plain.as_bytes()) {
        Ok(enc) => {
            use base64::Engine;
            format!("dpapi:{}", base64::engine::general_purpose::STANDARD.encode(enc))
        }
        Err(_) => {
            // AES fallback
            let key = get_machine_key();
            let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
            let nonce_bytes = [7u8; 12]; // deterministic fallback nonce
            let nonce = Nonce::from_slice(&nonce_bytes);
            if let Ok(ciphertext) = cipher.encrypt(nonce, plain.as_bytes()) {
                use base64::Engine;
                let mut combined = nonce_bytes.to_vec();
                combined.extend_from_slice(&ciphertext);
                format!("aesgcm:{}", base64::engine::general_purpose::STANDARD.encode(combined))
            } else {
                plain.to_string()
            }
        }
    }
}

/// Decrypts a sensitive string (supports dpapi:, aesgcm:, or plaintext).
pub fn decrypt_secret(cipher_text: &str) -> String {
    use base64::Engine;
    if cipher_text.is_empty() {
        return String::new();
    }

    if let Some(rest) = cipher_text.strip_prefix("dpapi:") {
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(rest) {
            if let Ok(dec) = dpapi_decrypt(&bytes) {
                if let Ok(s) = String::from_utf8(dec) {
                    return s;
                }
            }
        }
    } else if let Some(rest) = cipher_text.strip_prefix("aesgcm:") {
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(rest) {
            if bytes.len() > 12 {
                let (nonce_bytes, ct) = bytes.split_at(12);
                let key = get_machine_key();
                if let Ok(cipher) = Aes256Gcm::new_from_slice(&key) {
                    let nonce = Nonce::from_slice(nonce_bytes);
                    if let Ok(pt) = cipher.decrypt(nonce, ct) {
                        if let Ok(s) = String::from_utf8(pt) {
                            return s;
                        }
                    }
                }
            }
        }
    } else if let Some(rest) = cipher_text.strip_prefix("xor:") {
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(rest) {
            let key = get_machine_key();
            let xor_bytes: Vec<u8> = bytes.iter().enumerate().map(|(i, b)| b ^ key[i % key.len()]).collect();
            if let Ok(s) = String::from_utf8(xor_bytes) {
                return s;
            }
        }
    }

    cipher_text.to_string()
}

/// Encrypts raw file bytes for quarantine storage using AES-256-GCM.
/// Matches Python b"FIKRADO_ENC_V1" + 12-byte nonce + ciphertext.
pub fn encrypt_file_data(data: &[u8]) -> Vec<u8> {
    let key = get_machine_key();
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    // Generate pseudo-random nonce from timestamp and size
    let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..8].copy_from_slice(&now.to_le_bytes());
    nonce_bytes[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut result = b"FIKRADO_ENC_V1".to_vec();
    result.extend_from_slice(&nonce_bytes);
    if let Ok(ciphertext) = cipher.encrypt(nonce, data) {
        result.extend_from_slice(&ciphertext);
        result
    } else {
        // Fallback XOR
        let mut xor_res = b"FIKRADO_XOR_V1".to_vec();
        for (i, b) in data.iter().enumerate() {
            xor_res.push(b ^ key[i % key.len()]);
        }
        xor_res
    }
}

/// Decrypts quarantined file bytes for safe restoration.
pub fn decrypt_file_data(data: &[u8]) -> Result<Vec<u8>, String> {
    let key = get_machine_key();
    if data.starts_with(b"FIKRADO_ENC_V1") && data.len() > 26 {
        let nonce_bytes = &data[14..26];
        let ciphertext = &data[26..];
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher.decrypt(nonce, ciphertext).map_err(|e| format!("Decryption failed: {:?}", e))
    } else if data.starts_with(b"FIKRADO_XOR_V1") {
        let payload = &data[14..];
        let pt: Vec<u8> = payload.iter().enumerate().map(|(i, b)| b ^ key[i % key.len()]).collect();
        Ok(pt)
    } else {
        Ok(data.to_vec())
    }
}
