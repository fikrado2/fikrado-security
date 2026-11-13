use crate::crypto::{decrypt_file_data, encrypt_file_data};
use crate::models::QuarantineItem;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub fn get_quarantine_dir() -> PathBuf {
    let appdata = std::env::var("APPDATA")
        .unwrap_or_else(|_| "C:\\Users\\Default\\AppData\\Roaming".to_string());
    let qdir = PathBuf::from(appdata).join("FikradoSecurity\\quarantine");
    let _ = fs::create_dir_all(&qdir);
    qdir
}

pub fn is_protected_system_file(file_path: &str) -> bool {
    let lower = file_path.to_ascii_lowercase();
    let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string()).to_ascii_lowercase();

    let protected = [
        format!("{}\\system32", sys_root),
        format!("{}\\syswow64", sys_root),
        format!("{}\\winsxs", sys_root),
        format!("{}\\system32\\drivers", sys_root),
    ];

    for p in &protected {
        if lower.starts_with(p) {
            // Check critical core files
            let critical = ["ntoskrnl.exe", "hal.dll", "kernel32.dll", "ntdll.dll", "user32.dll", "csrss.exe", "winlogon.exe"];
            for c in &critical {
                if lower.ends_with(c) {
                    return true;
                }
            }
        }
    }
    false
}

pub fn quarantine_file(
    file_path: &str,
    threat_name: &str,
    threat_type: &str,
    severity: &str,
    engine: &str,
) -> Result<QuarantineItem, String> {
    let path = Path::new(file_path);
    if !path.exists() || !path.is_file() {
        return Err(format!("File does not exist: {}", file_path));
    }

    if is_protected_system_file(file_path) {
        return Err("SAFETY SHIELD: Cannot quarantine protected Windows system file.".to_string());
    }

    let raw_bytes = fs::read(path).map_err(|e| format!("Read error: {}", e))?;
    let file_size = raw_bytes.len() as u64;

    let mut hasher = Sha256::new();
    hasher.update(&raw_bytes);
    let sha256_hash = format!("{:x}", hasher.finalize());

    let q_id = uuid::Uuid::new_v4().to_string();
    let encrypted_bytes = encrypt_file_data(&raw_bytes);

    let qdir = get_quarantine_dir();
    let blob_path = qdir.join(format!("{}.qtn", q_id));
    fs::write(&blob_path, encrypted_bytes).map_err(|e| format!("Failed to write quarantine blob: {}", e))?;

    // Remove original file
    let _ = fs::remove_file(path);

    let item = QuarantineItem {
        id: q_id,
        original_path: path.to_string_lossy().to_string(),
        filename: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
        file_size,
        sha256: sha256_hash,
        threat_name: threat_name.to_string(),
        threat_type: threat_type.to_string(),
        severity: severity.to_string(),
        detection_engine: engine.to_string(),
        quarantine_time: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        notes: "Securely isolated with AES-256-GCM encryption.".to_string(),
        status: "Quarantined".to_string(),
    };

    save_quarantine_index(&item);
    Ok(item)
}

fn get_index_path() -> PathBuf {
    get_quarantine_dir().join("quarantine_index.json")
}

pub fn list_quarantine_items() -> Vec<QuarantineItem> {
    let index_file = get_index_path();
    if let Ok(content) = fs::read_to_string(index_file) {
        if let Ok(items) = serde_json::from_str::<Vec<QuarantineItem>>(&content) {
            return items;
        }
    }
    Vec::new()
}

fn save_quarantine_index(item: &QuarantineItem) {
    let mut items = list_quarantine_items();
    items.retain(|i| i.id != item.id);
    items.insert(0, item.clone());
    let _ = fs::write(get_index_path(), serde_json::to_string_pretty(&items).unwrap_or_default());
}

pub fn restore_quarantined_file(id: &str) -> Result<String, String> {
    let items = list_quarantine_items();
    let item = items
        .iter()
        .find(|i| i.id == id)
        .ok_or_else(|| "Item not found in quarantine index".to_string())?;

    let qdir = get_quarantine_dir();
    let blob_path = qdir.join(format!("{}.qtn", id));
    if !blob_path.exists() {
        return Err("Encrypted quarantine blob file missing.".to_string());
    }

    let enc_bytes = fs::read(&blob_path).map_err(|e| e.to_string())?;
    let raw_bytes = decrypt_file_data(&enc_bytes)?;

    let orig_path = PathBuf::from(&item.original_path);
    if let Some(parent) = orig_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    fs::write(&orig_path, raw_bytes).map_err(|e| format!("Restore write error: {}", e))?;
    let _ = fs::remove_file(&blob_path);

    let mut remaining = items;
    remaining.retain(|i| i.id != id);
    let _ = fs::write(get_index_path(), serde_json::to_string_pretty(&remaining).unwrap_or_default());

    Ok(format!("File restored safely to '{}'.", orig_path.display()))
}

pub fn delete_quarantined_file(id: &str) -> Result<String, String> {
    let items = list_quarantine_items();
    let qdir = get_quarantine_dir();
    let blob_path = qdir.join(format!("{}.qtn", id));
    let _ = fs::remove_file(blob_path);

    let mut remaining = items;
    remaining.retain(|i| i.id != id);
    let _ = fs::write(get_index_path(), serde_json::to_string_pretty(&remaining).unwrap_or_default());

    Ok("Quarantined artifact permanently destroyed.".to_string())
}
