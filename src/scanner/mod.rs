pub mod pe_analyzer;
pub mod persistence;

use crate::db::Database;
use crate::models::{ScanMode, ScanProgress, ScanSummary, ThreatFinding};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use sysinfo::System;
use walkdir::WalkDir;

pub struct ScannerController {
    pub is_paused: Arc<AtomicBool>,
    pub is_cancelled: Arc<AtomicBool>,
}

impl ScannerController {
    pub fn new() -> Self {
        Self {
            is_paused: Arc::new(AtomicBool::new(false)),
            is_cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn pause(&self) {
        self.is_paused.store(true, Ordering::SeqCst);
    }

    pub fn resume(&self) {
        self.is_paused.store(false, Ordering::SeqCst);
    }

    pub fn cancel(&self) {
        self.is_cancelled.store(true, Ordering::SeqCst);
    }
}

pub fn compute_sha256(path: &Path) -> Option<String> {
    if let Ok(metadata) = path.metadata() {
        // Skip files > 200MB for fast scanning
        if metadata.len() > 200 * 1024 * 1024 {
            return None;
        }
    }

    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let count = file.read(&mut buffer).ok()?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    Some(format!("{:x}", hasher.finalize()))
}

pub fn run_scan<F>(
    mode: ScanMode,
    custom_target: Option<String>,
    controller: &ScannerController,
    db: Arc<Database>,
    mut progress_cb: F,
) -> ScanSummary
where
    F: FnMut(ScanProgress),
{
    let mode_str = match mode {
        ScanMode::Quick => "Quick",
        ScanMode::Full => "Full",
        ScanMode::Custom => "Custom",
    };

    let scan_id = db.record_scan_start(mode_str).unwrap_or(0);
    let start_time = Instant::now();
    let mut threats: Vec<ThreatFinding> = Vec::new();

    // In Quick or Full mode, check persistence hooks
    if matches!(mode, ScanMode::Quick | ScanMode::Full) {
        let persist_threats = persistence::inspect_persistence();
        for mut pt in persist_threats {
            pt.scan_id = Some(scan_id);
            let _ = db.record_threat(&pt);
            threats.push(pt);
        }
    }

    // Collect target files
    let mut target_files: Vec<PathBuf> = Vec::new();
    match mode {
        ScanMode::Custom => {
            if let Some(target) = custom_target {
                let p = PathBuf::from(target);
                if p.is_file() {
                    target_files.push(p);
                } else if p.is_dir() {
                    for entry in WalkDir::new(&p).max_depth(5).into_iter().filter_map(|e| e.ok()) {
                        if entry.file_type().is_file() {
                            target_files.push(entry.into_path());
                        }
                    }
                }
            }
        }
        ScanMode::Quick => {
            let mut probe_dirs = Vec::new();
            if let Ok(temp) = std::env::var("TEMP") {
                probe_dirs.push(PathBuf::from(temp));
            }
            if let Ok(userprofile) = std::env::var("USERPROFILE") {
                let up = PathBuf::from(userprofile);
                probe_dirs.push(up.join("Downloads"));
                probe_dirs.push(up.join("Desktop"));
                probe_dirs.push(up.join("AppData\\Local\\Temp"));
            }

            let extensions = ["exe", "dll", "bat", "ps1", "vbs", "cmd", "scr", "zip", "msi"];

            for dir in probe_dirs {
                if !dir.exists() {
                    continue;
                }
                for entry in WalkDir::new(&dir).max_depth(3).into_iter().filter_map(|e| e.ok()) {
                    if entry.file_type().is_file() {
                        let path = entry.path();
                        let ext = path
                            .extension()
                            .and_then(|e| e.to_str())
                            .map(|s| s.to_ascii_lowercase())
                            .unwrap_or_default();
                        if extensions.contains(&ext.as_str()) {
                            target_files.push(path.to_path_buf());
                        }
                        if target_files.len() >= 600 {
                            break;
                        }
                    }
                }
            }

            // Running process binaries
            let mut sys = System::new_all();
            sys.refresh_all();
            for (_, proc) in sys.processes() {
                if let Some(exe) = proc.exe() {
                    if exe.is_file() && !target_files.contains(&exe.to_path_buf()) {
                        target_files.push(exe.to_path_buf());
                    }
                }
            }
        }
        ScanMode::Full => {
            // Enumerate drives C..Z
            for drive in b'C'..=b'Z' {
                let drive_str = format!("{}:\\", drive as char);
                let p = PathBuf::from(&drive_str);
                if p.exists() {
                    for entry in WalkDir::new(&p).max_depth(4).into_iter().filter_map(|e| e.ok()) {
                        if entry.file_type().is_file() {
                            target_files.push(entry.into_path());
                        }
                        if target_files.len() >= 2500 {
                            break;
                        }
                    }
                }
            }
        }
    }

    let total = target_files.len().max(1);
    let mut scanned_count = 0;

    for (idx, path) in target_files.iter().enumerate() {
        // Check cancel
        if controller.is_cancelled.load(Ordering::SeqCst) {
            break;
        }

        // Check pause loop
        while controller.is_paused.load(Ordering::SeqCst) {
            if controller.is_cancelled.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(150));
        }

        scanned_count = idx + 1;
        let elapsed = start_time.elapsed().as_secs_f64();
        let speed = scanned_count as f64 / elapsed.max(0.1);
        let remaining = total.saturating_sub(scanned_count);
        let eta_seconds = (remaining as f64 / speed.max(1.0)) as u64;

        progress_cb(ScanProgress {
            scanned_count,
            total_count: total,
            current_file: path.to_string_lossy().to_string(),
            eta_seconds,
            percentage: ((scanned_count * 100) / total) as u32,
            threats_count: threats.len(),
        });

        // 1. Hash Lookup
        if let Some(hash) = compute_sha256(path) {
            if let Ok(Some((t_name, t_type, sev, desc))) = db.check_known_hash(&hash) {
                let tf = ThreatFinding {
                    id: None,
                    scan_id: Some(scan_id),
                    file_path: path.to_string_lossy().to_string(),
                    threat_name: t_name,
                    threat_type: t_type,
                    severity: sev,
                    detection_engine: "Signature Hash Database".to_string(),
                    description: desc,
                    action_taken: "Flagged".to_string(),
                    sha256: hash.clone(),
                    detected_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                };
                let _ = db.record_threat(&tf);
                threats.push(tf);
                continue;
            }
        }

        // 2. PE Heuristics & Section Entropy
        let pe_findings = pe_analyzer::analyze_pe(path);
        for pe_f in pe_findings {
            let tf = ThreatFinding {
                id: None,
                scan_id: Some(scan_id),
                file_path: path.to_string_lossy().to_string(),
                threat_name: pe_f.threat_name,
                threat_type: pe_f.threat_type,
                severity: pe_f.severity,
                detection_engine: pe_f.engine,
                description: pe_f.description,
                action_taken: "Flagged".to_string(),
                sha256: "".to_string(),
                detected_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            };
            let _ = db.record_threat(&tf);
            threats.push(tf);
        }
    }

    let duration_seconds = start_time.elapsed().as_secs_f64();
    let score = (100 - (threats.len() as i32 * 15)).max(0);
    let status = if controller.is_cancelled.load(Ordering::SeqCst) {
        "Cancelled"
    } else {
        "Completed"
    };

    let _ = db.record_scan_finish(scan_id, scanned_count, threats.len(), duration_seconds, score, status);

    ScanSummary {
        scan_id,
        scan_mode: mode_str.to_string(),
        duration_seconds,
        scanned_count,
        threats_count: threats.len(),
        score,
        status: status.to_string(),
        threats,
    }
}
