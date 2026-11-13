use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanMode {
    Quick,
    Full,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFinding {
    pub id: Option<i64>,
    pub scan_id: Option<i64>,
    pub file_path: String,
    pub threat_name: String,
    pub threat_type: String,
    pub severity: String,
    pub detection_engine: String,
    pub description: String,
    pub action_taken: String,
    pub sha256: String,
    pub detected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scanned_count: usize,
    pub total_count: usize,
    pub current_file: String,
    pub eta_seconds: u64,
    pub percentage: u32,
    pub threats_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub scan_id: i64,
    pub scan_mode: String,
    pub duration_seconds: f64,
    pub scanned_count: usize,
    pub threats_count: usize,
    pub score: i32,
    pub status: String,
    pub threats: Vec<ThreatFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanHistoryItem {
    pub id: i64,
    pub scan_type: String,
    pub start_time: String,
    pub end_time: Option<String>,
    pub duration_seconds: Option<f64>,
    pub files_scanned: i64,
    pub threats_found: i64,
    pub status: String,
    pub score: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenPort {
    pub protocol: String,
    pub local_ip: String,
    pub port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub status: String,
    pub pid: Option<u32>,
    pub process_name: String,
    pub exe_path: String,
    pub is_risky: bool,
    pub service_name: String,
    pub severity: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledApp {
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub registry_id: String,
    pub cve_matches: Vec<CveRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveRecord {
    pub cve_id: String,
    pub vendor_project: String,
    pub product: String,
    pub vulnerability_name: String,
    pub date_added: String,
    pub short_description: String,
    pub required_action: String,
    pub due_date: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupItem {
    pub id: String,
    pub name: String,
    pub command: String,
    pub location: String,
    pub is_enabled: bool,
    pub is_suspicious: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessItem {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
    pub cpu_percent: f32,
    pub memory_mb: f64,
    pub is_suspicious: bool,
    pub risk_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningCheck {
    pub id: String,
    pub title: String,
    pub status: String, // "Pass", "Warn", "Fail"
    pub details: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineItem {
    pub id: String,
    pub original_path: String,
    pub filename: String,
    pub file_size: u64,
    pub sha256: String,
    pub threat_name: String,
    pub threat_type: String,
    pub severity: String,
    pub detection_engine: String,
    pub quarantine_time: String,
    pub notes: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardStats {
    pub total_scanned_files: u64,
    pub threats_blocked: u64,
    pub active_protections: u32,
    pub cves_tracked: u64,
    pub last_score: i32,
    pub last_scan_time: String,
    pub shield_active: bool,
    pub defender_active: bool,
    pub firewall_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiProviderConfig {
    pub id: String,
    pub name: String,
    pub default_model: String,
    pub endpoint: String,
    pub has_key: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDiagResult {
    pub adapter_name: String,
    pub ip_address: String,
    pub mac_address: String,
    pub dns_servers: Vec<String>,
    pub gateway: String,
    pub public_ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostsAuditResult {
    pub path: String,
    pub total_lines: usize,
    pub active_entries: usize,
    pub hijacked_entries: Vec<String>,
    pub is_clean: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootkitResult {
    pub check_type: String,
    pub severity: String,
    pub detail: String,
    pub indicator: String,
    pub recommendation: String,
}
