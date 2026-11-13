use std::fs::File;
use std::io::Read;
use std::path::Path;

pub struct PeAnalysisFinding {
    pub engine: String,
    pub threat_name: String,
    pub threat_type: String,
    pub severity: String,
    pub description: String,
}

/// Calculates Shannon entropy of a byte slice (0.0 to 8.0).
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len_f = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len_f;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Analyzes a PE file for heuristic threat indicators (packer, high entropy, suspicious strings).
pub fn analyze_pe(file_path: &Path) -> Vec<PeAnalysisFinding> {
    let mut findings = Vec::new();

    // Check extension
    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    if !["exe", "dll", "sys", "scr", "cpl", "ocx"].contains(&ext.as_str()) {
        return findings;
    }

    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return findings,
    };

    let mut buffer = Vec::new();
    // Read up to 10MB
    if file.take(10 * 1024 * 1024).read_to_end(&mut buffer).is_err() || buffer.len() < 512 {
        return findings;
    }

    // Verify DOS signature "MZ"
    if buffer[0] != b'M' || buffer[1] != b'Z' {
        return findings;
    }

    // Find PE offset at 0x3C
    let pe_offset = u32::from_le_bytes([buffer[0x3C], buffer[0x3D], buffer[0x3E], buffer[0x3F]]) as usize;
    if pe_offset + 4 > buffer.len() {
        return findings;
    }

    // Verify PE signature "PE\0\0"
    if buffer[pe_offset..pe_offset + 4] != [b'P', b'E', 0, 0] {
        return findings;
    }

    // Read NumberOfSections at pe_offset + 6
    let num_sections = u16::from_le_bytes([buffer[pe_offset + 6], buffer[pe_offset + 7]]) as usize;
    let opt_header_size = u16::from_le_bytes([buffer[pe_offset + 20], buffer[pe_offset + 21]]) as usize;
    let section_table_offset = pe_offset + 24 + opt_header_size;

    let known_packers = ["upx", "aspack", "pecompact", "themida", "vmprotect", "mew", "fsg"];
    let mut high_entropy_sections = 0;

    for i in 0..num_sections.min(32) {
        let sec_offset = section_table_offset + (i * 40);
        if sec_offset + 40 > buffer.len() {
            break;
        }

        let name_bytes = &buffer[sec_offset..sec_offset + 8];
        let name = String::from_utf8_lossy(name_bytes)
            .trim_matches(char::from(0))
            .to_ascii_lowercase();

        let raw_size = u32::from_le_bytes([
            buffer[sec_offset + 16],
            buffer[sec_offset + 17],
            buffer[sec_offset + 18],
            buffer[sec_offset + 19],
        ]) as usize;

        let raw_offset = u32::from_le_bytes([
            buffer[sec_offset + 20],
            buffer[sec_offset + 21],
            buffer[sec_offset + 22],
            buffer[sec_offset + 23],
        ]) as usize;

        for kp in &known_packers {
            if name.contains(kp) {
                findings.push(PeAnalysisFinding {
                    engine: "PE Packer Detector".to_string(),
                    threat_name: format!("Suspicious Known Packer: {}", name.to_uppercase()),
                    threat_type: "Suspicious".to_string(),
                    severity: "Medium".to_string(),
                    description: format!(
                        "Executable section '{}' matches known packer {}, commonly used to obfuscate payloads.",
                        name,
                        kp.to_uppercase()
                    ),
                });
            }
        }

        if raw_offset + raw_size <= buffer.len() && raw_size > 512 {
            let section_data = &buffer[raw_offset..raw_offset + raw_size];
            let entropy = calculate_entropy(section_data);
            if entropy > 7.3 {
                high_entropy_sections += 1;
            }
        }
    }

    if high_entropy_sections >= 2 {
        findings.push(PeAnalysisFinding {
            engine: "PE Entropy Analyzer".to_string(),
            threat_name: "High-Entropy Binary Sections (Packed / Encrypted)".to_string(),
            threat_type: "Suspicious".to_string(),
            severity: "Medium".to_string(),
            description: format!(
                "Detected {} sections with Shannon entropy > 7.3, indicating packed, compressed or encrypted payload.",
                high_entropy_sections
            ),
        });
    }

    // Inspect strings for critical API injections
    let content_str = String::from_utf8_lossy(&buffer);
    let mut api_matches = 0;
    let suspicious_apis = [
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "SetWindowsHookEx",
        "NtUnmapViewOfSection",
        "InternetOpenUrl",
        "HttpSendRequest",
        "QueueUserAPC",
    ];

    for api in &suspicious_apis {
        if content_str.contains(api) {
            api_matches += 1;
        }
    }

    if api_matches >= 3 {
        findings.push(PeAnalysisFinding {
            engine: "PE Import Heuristics".to_string(),
            threat_name: "Process Injection / Evasion API Cluster".to_string(),
            threat_type: "Trojan".to_string(),
            severity: "High".to_string(),
            description: format!(
                "Binary imports multiple APIs used in process hollowing, memory injection, or keylogging ({} matches).",
                api_matches
            ),
        });
    }

    findings
}
