#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct PasswordAnalysis {
    pub length: usize,
    pub entropy_bits: f64,
    pub strength_label: String,
    pub score: u32, // 0 to 100
    pub breached_count: Option<u64>,
    pub recommendation: String,
}

pub fn calculate_entropy(password: &str) -> (f64, String, u32) {
    if password.is_empty() {
        return (0.0, "Very Weak".to_string(), 0);
    }

    let mut pool_size = 0usize;
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    if has_lower { pool_size += 26; }
    if has_upper { pool_size += 26; }
    if has_digit { pool_size += 10; }
    if has_special { pool_size += 32; }

    let entropy = (password.len() as f64) * (pool_size as f64).log2();
    let score = ((entropy / 80.0) * 100.0).clamp(0.0, 100.0) as u32;

    let label = if entropy < 28.0 {
        "Very Weak"
    } else if entropy < 45.0 {
        "Weak"
    } else if entropy < 65.0 {
        "Moderate"
    } else if entropy < 85.0 {
        "Strong"
    } else {
        "Very Strong"
    };

    (entropy, label.to_string(), score)
}

pub fn check_haveibeenpwned(password: &str) -> Option<u64> {
    if password.is_empty() {
        return None;
    }

    // SHA-1 of password for k-anonymity API
    use sha1::{Digest as Sha1Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let hash = format!("{:X}", hasher.finalize());

    if hash.len() < 5 {
        return None;
    }

    let prefix = &hash[..5];
    let suffix = &hash[5..];

    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(4))
        .build()
        .ok()?;

    let resp = client.get(&url).header("User-Agent", "FikradoSecurity").send().ok()?;
    if resp.status().is_success() {
        let text = resp.text().ok()?;
        for line in text.lines() {
            let parts: Vec<&str> = line.trim().split(':').collect();
            if parts.len() == 2 && parts[0].eq_ignore_ascii_case(suffix) {
                return parts[1].parse().ok();
            }
        }
        return Some(0); // 0 breaches found
    }

    None
}
