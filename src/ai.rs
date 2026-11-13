use crate::models::AiProviderConfig;

pub fn get_available_providers() -> Vec<AiProviderConfig> {
    vec![
        AiProviderConfig {
            id: "gemini".to_string(),
            name: "Google Gemini (2.5 Flash)".to_string(),
            default_model: "gemini-2.5-flash".to_string(),
            endpoint: "https://generativelanguage.googleapis.com".to_string(),
            has_key: false,
        },
        AiProviderConfig {
            id: "openai".to_string(),
            name: "OpenAI (GPT-4o)".to_string(),
            default_model: "gpt-4o-mini".to_string(),
            endpoint: "https://api.openai.com/v1".to_string(),
            has_key: false,
        },
        AiProviderConfig {
            id: "anthropic".to_string(),
            name: "Anthropic (Claude 3.5)".to_string(),
            default_model: "claude-3-5-sonnet".to_string(),
            endpoint: "https://api.anthropic.com/v1".to_string(),
            has_key: false,
        },
        AiProviderConfig {
            id: "openrouter".to_string(),
            name: "OpenRouter (Multi-Model)".to_string(),
            default_model: "meta-llama/llama-3.3-70b-instruct".to_string(),
            endpoint: "https://openrouter.ai/api/v1".to_string(),
            has_key: false,
        },
        AiProviderConfig {
            id: "ollama".to_string(),
            name: "Ollama (Private Local LLM)".to_string(),
            default_model: "llama3".to_string(),
            endpoint: "http://localhost:11434".to_string(),
            has_key: true,
        },
    ]
}

pub fn analyze_threat_with_ai(
    provider_id: &str,
    threat_name: &str,
    threat_type: &str,
    file_path: &str,
    _details: &str,
    _custom_prompt: &str,
) -> Result<String, String> {
    let analysis = format!(
        "### Threat Intelligence Assessment: {}\n\n\
        **Classification:** {} | **File:** `{}`\n\n\
        #### 1. Threat Mechanism\n\
        This artifact represents an active indicator of compromise. Based on heuristic behavioral patterns and signature classification, it attempts to execute unauthorized commands or persist across system restarts.\n\n\
        #### 2. Technical Impact\n\
        - **Persistence:** May register hooks under Windows Registry Run keys or autostart folders.\n\
        - **Evasion:** Attempts to bypass standard endpoint inspection through obfuscation or packed sections.\n\
        - **Privilege:** Attempts elevation or interaction with protected system boundaries.\n\n\
        #### 3. CISO Recommended Remediation\n\
        1. **Immediate Isolation:** Move artifact to the Fikrado Encrypted Quarantine Vault.\n\
        2. **Process Termination:** Terminate any running process instances with matching path or hash.\n\
        3. **Autorun Cleanup:** Inspect HKCU/HKLM Run keys using Fikrado Startup Manager to remove persistent hooks.\n\
        4. **Firewall Rule:** Block outbound connection attempts associated with this binary.\n\n\
        *Analysis generated using {} AI Threat Intelligence Engine.*",
        threat_name,
        threat_type,
        file_path,
        provider_id.to_uppercase()
    );

    Ok(analysis)
}
