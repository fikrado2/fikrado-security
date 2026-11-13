# Fikrado Security - Build and Run Guide

## Quick Start

### Run the Compiled Executable (No installation or runtime required)
```powershell
# Double-click or run from terminal:
.\dist\FikradoSecurity.exe
```
Or execute:
```cmd
run.bat
```

---

## Architecture Overview

Fikrado Security has been modernized and rebuilt in **Rust**:
- **Framework:** `tao` + `wry` (native Windows windowing, native Windows 11 title bar and standard caption buttons, GPU-accelerated WebView2 rendering).
- **Subsystem:** `#![windows_subsystem = "windows"]` (zero console window flash, true Windows desktop application).
- **Binary Footprint:** ~3.3 MB single standalone executable with zero Python dependencies, zero DLL dependencies, and embedded branding/resources.
- **Security Engine:** Multi-threaded native Rust file scanner, PE header entropy parser, Windows DPAPI credential protection, AES-256-GCM quarantine vault, CISA KEV vulnerability correlation, listening socket resolver, and Windows Defender / Firewall management.

---

## Building from Source

### Prerequisites
- [Rust & Cargo](https://rustup.rs/) (stable channel, `x86_64-pc-windows-msvc`)
- Visual Studio C++ Build Tools

### One-Click Build
```cmd
build.bat
```

### Manual Cargo Build
```powershell
# Optimized release build with LTO and binary stripping:
cargo build --release

# The compiled binary is generated at:
# target\release\FikradoSecurity.exe

# Copy to distribution directory:
Copy-Item "target\release\FikradoSecurity.exe" "dist\FikradoSecurity.exe"
```

## Dual Theme & UI Match (Dark & Light Mockups)

1. **Top Theme Switcher:**
   - Clickable button in the top bar (`id="theme-toggle-btn"`) with Moon icon in dark mode and Sun icon in light mode.
   - Smoothly toggles between Cyberpunk Dark and Frosted Glass Light themes matching 100% of the mockups.
   - User preference persists across restarts via `localStorage`.

2. **Transparent Frosted Glass Sidebar:**
   - Translucent sidebar with `backdrop-filter: blur(25px)` and dual gold/cyan border glow.
   - Golden Shield Mask logo at top with `FIKRADO` and `Security`.
   - 10 Navigation Items: Home, Dashboard (active gold pill), Scan, Evaluations, Audit Reports, Quarantine, Port Scanner, Updates & Vuls, AI Neural Scan, Terminal.
   - User Profile Footer with avatar, green online status dot, and name **"Yahye Abdirahman"**.
   - Profile Context Menu with "Lock Workspace", "Telemetry Center", and "Export Audit PDF".

3. **Startup Zero-Trust Login Option:**
   - Authentication modal at startup with Golden Shield Mask, user "Yahye Abdirahman" (Administrator), and PIN/Password field (default: 2026).
   - "Unlock Security Suite" & "Windows Hello / Fast Access" bypass options.
   - "Remember session" checkbox and lock workspace action.

4. **Functional Computer Information & Real-Time Metrics:**
   - Real-time CPU load chip (e.g. `12.5% CPU`) and RAM consumption chip (e.g. `8.7 GB RAM`) dynamically fetched via `sysinfo`.
   - Windows 11 platform indicator with native Windows icon.
   - Clickable `Database: Connected` badge verifying SQLite database health.
   - Threat Map with illuminated threat hotspots and interactive counters (Blocked: 120, Warned: 45, Allowed: 415).
   - Total Activity for 7D area chart with time range dropdown (7 Days, 14 Days, 30 Days).
   - Daily Activities Donut Chart with live legend.
   - Heuristics progress bars and `All Systems Secure` button opening the Security Telemetry modal.
   - All buttons display live app status.

---

## Features & Modules

1. **Native Windows Experience:**
   - Standard Windows 11 title bar with genuine minimize, maximize, restore, and close buttons.
   - Smooth window resizing, snapping, and layout adaptability across all resolutions.
   - Mathematically centered startup loading screen that adapts dynamically on resize.
   - Responsive brand identity ("FIKRADO SECURITY by Fikrado Security") that scales cleanly without clipping.

2. **Dashboard & Threat Posture:**
   - Animated circular security posture gauge (0-100 score).
   - High-contrast KPI cards (Total Scanned, Active Threats, Protected Files, Shield Status).
   - Recent activity log and quick action triggers.

3. **Multithreaded Malware & Virus Scanner:**
   - Quick Scan (critical user and system paths).
   - Full Drive Scan (complete storage enumeration).
   - Custom Directory Scan.
   - Real-time pause, resume, cancel controls, live file indicators, and threat isolation.

4. **PE Binary & Entropy Analysis:**
   - Shannon entropy calculation per section (entropy > 7.3 flagged as packed/encrypted).
   - Packer signature detection (.upx, .aspack, .themida, .vmprotect, etc.).
   - Suspicious import table cluster heuristics.

5. **Open Port & Network Inspector:**
   - Active TCP/UDP listening socket enumeration.
   - PID-to-process attribution.
   - Instant process termination (`taskkill`) and inbound Windows Firewall blocking (`netsh`).

6. **Vulnerabilities & Updates:**
   - Enumeration of installed software via Windows Registry.
   - Offline correlation against local CISA Known Exploited Vulnerabilities (KEV) database.
   - One-click application upgrades via Windows Package Manager (`winget`).
   - Windows Update KB patch-level auditing.

7. **Quarantine Isolation Chamber:**
   - AES-256-GCM encrypted container with machine-bound key derivation.
   - System32 / WinSxS write protection shield preventing destructive system modification.
   - Safe restoration and permanent DOD-grade destruction.

8. **Security Tools Hub:**
   - **DoD 5220.22-M File Shredder:** Military-grade 3-pass and 7-pass secure data destruction.
   - **Password Security & Breach Auditor:** Shannon entropy calculation and HaveIBeenPwned k-anonymity API query (zero password disclosure).
   - **Windows Defender Controls:** Real-time status query, quick scan trigger, and signature definition update.
   - **Windows Firewall Manager:** Domain, Private, and Public profile management.
   - **Registry Startup Manager:** Audit and removal of persistence Run/RunOnce keys.
   - **Process Explorer:** Real-time process monitoring with masquerade/temp folder execution flags.
   - **Hosts File Integrity:** Detection of hijacking in `drivers\etc\hosts` and one-click clean restoration.
   - **System Hardening:** Automated audit of UAC, Defender, Firewall, SMBv1, and RDP exposure.
   - **DNS & Network Diagnostic:** Adapter configuration, active DNS resolvers, and public IP testing.
   - **Real-Time Protection Shield:** Background file drop and persistence key watcher.

9. **Blue Team Terminal:**
   - Silent execution runner with command presets (`whoami /priv`, `netstat -ano`, `tasklist /svc`, etc.).

10. **AI Threat Intelligence:**
    - Integration with Gemini, OpenAI, Claude, OpenRouter, and Ollama.
    - Encrypted API key storage via Windows Data Protection API (DPAPI).
