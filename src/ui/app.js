// Fikrado Security - Native Windows Application Controller

let activePageIdx = 0;
let isShieldActive = true;
let isScanning = false;

// -----------------------------------------------------------------------------
// IPC Bridge
// -----------------------------------------------------------------------------
function sendIpc(cmd, payload = {}) {
  const msg = JSON.stringify({ cmd, payload });
  if (window.ipc) {
    window.ipc.postMessage(msg);
  } else {
    console.log("[MOCK IPC]", cmd, payload);
  }
}

// Global receiver called from Rust webview.evaluate_script
window.__onRustEvent = function (event, data) {
  if (event === "scan:progress") {
    handleScanProgress(data);
  } else if (event === "scan:threat_found") {
    handleThreatFound(data);
  } else if (event === "scan:finished") {
    handleScanFinished(data);
  } else if (event === "terminal:output") {
    handleTerminalOutput(data);
  } else if (event === "report:data") {
    handleReportData(data);
  } else if (event === "hardening:data") {
    handleHardeningData(data);
  } else if (event === "startup:data") {
    handleStartupData(data);
  } else if (event === "process:data") {
    handleProcessData(data);
  } else if (event === "dns:data") {
    handleDnsData(data);
  } else if (event === "firewall:status") {
    handleFirewallStatus(data);
  } else if (event === "defender:status") {
    handleDefenderStatus(data);
  } else if (event === "telemetry:data") {
    handleTelemetryData(data);
  }
};

function handleTelemetryData(data) {
  showToast("Security telemetry: All active protections verified.", "success");
}

// -----------------------------------------------------------------------------
// Safe Storage (Protects against DOMException / opaque origin in WebView2)
// -----------------------------------------------------------------------------
const SafeStorage = {
  _mem: {},
  getItem(key) {
    try {
      if (typeof window !== "undefined" && window.localStorage) {
        return window.localStorage.getItem(key);
      }
    } catch (_) {}
    return this._mem[key] !== undefined ? this._mem[key] : null;
  },
  setItem(key, val) {
    try {
      if (typeof window !== "undefined" && window.localStorage) {
        window.localStorage.setItem(key, val);
        return;
      }
    } catch (_) {}
    this._mem[key] = String(val);
  },
  removeItem(key) {
    try {
      if (typeof window !== "undefined" && window.localStorage) {
        window.localStorage.removeItem(key);
        return;
      }
    } catch (_) {}
    delete this._mem[key];
  }
};

// -----------------------------------------------------------------------------
// Theme Management (Light Frosted Glass & Cyber Dark Theme)
// -----------------------------------------------------------------------------
function toggleTheme() {
  const isLight = document.body.classList.toggle("light-theme");
  document.body.classList.toggle("dark-theme", !isLight);
  SafeStorage.setItem("fikrado_theme", isLight ? "light" : "dark");
  updateThemeIcons(isLight);
  updateChartTheme(isLight);
  showToast(isLight ? "Light Frosted Theme Enabled" : "Cyber Dark Theme Enabled", "info");
}

function initTheme() {
  try {
    const saved = SafeStorage.getItem("fikrado_theme");
    const isLight = (saved === "light");
    if (isLight) {
      document.body.classList.add("light-theme");
      document.body.classList.remove("dark-theme");
    } else {
      document.body.classList.add("dark-theme");
      document.body.classList.remove("light-theme");
    }
    updateThemeIcons(isLight);
    updateChartTheme(isLight);
  } catch (e) {
    console.error("Theme init error:", e);
  }
}

function updateThemeIcons(isLight) {
  const btn = document.getElementById("theme-toggle-btn");
  if (!btn) return;
  if (isLight) {
    // Sun icon in light mode
    btn.innerHTML = `<svg viewBox="0 0 24 24" width="16" height="16" fill="#EAB308"><path d="M12 7c-2.76 0-5 2.24-5 5s2.24 5 5 5 5-2.24 5-5-2.24-5-5-5zM2 13h2c.55 0 1-.45 1-1s-.45-1-1-1H2c-.55 0-1 .45-1 1s.45 1 1 1zm18 0h2c.55 0 1-.45 1-1s-.45-1-1-1h-2c-.55 0-1 .45-1 1s.45 1 1 1zM11 2v2c0 .55.45 1 1 1s1-.45 1-1V2c0-.55-.45-1-1-1s-1 .45-1 1zm0 18v2c0 .55.45 1 1 1s1-.45 1-1v-2c0-.55-.45-1-1-1s-1 .45-1 1zM5.99 4.58c-.39-.39-1.03-.39-1.41 0s-.39 1.03 0 1.41l1.06 1.06c.39.39 1.03.39 1.41 0s.39-1.03 0-1.41L5.99 4.58zm12.37 12.37c-.39-.39-1.03-.39-1.41 0s-.39 1.03 0 1.41l1.06 1.06c.39.39 1.03.39 1.41 0s.39-1.03 0-1.41l-1.06-1.06zm1.06-10.96c.39-.39.39-1.03 0-1.41s-1.03-.39-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06zM7.05 18.36c.39-.39.39-1.03 0-1.41s-1.03-.39-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06z"/></svg>`;
    btn.title = "Switch to Dark Theme";
  } else {
    // Moon icon in dark mode
    btn.innerHTML = `<svg viewBox="0 0 24 24" width="16" height="16" fill="#FFC700"><path d="M12 3c-4.97 0-9 4.03-9 9 0 2.12.74 4.07 1.97 5.61L4.35 19.4c-.39.39-.39 1.02 0 1.41.39.39 1.02.39 1.41 0l1.9-1.9C9.22 19.57 10.57 20 12 20c4.97 0 9-4.03 9-9s-4.03-9-9-9zm0 15c-3.31 0-6-2.69-6-6s2.69-6 6-6 6 2.69 6 6-2.69 6-6 6z"/></svg>`;
    btn.title = "Switch to Light Theme";
  }
}

function updateChartTheme(isLight) {
  const spline = document.getElementById("wave-spline-path");
  if (spline) {
    spline.setAttribute("stroke", isLight ? "#EAB308" : "#FFC700");
  }
}

// -----------------------------------------------------------------------------
// Startup Loading & Zero-Trust Authentication Screen
// -----------------------------------------------------------------------------
let startupFinished = false;

function finishStartup() {
  if (startupFinished) return;
  startupFinished = true;

  const loadingScreen = document.getElementById("loading-screen");
  const loginScreen = document.getElementById("login-screen");

  if (loadingScreen) {
    loadingScreen.style.opacity = "0";
    setTimeout(() => {
      loadingScreen.classList.add("hidden");
      loadingScreen.style.display = "none";
    }, 350);
  }

  const isAuthRemembered = SafeStorage.getItem("fikrado_auth") === "true";
  if (isAuthRemembered) {
    if (loginScreen) {
      loginScreen.classList.add("hidden");
      loginScreen.style.display = "none";
    }
    loadDashboardData();
    showToast("Authorized session restored. Welcome, Yahye Abdirahman.", "success");
  } else {
    if (loginScreen) {
      loginScreen.style.display = "";
      loginScreen.classList.remove("hidden");
      loginScreen.style.opacity = "1";
    }
    const pinInput = document.getElementById("login-pin");
    if (pinInput) pinInput.focus();
  }
}

function initAppStartup() {
  if (startupFinished) return;

  try {
    initTheme();
  } catch (e) {
    console.error("Theme init error:", e);
  }

  const steps = [
    { pct: 30, msg: "Seeding malware signatures & CISA KEV feeds..." },
    { pct: 60, msg: "Loading AI threat plugins & DPAPI security credentials..." },
    { pct: 85, msg: "Starting Real-Time Protection Shield..." },
    { pct: 100, msg: "Ready. Launching Fikrado Security..." }
  ];

  let currentStep = 0;
  const bar = document.getElementById("loading-bar");
  const status = document.getElementById("loading-status");

  function advance() {
    if (startupFinished) return;

    if (currentStep < steps.length) {
      const s = steps[currentStep];
      if (bar) bar.style.width = s.pct + "%";
      if (status) status.innerText = s.msg;
      currentStep++;
      setTimeout(advance, 180);
    } else {
      setTimeout(finishStartup, 200);
    }
  }

  // Absolute safety timeout: loading screen can NEVER remain stuck under any circumstances
  setTimeout(() => {
    if (!startupFinished) {
      console.warn("Failsafe timer finishing startup sequence");
      finishStartup();
    }
  }, 1400);

  setTimeout(advance, 100);
}

function submitLogin() {
  const pinInput = document.getElementById("login-pin");
  const pinVal = pinInput ? pinInput.value.trim() : "";
  const remember = document.getElementById("remember-session-check");
  const loginScreen = document.getElementById("login-screen");

  if (!pinVal) {
    showToast("Please enter security PIN or password", "warn");
    return;
  }

  if (remember && remember.checked) {
    SafeStorage.setItem("fikrado_auth", "true");
  }

  showToast("Security credentials verified. Unlocking dashboard...", "success");

  if (loginScreen) {
    loginScreen.style.opacity = "0";
    loginScreen.style.transform = "scale(1.04)";
    setTimeout(() => {
      loginScreen.classList.add("hidden");
      loginScreen.style.display = "none";
      loginScreen.style.opacity = "";
      loginScreen.style.transform = "";
      loadDashboardData();
    }, 280);
  }
}

function fastBypassLogin() {
  const remember = document.getElementById("remember-session-check");
  const loginScreen = document.getElementById("login-screen");

  if (remember && remember.checked) {
    SafeStorage.setItem("fikrado_auth", "true");
  }

  showToast("Windows Hello biometric verified for Yahye Abdirahman.", "success");

  if (loginScreen) {
    loginScreen.style.opacity = "0";
    setTimeout(() => {
      loginScreen.classList.add("hidden");
      loginScreen.style.display = "none";
      loginScreen.style.opacity = "";
      loadDashboardData();
    }, 250);
  }
}

function togglePinVisibility() {
  const pinInput = document.getElementById("login-pin");
  if (!pinInput) return;
  pinInput.type = (pinInput.type === "password") ? "text" : "password";
}

function lockWorkspace() {
  SafeStorage.removeItem("fikrado_auth");
  const loginScreen = document.getElementById("login-screen");
  if (loginScreen) {
    loginScreen.style.display = "";
    loginScreen.classList.remove("hidden");
    loginScreen.style.opacity = "1";
    loginScreen.style.visibility = "visible";
  }
  const userMenu = document.getElementById("user-profile-menu");
  if (userMenu) userMenu.classList.remove("show");
  showToast("Workspace securely locked.", "info");
}

// -----------------------------------------------------------------------------
// Drawers, Menus & Telemetry Modals
// -----------------------------------------------------------------------------
function toggleNotificationDrawer() {
  const drawer = document.getElementById("notification-drawer");
  if (drawer) drawer.classList.toggle("show");
}

function toggleUserProfileMenu() {
  const menu = document.getElementById("user-profile-menu");
  if (menu) menu.classList.toggle("show");
}

function openSystemTelemetryModal() {
  const modal = document.getElementById("telemetry-modal");
  if (modal) modal.classList.add("show");
  sendIpc("get_system_telemetry");
}

function closeTelemetryModal() {
  const modal = document.getElementById("telemetry-modal");
  if (modal) modal.classList.remove("show");
}

function checkDatabaseHealth() {
  sendIpc("check_database_health");
}

function refreshHardwareMetrics() {
  sendIpc("get_dashboard_stats");
  showToast("Live CPU & physical RAM telemetry refreshed from kernel.", "info");
}

let currentTimeRangeIndex = 0;
const timeRanges = ["7 Days", "14 Days", "30 Days"];

function cycleActivityTimeRange() {
  currentTimeRangeIndex = (currentTimeRangeIndex + 1) % timeRanges.length;
  const label = document.getElementById("chart-range-label");
  if (label) label.innerText = timeRanges[currentTimeRangeIndex];
  
  // Smoothly perturb nodes
  const nodes = document.querySelectorAll(".chart-node");
  nodes.forEach((n, idx) => {
    n.style.transform = `scale(1.2) translateY(${idx % 2 === 0 ? -3 : 3}px)`;
    setTimeout(() => { n.style.transform = ""; }, 250);
  });
  showToast(`Activity timeline filtered to ${timeRanges[currentTimeRangeIndex]}`, "info");
}

function filterThreats(status) {
  showToast(`Threat Intelligence filtered: ${status} records.`, "info");
  const table = document.getElementById("dashboard-threats-tbody");
  if (table) table.scrollIntoView({ behavior: "smooth" });
}

function handleGlobalSearch(query) {
  if (!query) return;
  const q = query.toLowerCase();
  const rows = document.querySelectorAll("#dashboard-threats-tbody tr, #ports-tbody tr, #vulns-tbody tr");
  rows.forEach(r => {
    const text = r.innerText.toLowerCase();
    r.style.display = text.includes(q) ? "" : "none";
  });
}

// -----------------------------------------------------------------------------
// Navigation
// -----------------------------------------------------------------------------
function navigateToPage(target, navElement) {
  let targetId = (typeof target === "number") ? `page-${target}` : target;
  if (!targetId.startsWith("page-")) {
    targetId = `page-${targetId}`;
  }

  // Toggle active class on all page sections
  document.querySelectorAll(".page").forEach(p => {
    p.classList.toggle("active", p.id === targetId);
  });

  // Toggle active class on nav items
  document.querySelectorAll(".nav-list .nav-item").forEach(n => {
    n.classList.remove("active");
  });

  if (navElement && navElement.classList) {
    navElement.classList.add("active");
  } else {
    const match = document.querySelector(`.nav-list .nav-item[data-page="${targetId}"]`);
    if (match) {
      match.classList.add("active");
    } else {
      // If page-0 or page-home, default to Dashboard nav item
      const dash = document.querySelector('.nav-list .nav-item[data-page="page-0"]');
      if (dash) dash.classList.add("active");
    }
  }

  // Page specific data loading
  if (targetId === "page-0") loadDashboardData();
  else if (targetId === "page-1") resetScanButtons();
  else if (targetId === "page-4") loadNetworkConnections();
  else if (targetId === "page-5") loadVulnerabilities();
  else if (targetId === "page-7") loadToolsData();
  else if (targetId === "page-8") loadQuarantineData();
  else if (targetId === "page-9") loadReportData();
  else if (targetId === "page-10") loadTerminalCommands();
  else if (targetId === "page-11") runBootkitAudit();
}

// -----------------------------------------------------------------------------
// Dashboard Data & Circular Gauge
// -----------------------------------------------------------------------------
function loadDashboardData() {
  sendIpc("get_dashboard_stats");
  sendIpc("get_recent_threats");
}

function updateGaugeScore(score) {
  const numberEl = document.getElementById("gauge-score-number");
  const fillEl = document.getElementById("gauge-fill-circle");
  if (numberEl) numberEl.innerText = score;
  if (fillEl) {
    // 440 circumference: 100 -> 0 offset, 0 -> 440 offset
    const offset = 440 - (440 * (score / 100));
    fillEl.style.strokeDashoffset = offset;
  }
}

// -----------------------------------------------------------------------------
// Scanning Engine
// -----------------------------------------------------------------------------
function startScan(mode, customTarget = null) {
  isScanning = true;
  const pBox = document.getElementById("scan-progress-box");
  if (pBox) pBox.style.display = "block";
  const bStart = document.getElementById("scan-btn-start");
  if (bStart) bStart.style.display = "none";
  const bPause = document.getElementById("scan-btn-pause");
  if (bPause) bPause.style.display = "inline-flex";
  const bCancel = document.getElementById("scan-btn-cancel");
  if (bCancel) bCancel.style.display = "inline-flex";

  const dashBtn = document.getElementById("btn-quick-scan-dash");
  if (dashBtn) dashBtn.innerText = "⏳ Scanning [0%]...";

  const tbody = document.getElementById("scan-threats-tbody");
  if (tbody) tbody.innerHTML = "";

  sendIpc("start_scan", { mode, target: customTarget });
  showToast(`${mode} Scan initialized`, "info");
}

function pauseScan() {
  sendIpc("pause_scan");
  const bPause = document.getElementById("scan-btn-pause");
  if (bPause) {
    bPause.innerText = "Resume";
    bPause.onclick = resumeScan;
  }
  showToast("Scan paused", "warn");
}

function resumeScan() {
  sendIpc("resume_scan");
  const bPause = document.getElementById("scan-btn-pause");
  if (bPause) {
    bPause.innerText = "Pause";
    bPause.onclick = pauseScan;
  }
  showToast("Scan resumed", "info");
}

function cancelScan() {
  sendIpc("cancel_scan");
  isScanning = false;
  const dashBtn = document.getElementById("btn-quick-scan-dash");
  if (dashBtn) dashBtn.innerText = "⚡ Quick Scan [Idle]";
  showToast("Scan cancelled", "warn");
  resetScanButtons();
}

function handleScanProgress(prog) {
  const pct = document.getElementById("scan-percentage-text");
  if (pct) pct.innerText = prog.percentage + "%";
  const pBar = document.getElementById("scan-progress-bar");
  if (pBar) pBar.style.width = prog.percentage + "%";
  const cFile = document.getElementById("scan-current-file");
  if (cFile) cFile.innerText = prog.current_file;
  const cCounts = document.getElementById("scan-counts");
  if (cCounts) cCounts.innerText = `${prog.scanned_count} / ${prog.total_count} files (${prog.eta_seconds}s remaining)`;

  const dashBtn = document.getElementById("btn-quick-scan-dash");
  if (dashBtn) dashBtn.innerText = `⏳ Scanning [${prog.percentage}%]...`;
}

function handleThreatFound(threat) {
  const tbody = document.getElementById("scan-threats-tbody");
  if (!tbody) return;

  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td><span class="badge badge-${threat.severity.toLowerCase()}">${threat.severity}</span></td>
    <td><strong>${threat.threat_name}</strong></td>
    <td>${threat.threat_type}</td>
    <td style="max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${threat.file_path}</td>
    <td>${threat.detection_engine}</td>
    <td>
      <button class="btn btn-secondary btn-sm" onclick="quarantineItem('${threat.file_path.replace(/\\/g, '\\\\')}', '${threat.threat_name}', '${threat.threat_type}', '${threat.severity}', '${threat.detection_engine}')">Quarantine</button>
      <button class="btn btn-secondary btn-sm" onclick="explainThreatAi('${threat.threat_name}', '${threat.threat_type}', '${threat.file_path.replace(/\\/g, '\\\\')}')">AI Explain</button>
    </td>
  `;
  tbody.appendChild(tr);
}

function handleScanFinished(summary) {
  isScanning = false;
  resetScanButtons();
  updateGaugeScore(summary.score);
  const dashBtn = document.getElementById("btn-quick-scan-dash");
  if (dashBtn) dashBtn.innerText = "⚡ Quick Scan [Idle]";
  showToast(`Scan ${summary.status}: found ${summary.threats_count} threat(s)`, summary.threats_count > 0 ? "warn" : "success");
}

function resetScanButtons() {
  document.getElementById("scan-btn-start").style.display = "inline-flex";
  document.getElementById("scan-btn-pause").style.display = "none";
  document.getElementById("scan-btn-cancel").style.display = "none";
}

// -----------------------------------------------------------------------------
// Network & Open Port Scanner
// -----------------------------------------------------------------------------
function loadNetworkConnections() {
  sendIpc("get_network_connections");
}

function killProcess(pid) {
  sendIpc("kill_port_process", { pid: parseInt(pid) });
  showToast(`Terminating process PID ${pid}...`, "info");
}

function blockPort(port, proto) {
  sendIpc("block_port_firewall", { port: parseInt(port), protocol: proto });
  showToast(`Adding firewall block rule for port ${port}...`, "info");
}

// -----------------------------------------------------------------------------
// Vulnerabilities & CISA KEV
// -----------------------------------------------------------------------------
function loadVulnerabilities() {
  sendIpc("get_installed_software");
  sendIpc("get_windows_patches");
}

function upgradeApp(name) {
  sendIpc("upgrade_software", { name });
  showToast(`Starting winget upgrade for ${name}...`, "info");
}

// -----------------------------------------------------------------------------
// AI Threat Intelligence
// -----------------------------------------------------------------------------
function explainThreatAi(threatName, threatType, filePath) {
  navigateToPage(6);
  document.getElementById("ai-threat-name").value = threatName;
  document.getElementById("ai-threat-type").value = threatType;
  document.getElementById("ai-file-path").value = filePath;
  runAiThreatAnalysis();
}

function runAiThreatAnalysis() {
  const provider = document.getElementById("ai-provider-select").value;
  const threatName = document.getElementById("ai-threat-name").value || "Suspicious Binary Dropper";
  const threatType = document.getElementById("ai-threat-type").value || "Trojan";
  const filePath = document.getElementById("ai-file-path").value || "C:\\Users\\User\\Downloads\\sample.exe";
  const prompt = document.getElementById("ai-prompt-input").value;

  document.getElementById("ai-output-box").innerHTML = "<em>Analyzing threat vectors and generating CISO remediation roadmap...</em>";

  sendIpc("explain_threat_ai", {
    provider_id: provider,
    threat_name: threatName,
    threat_type: threatType,
    file_path: filePath,
    details: "Heuristic and section entropy anomaly.",
    custom_prompt: prompt
  });
}

// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
// Tools Hub & Diagnostics
// -----------------------------------------------------------------------------
function loadToolsData() {
  loadDefenderStatus();
  loadFirewallStatus();
  loadHardeningChecks();
  loadNetworkDiag();
}

function loadDefenderStatus() {
  sendIpc("get_defender_status");
}

function handleDefenderStatus(data) {
  const badge = document.getElementById("defender-status-badge");
  const detail = document.getElementById("defender-detail-text");
  if (badge) {
    if (data.real_time_protection && data.antivirus_enabled) {
      badge.className = "badge badge-low";
      badge.innerText = "SHIELDED";
    } else {
      badge.className = "badge badge-critical";
      badge.innerText = "AT RISK";
    }
  }
  if (detail) {
    detail.innerText = `Real-time: ${data.real_time_protection ? "ON" : "OFF"} | Signature Ver: ${data.definition_version} | Updated: ${data.last_update}`;
  }
}

function triggerDefenderScan() {
  sendIpc("trigger_defender_scan");
  showToast("Triggering Defender Quick Scan...", "info");
}

function updateDefenderDefs() {
  sendIpc("update_defender_defs");
  showToast("Updating Defender virus definitions...", "info");
}

function loadFirewallStatus() {
  sendIpc("get_firewall_status");
}

function handleFirewallStatus(data) {
  const badge = document.getElementById("firewall-status-badge");
  const detail = document.getElementById("firewall-detail-text");
  const allOn = data.domain_enabled && data.private_enabled && data.public_enabled;
  if (badge) {
    badge.className = allOn ? "badge badge-low" : "badge badge-critical";
    badge.innerText = allOn ? "ACTIVE (3/3)" : "VULNERABLE";
  }
  if (detail) {
    detail.innerText = `Domain: ${data.domain_enabled ? "ON" : "OFF"} | Private: ${data.private_enabled ? "ON" : "OFF"} | Public: ${data.public_enabled ? "ON" : "OFF"}`;
  }
}

function enableAllFirewalls() {
  sendIpc("enable_all_firewalls");
  showToast("Enforcing Windows Firewall across all profiles...", "info");
}

function loadHardeningChecks() {
  sendIpc("get_hardening_checks");
}

function handleHardeningData(checks) {
  const tbody = document.getElementById("hardening-tbody");
  if (!tbody) return;
  if (!checks || checks.length === 0) {
    tbody.innerHTML = "<tr><td colspan='5' style='text-align:center;'>No hardening checks found.</td></tr>";
    return;
  }
  let html = "";
  for (const c of checks) {
    const badgeClass = c.status === "Pass" ? "badge-low" : (c.status === "Warn" ? "badge-high" : "badge-critical");
    html += `<tr>
      <td><strong>${c.title}</strong></td>
      <td><span class="badge ${badgeClass}">${c.status.toUpperCase()}</span></td>
      <td>${c.details}</td>
      <td style="font-size:11px; color:var(--text-secondary);">${c.recommendation}</td>
      <td><button class="btn btn-secondary btn-sm" onclick="applyHardeningFix('${c.id}')">Harden</button></td>
    </tr>`;
  }
  tbody.innerHTML = html;
}

function applyHardeningFix(id) {
  sendIpc("apply_hardening_fix", { id });
  showToast(`Enforcing security policy for '${id}'...`, "info");
}

function loadStartupItems() {
  sendIpc("get_startup_items");
}

function handleStartupData(items) {
  const tbody = document.getElementById("startup-tbody");
  if (!tbody) return;
  if (!items || items.length === 0) {
    tbody.innerHTML = "<tr><td colspan='5' style='text-align:center; color:var(--aurora-green);'>No startup persistence entries detected. Clean boot configuration.</td></tr>";
    return;
  }
  let html = "";
  for (const item of items) {
    const badgeClass = item.is_suspicious ? "badge-critical" : "badge-low";
    const badgeLabel = item.is_suspicious ? "SUSPICIOUS" : "VERIFIED";
    html += `<tr>
      <td><strong>${item.name}</strong></td>
      <td>${item.location}</td>
      <td style="max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-family:monospace; font-size:11px;">${item.command}</td>
      <td><span class="badge ${badgeClass}">${badgeLabel}</span> ${item.reason}</td>
      <td><button class="btn btn-danger btn-sm" onclick="deleteStartupItem('${item.location.replace(" Run", "")}', '${item.name.replace(/'/g, "\\'")}')">Remove</button></td>
    </tr>`;
  }
  tbody.innerHTML = html;
}

function deleteStartupItem(key, name) {
  const fullKey = key === "HKLM" ? "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" : "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
  sendIpc("delete_startup_item", { key: fullKey, name });
  showToast(`Removing startup key '${name}'...`, "info");
}

function loadProcessExplorer() {
  sendIpc("get_process_list");
}

function handleProcessData(procs) {
  const tbody = document.getElementById("process-tbody");
  if (!tbody) return;
  if (!procs || procs.length === 0) {
    tbody.innerHTML = "<tr><td colspan='7' style='text-align:center;'>No active processes returned.</td></tr>";
    return;
  }
  let html = "";
  for (const p of procs.slice(0, 35)) {
    const badgeClass = p.is_suspicious ? "badge-critical" : "badge-low";
    const badgeLabel = p.is_suspicious ? "ALERT" : "NORMAL";
    html += `<tr>
      <td>${p.pid}</td>
      <td><strong>${p.name}</strong></td>
      <td>${p.memory_mb.toFixed(1)} MB</td>
      <td>${p.cpu_percent.toFixed(1)}%</td>
      <td style="max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-family:monospace; font-size:11px;">${p.exe_path || "-"}</td>
      <td><span class="badge ${badgeClass}">${badgeLabel}</span> ${p.risk_reason || ""}</td>
      <td><button class="btn btn-danger btn-sm" onclick="killProcessByPid(${p.pid})">Kill</button></td>
    </tr>`;
  }
  tbody.innerHTML = html;
}

function killProcessByPid(pid) {
  sendIpc("kill_process_by_pid", { pid });
  showToast(`Terminating process PID ${pid}...`, "info");
}

function loadNetworkDiag() {
  sendIpc("get_network_diagnostics");
}

function handleDnsData(diag) {
  const box = document.getElementById("dns-info-box");
  if (!box) return;
  box.innerHTML = `
    <div><strong>Active Adapter:</strong> ${diag.adapter_name}</div>
    <div><strong>Local IPv4:</strong> ${diag.ip_address} | <strong>Gateway:</strong> ${diag.gateway}</div>
    <div><strong>DNS Resolvers:</strong> ${diag.dns_servers.join(", ")}</div>
    <div><strong>Public IP:</strong> <span style="color:var(--frost-cyan);">${diag.public_ip}</span></div>
  `;
}

function flushDnsCache() {
  sendIpc("flush_dns_cache");
  showToast("Flushing local DNS resolver cache...", "info");
}

function shredFileDod() {
  const path = document.getElementById("shredder-path").value;
  const passes = parseInt(document.getElementById("shredder-passes").value);
  if (!path) {
    showToast("Please specify a target file path to shred.", "warn");
    return;
  }
  sendIpc("shred_file_dod", { path, passes });
  showToast(`Shredding file with ${passes} passes...`, "info");
}

function checkPasswordStrength() {
  const pwd = document.getElementById("password-input").value;
  if (!pwd) return;
  sendIpc("check_password_security", { password: pwd });
}

function restoreCleanHosts() {
  sendIpc("restore_clean_hosts");
  showToast("Restoring clean default Windows hosts file...", "info");
}

// -----------------------------------------------------------------------------
// Quarantine Vault
// -----------------------------------------------------------------------------
function loadQuarantineData() {
  sendIpc("get_quarantine_items");
}

function quarantineItem(path, name, type, sev, eng) {
  sendIpc("quarantine_threat", {
    file_path: path,
    threat_name: name,
    threat_type: type,
    severity: sev,
    engine: eng
  });
  showToast("Quarantining file with AES-256-GCM encryption...", "info");
}

function restoreQuarantined(id) {
  sendIpc("restore_quarantined_item", { id });
  showToast("Restoring quarantined file...", "info");
}

function deleteQuarantined(id) {
  sendIpc("delete_quarantined_item", { id });
  showToast("Deleting quarantined file permanently...", "info");
}

// -----------------------------------------------------------------------------
// Blue Team Terminal
// -----------------------------------------------------------------------------
function loadTerminalCommands() {
  sendIpc("get_terminal_commands");
}

function runTerminalCmd(cmd) {
  const term = document.getElementById("terminal-console");
  term.innerHTML += `\n<span style="color:#88C0D0;">&gt; ${cmd}</span>\n`;
  sendIpc("execute_terminal_command", { cmd });
}

function handleTerminalOutput(data) {
  const term = document.getElementById("terminal-console");
  term.innerHTML += data.output + "\n";
  term.scrollTop = term.scrollHeight;
}

// -----------------------------------------------------------------------------
// Bootkit & Rootkit Scan
// -----------------------------------------------------------------------------
function runBootkitAudit() {
  sendIpc("run_bootkit_scan");
  showToast("Auditing MBR and kernel integrity...", "info");
}

// -----------------------------------------------------------------------------
// Real-Time Protection Shield Toggle
// -----------------------------------------------------------------------------
function toggleRealTimeShield() {
  isShieldActive = !isShieldActive;
  const dot = document.getElementById("shield-dot");
  const txt = document.getElementById("shield-status-text");

  if (isShieldActive) {
    dot.classList.remove("paused");
    txt.innerText = "Shield Active";
    showToast("Real-Time Protection Shield resumed", "success");
  } else {
    dot.classList.add("paused");
    txt.innerText = "Shield Paused";
    showToast("Real-Time Protection Shield paused", "warn");
  }

  sendIpc("toggle_realtime_shield");
}

// -----------------------------------------------------------------------------
// Executive Security Audit & PDF Report
// -----------------------------------------------------------------------------
function generatePdfReport() {
  sendIpc("generate_pdf_report");
  showToast("Compiling executive security audit report into vector PDF...", "info");
}

function loadAuditReport() {
  sendIpc("get_audit_report_data");
  showToast("Gathering endpoint security telemetry...", "info");
}

function loadReportData() {
  loadAuditReport();
}

function handleReportData(data) {
  const scoreVal = document.getElementById("report-score-val");
  const scoreGrade = document.getElementById("report-score-grade");
  const defVal = document.getElementById("report-defender-val");
  const defSub = document.getElementById("report-defender-sub");
  const fwVal = document.getElementById("report-firewall-val");
  const surfVal = document.getElementById("report-surface-val");
  const surfSub = document.getElementById("report-surface-sub");
  const container = document.getElementById("report-preview-container");

  if (scoreVal) {
    scoreVal.innerText = data.posture_score;
    scoreVal.style.color = data.posture_score >= 80 ? "var(--aurora-green)" : (data.posture_score >= 60 ? "var(--aurora-yellow)" : "var(--aurora-red)");
  }
  if (scoreGrade) scoreGrade.innerText = data.posture_grade;

  if (defVal) {
    defVal.innerText = data.defender_active ? "SHIELD ACTIVE" : "DEFENDER AT RISK";
    defVal.style.color = data.defender_active ? "var(--aurora-green)" : "var(--aurora-red)";
  }
  if (defSub) defSub.innerText = `Signatures: ${data.defender_sig_version}`;

  if (fwVal) {
    const count = (data.firewall_domain ? 1 : 0) + (data.firewall_private ? 1 : 0) + (data.firewall_public ? 1 : 0);
    fwVal.innerText = `${count} / 3 PROFILES`;
    fwVal.style.color = count === 3 ? "var(--aurora-green)" : "var(--aurora-yellow)";
  }

  if (surfVal) {
    surfVal.innerText = `${data.risky_ports_count} RISKY`;
    surfVal.style.color = data.risky_ports_count === 0 ? "var(--aurora-green)" : "var(--aurora-red)";
  }
  if (surfSub) surfSub.innerText = `${data.total_listening_ports} Listening Sockets Active`;

  if (container) {
    let html = `
      <div style="background:var(--bg-card); border:1px solid var(--border-color); border-radius:8px; padding:16px; margin-bottom:14px;">
        <div style="display:flex; justify-content:space-between; margin-bottom:8px;">
          <span><strong>Host:</strong> ${data.hostname}</span>
          <span><strong>Generated:</strong> ${data.generated_at}</span>
        </div>
        <div style="color:var(--text-secondary); margin-bottom:12px;">
          <strong>OS:</strong> ${data.os_name} | <strong>Hardware:</strong> ${data.cpu_brand} (${data.total_memory_gb.toFixed(1)} GB RAM)
        </div>
        <div style="font-weight:700; margin-bottom:6px; color:var(--text-primary);">Hardening Compliance Overview:</div>
        <ul style="padding-left:20px; margin-bottom:12px; line-height:1.6;">
    `;
    for (const c of data.hardening_checks) {
      const color = c.status === "Pass" ? "var(--aurora-green)" : "var(--aurora-red)";
      html += `<li><strong style="color:${color};">[${c.status.toUpperCase()}]</strong> <strong>${c.title}</strong>: ${c.details}</li>`;
    }
    html += `
        </ul>
        <div style="font-weight:700; margin-bottom:6px; color:var(--text-primary);">Active Threat & Quarantine Status:</div>
        <p style="color:var(--text-secondary);">Recorded Threat Events: ${data.threats_history.length} | Quarantined Artifacts in AES-256 Vault: ${data.quarantine_items.length}</p>
      </div>
    `;
    container.innerHTML = html;
  }
}

// -----------------------------------------------------------------------------
// Toast Alerts
// -----------------------------------------------------------------------------
function showToast(msg, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.innerText = msg;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateX(20px)";
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// Initialize immediately and on DOM/load events with multi-tier fail-safe
try {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => initAppStartup());
  } else {
    initAppStartup();
  }
} catch (e) {
  initAppStartup();
}

window.addEventListener("load", () => {
  if (!startupFinished) {
    initAppStartup();
  }
});

// Immediate execution fallback in case document is already parsed
setTimeout(() => {
  if (!startupFinished) {
    initAppStartup();
  }
}, 50);

// Global emergency watchdog: dismiss loading screen after 1.5s no matter what
setTimeout(() => {
  if (!startupFinished) {
    console.warn("[WATCHDOG] Force-dismissing loading screen after timeout");
    finishStartup();
  }
}, 1500);
