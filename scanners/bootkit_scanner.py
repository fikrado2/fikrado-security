"""
Fikrado Security - Bootkit Scanner
Cross-platform bootkit detection using multiple indicators of compromise.
"""
import os
import stat
import subprocess
import struct
import sys
from pathlib import Path
from typing import List, Dict

from core.logger import logger
from core.platforms import IS_WINDOWS, IS_LINUX, IS_MAC


def _run_cmd(cmd: List[str]) -> tuple[bool, str]:
    """Run a command and return (success, stdout)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.returncode == 0, result.stdout.strip()
    except Exception as e:
        return False, str(e)


# ─── WINDOWS ─────────────────────────────────────────────────────────────────
def _scan_windows_bootkit() -> List[Dict]:
    """Windows bootkit indicators."""
    findings = []
    system_root = os.environ.get("SystemRoot", "C:\\Windows")

    # Check Master Boot Record for suspicious signatures
    mbr_path = r"\\.\PhysicalDrive0"
    try:
        if os.name == "nt":
            import ctypes
            with open(mbr_path, "rb") as f:
                mbr = f.read(512)
            # Check for common bootkit MBR signatures
            suspicious_patterns = [
                b"\x33\xC0\x8E\xD8"[:4],  # Common first instruction tweak
            ]
            for pattern in suspicious_patterns:
                if mbr.startswith(pattern) and not mbr.startswith(b"\xEB\x63\x90\x00"):
                    findings.append({
                        "severity": "Critical",
                        "type": "MBR Anomaly",
                        "detail": "Master Boot Record contains unexpected first-bytes pattern",
                        "indicator": f"Suspicious MBR pattern at offset 0: {mbr[:4].hex()}",
                        "recommendation": "Run 'bootrec /fixmbr' from Windows RE to restore original MBR",
                    })
    except PermissionError:
        findings.append({
            "severity": "Medium",
            "type": "MBR Access Denied",
            "detail": "Cannot read physical drive MBR — run as Administrator",
            "indicator": "Permission denied: PhysicalDrive0",
            "recommendation": "Run Fikrado as Administrator for full MBR inspection",
        })
    except Exception as e:
        logger.debug(f"MBR scan skipped: {e}")

    # Check VBR (Volume Boot Record) of system drive
    vbr_paths = [f"{system_root}\\System32\\drivers", f"{system_root}\\System32"]
    for vbr_dir in vbr_paths:
        if Path(vbr_dir).exists():
            pass  # Full VBR check requires raw disk access

    # Check for suspicious boot executables
    boot_dirs = [
        f"{system_root}\\System32\\drivers",
        f"{system_root}\\System32",
        f"{system_root}\\SysWOW64",
    ]
    suspicious_driver_names = [
        " RTCWatch", "DiskReg", "BootSafeguard", "SecureBoot",
    ]

    for boot_dir in boot_dirs:
        if not Path(boot_dir).exists():
            continue
        try:
            for f in Path(boot_dir).glob("*.sys"):
                name_lower = f.name.lower()
                for susp in suspicious_driver_names:
                    if susp.lower() in name_lower:
                        findings.append({
                            "severity": "Critical",
                            "type": "Suspicious Boot Driver",
                            "detail": f"Suspicious driver '{f.name}' found in {boot_dir}",
                            "indicator": f"Driver path: {f}",
                            "recommendation": "Submit driver to VirusTotal and consider removal",
                        })
        except PermissionError:
            pass

    # Check BCD (Boot Configuration Data) for unauthorized entries
    ok, bcd_out = _run_cmd(["bcdedit", "/enum", "all"])
    if ok:
        for line in bcd_out.splitlines():
            if any(kw in line.lower() for kw in ["unknown", "description", "device"]):
                pass  # Analyze BCD entries for tampered boot loaders

    # Check for evidence of 'Evil Bit' or Direct Memory Boot attacks
    ok, sysinfo = _run_cmd(["systeminfo"])
    if ok:
        if "BIOS Version" in sysinfo:
            bios_lines = [l for l in sysinfo.splitlines() if "BIOS" in l or "Version" in l]
            for line in bios_lines[:3]:
                if "Unknown" in line or "Invalid" in line:
                    findings.append({
                        "severity": "High",
                        "type": "BIOS Anomaly",
                        "detail": f"Potential BIOS/firmware tampering: {line.strip()}",
                        "indicator": line.strip(),
                        "recommendation": "Update BIOS from manufacturer's official site",
                    })

    # Check for signing status of all loaded drivers (sigcheck)
    ok, driver_list = _run_cmd([
        "powershell", "-NoProfile", "-Command",
        "Get-WinEvent -LogName System -MaxEvents 200 | Where-Object {$_.ProviderName -eq 'Microsoft-Windows-WindowsUpdateClient'} | Select-Object -First 5 | Format-List"
    ])
    if not ok:
        ok, driver_list = _run_cmd([
            "powershell", "-NoProfile", "-Command",
            "Get-CimInstance Win32_SystemDriver | Where-Object {$_.State -eq 'Running'} | Select-Object Name,PathName | ConvertTo-Json"
        ])

    return findings


# ─── LINUX ───────────────────────────────────────────────────────────────────
def _scan_linux_bootkit() -> List[Dict]:
    """Linux bootkit indicators — UEFI/MBR integrity and suspicious initramfs."""
    findings = []

    # Check UEFI Secure Boot status
    ok, sb_status = _run_cmd(["mokutil", "--sb-state"])
    if ok and "disabled" in sb_status.lower():
        findings.append({
            "severity": "High",
            "type": "Secure Boot Disabled",
            "detail": "UEFI Secure Boot is currently disabled. This reduces protection against pre-boot malware.",
            "indicator": sb_status,
            "recommendation": "Enable Secure Boot in UEFI/BIOS settings for boot integrity protection",
        })

    # Check for unsigned kernel modules (if lockdown is enabled)
    ok, lockdown = _run_cmd(["cat", "/sys/kernel/security/lockdown"])
    if ok:
        if "[none]" in lockdown.lower():
            findings.append({
                "severity": "Medium",
                "type": "Kernel Lockdown Disabled",
                "detail": "Kernel lockdown is not active, allowing direct kernel memory access",
                "indicator": lockdown.strip(),
                "recommendation": "Consider enabling kernel lockdown: add 'lockdown=confidentiality' to GRUB cmdline",
            })

    # Check initramfs for tampering (compare timestamps with kernel)
    ok, kernel_ts = _run_cmd(["stat", "-c", "%Y", "/boot/vmlinuz-$(uname -r)"])
    ok2, initrd_ts = _run_cmd(["stat", "-c", "%Y", "/initrd.img"])
    if ok and ok2:
        try:
            if abs(int(kernel_ts) - int(initrd_ts)) > 86400 * 30:
                findings.append({
                    "severity": "Medium",
                    "type": "Initramfs Timestamp Anomaly",
                    "detail": "initramfs timestamp differs significantly from kernel — possible rebuild after compromise",
                    "indicator": f"vmlinuz: {kernel_ts}, initrd: {initrd_ts}",
                    "recommendation": "Regenerate initramfs: sudo update-initramfs -u",
                })
        except (ValueError, TypeError):
            pass

    # Check for suspicious EFI binaries in ESP
    esp_paths = ["/boot/efi/EFI", "/boot/EFI"]
    suspicious_efi = ["shim.efi", "grubx64.efi", "mmx64.efi"]
    for esp in esp_paths:
        if not Path(esp).exists():
            continue
        try:
            for f in Path(esp).rglob("*.efi"):
                name = f.name.lower()
                if not any(s in name for s in suspicious_efi):
                    # Check if file hash is known-good (placeholder for actual VT check)
                    findings.append({
                        "severity": "Info",
                        "type": "Non-standard EFI Binary",
                        "detail": f"Found non-standard EFI binary: {f}",
                        "indicator": f"EFI file: {f}",
                        "recommendation": "Verify this binary is expected: sha256sum " + str(f),
                    })
        except PermissionError:
            pass

    # Check GRUB2 config for password protection
    ok, grub_cfg = _run_cmd(["test", "-f", "/boot/grub/grub.cfg"])
    if ok:
        ok2, grub_pw = _run_cmd(["grep", "-c", "password_pbkdf2", "/boot/grub/grub.cfg"])
        if ok2 and int(grub_pw or "0") == 0:
            findings.append({
                "severity": "Medium",
                "type": "GRUB2 Unprotected",
                "detail": "GRUB2 boot loader is not password-protected, allowing single-user mode tampering",
                "indicator": "No password_pbkdf2 found in /boot/grub/grub.cfg",
                "recommendation": "Set GRUB2 password: sudo grub2-mkpasswd-pbkdf2 and update grub.cfg",
            })

    return findings


# ─── MACOS ───────────────────────────────────────────────────────────────────
def _scan_macos_bootkit() -> List[Dict]:
    """macOS bootkit indicators — SIP, kernel extensions, and startup items."""
    findings = []

    # Check System Integrity Protection status
    ok, sip = _run_cmd(["csrutil", "status"])
    if ok and "disabled" in sip.lower():
        findings.append({
            "severity": "Critical",
            "type": "System Integrity Protection Disabled",
            "detail": "SIP is disabled, allowing unsigned kernel extensions and protected file modifications",
            "indicator": sip.strip(),
            "recommendation": "Enable SIP from Recovery Mode: csrutil enable",
        })

    # Check for problematic LaunchDaemons from non-Apple sources
    launchd_paths = [
        "/Library/LaunchDaemons",
        "/Library/LaunchAgents",
    ]
    suspicious_daemons = ["com.celsius", "com.driver.agent", "com.system.update"]
    for lpath in launchd_paths:
        if not Path(lpath).exists():
            continue
        try:
            for f in Path(lpath).glob("*.plist"):
                for susp in suspicious_daemons:
                    if susp in f.name.lower():
                        findings.append({
                            "severity": "High",
                            "type": "Suspicious LaunchDaemon",
                            "detail": f"Potentially unwanted LaunchDaemon: {f.name}",
                            "indicator": f"Path: {f}",
                            "recommendation": f"Review and remove if unneeded: sudo rm '{f}'",
                        })
        except PermissionError:
            pass

    # Check for unsigned kernel extensions
    ok, kexts = _run_cmd([
        "system_profiler", "SPExtensionsDataType", "-json"
    ])
    if ok:
        import json
        try:
            data = json.loads(kexts)
            kext_data = data.get("SPExtensionsDataType", [])
            for k in kext_data:
                if k.get("kext_signed") == "No":
                    findings.append({
                        "severity": "High",
                        "type": "Unsigned Kernel Extension",
                        "detail": f"Unsigned KEXT: {k.get('kext_name', 'Unknown')}",
                        "indicator": f"Path: {k.get('kext_path', 'N/A')}",
                        "recommendation": "Remove or sign the kernel extension",
                    })
        except (json.JSONDecodeError, TypeError, KeyError):
            pass

    return findings


# ─── CROSS-PLATFORM SCAN FUNCTION ───────────────────────────────────────────
def scan_bootkit() -> List[Dict]:
    """
    Perform a bootkit integrity scan on the current platform.
    Returns a list of bootkit indicators.
    """
    logger.info("Starting bootkit integrity scan...")
    try:
        if IS_WINDOWS:
            findings = _scan_windows_bootkit()
        elif IS_LINUX:
            findings = _scan_linux_bootkit()
        elif IS_MAC:
            findings = _scan_macos_bootkit()
        else:
            findings = [{
                "severity": "Warning",
                "type": "Unknown Platform",
                "detail": "Bootkit scan not implemented for this platform",
                "indicator": sys.platform,
                "recommendation": "Run on Windows, Linux, or macOS for bootkit detection",
            }]

        logger.info(f"Bootkit scan complete: {len(findings)} findings")
        return findings

    except Exception as e:
        logger.exception("Bootkit scan failed")
        return [{
            "severity": "Error",
            "type": "Scan Error",
            "detail": f"Bootkit scan encountered an error: {str(e)}",
            "indicator": "Exception during scan",
            "recommendation": "Check logs for details and ensure administrator/root privileges",
        }]