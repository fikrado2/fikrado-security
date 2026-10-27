"""
Fikrado Security - YARA Signature Engine
Compiles and scans files using YARA rules covering major malware families.
"""
from typing import List, Optional
from core.logger import logger

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False
    logger.warning("yara-python module not available, using built-in pattern matcher fallback.")

YARA_RULES_SOURCE = """
rule Ransomware_Generic_Indicators
{
    meta:
        description = "Detects generic ransomware indicators such as shadow copy deletion and ransom notes"
        threat_type = "Ransomware"
        severity = "Critical"
    strings:
        $s1 = "vssadmin.exe delete shadows" nocase ascii wide
        $s2 = "vssadmin delete shadows" nocase ascii wide
        $s3 = "bootstatuspolicy ignoreallfailures" nocase ascii wide
        $s4 = "recoveryenabled no" nocase ascii wide
        $s5 = "wbadmin delete catalog" nocase ascii wide
        $r1 = "YOUR FILES ARE ENCRYPTED" nocase ascii wide
        $r2 = "All your files have been encrypted" nocase ascii wide
        $r3 = "DECRYPT_FILES" nocase ascii wide
        $r4 = "decrypt_instruction" nocase ascii wide
        $r5 = "send bitcoin to" nocase ascii wide
    condition:
        2 of ($s*) or 1 of ($r*)
}

rule Trojan_Dropper_Obfuscated
{
    meta:
        description = "Detects malicious dropper and obfuscated PowerShell/Certutil payload loaders"
        threat_type = "Trojan"
        severity = "High"
    strings:
        $p1 = "powershell -enc" nocase ascii wide
        $p2 = "powershell -encodedcommand" nocase ascii wide
        $p3 = "-w hidden -nop -ep bypass" nocase ascii wide
        $c1 = "certutil -urlcache -split -f" nocase ascii wide
        $c2 = "certutil.exe -decode" nocase ascii wide
        $b1 = "bitsadmin /transfer" nocase ascii wide
        $d1 = "DownloadFile(" nocase ascii wide
        $d2 = "DownloadString(" nocase ascii wide
    condition:
        ($p1 and $d1) or ($p2 and $d2) or $p3 or 1 of ($c*) or $b1
}

rule Keylogger_Generic_Pattern
{
    meta:
        description = "Detects keylogger hooks, keystroke polling, and logging artifacts"
        threat_type = "Keylogger"
        severity = "High"
    strings:
        $k1 = "SetWindowsHookEx" ascii wide
        $k2 = "GetAsyncKeyState" ascii wide
        $k3 = "GetKeyboardState" ascii wide
        $k4 = "[Keylogger]" nocase ascii wide
        $k5 = "[Backspace]" nocase ascii wide
        $k6 = "[Enter]" nocase ascii wide
        $k7 = "keystrokes.txt" nocase ascii wide
    condition:
        ($k1 and $k2 and 1 of ($k4, $k5, $k6, $k7)) or
        (3 of ($k1, $k2, $k3, $k4, $k5, $k6, $k7))
}

rule Backdoor_RAT_Command_Control
{
    meta:
        description = "Detects Remote Access Trojans (RATs) and reverse shell mechanisms"
        threat_type = "RAT"
        severity = "Critical"
    strings:
        $r1 = "cmd.exe /c whoami" nocase ascii wide
        $r2 = "cmd.exe /c systeminfo" nocase ascii wide
        $r3 = "ReverseShell" nocase ascii wide
        $r4 = "RemoteDesktopClient" nocase ascii wide
        $r5 = "C2Server" nocase ascii wide
        $r6 = "AsyncRAT" nocase ascii wide
        $r7 = "QuasarServer" nocase ascii wide
        $r8 = "NanoCore" nocase ascii wide
        $r9 = "Remcos" nocase ascii wide
    condition:
        2 of ($r*)
}

rule Spyware_Infostealer_Credentials
{
    meta:
        description = "Detects infostealers targeting browsers, cryptocurrency wallets, and tokens"
        threat_type = "Spyware"
        severity = "High"
    strings:
        $b1 = "User Data/Default/Login Data" nocase ascii wide
        $b2 = "User Data/Local State" nocase ascii wide
        $b3 = "Edge/User Data/Default" nocase ascii wide
        $v1 = "vaultcli.dll" nocase ascii wide
        $v2 = "VaultEnumerateVaults" nocase ascii wide
        $d1 = "discord/Local Storage/leveldb" nocase ascii wide
        $t1 = "wallet.dat" nocase ascii wide
    condition:
        2 of ($b*) or ($v1 and $v2) or ($b1 and $d1) or ($b1 and $t1)
}

rule Worm_Propagation_Network
{
    meta:
        description = "Detects worm self-replication and autorun propagation"
        threat_type = "Worm"
        severity = "High"
    strings:
        $a1 = "[autorun]" nocase ascii wide
        $a2 = "open=setup.exe" nocase ascii wide
        $s1 = "IPC$" nocase ascii wide
        $s2 = "ADMIN$" nocase ascii wide
        $s3 = "C$" nocase ascii wide
        $w1 = "NetShareEnum" ascii wide
    condition:
        ($a1 and $a2) or ($w1 and 1 of ($s*))
}

rule Adware_PUP_Injector
{
    meta:
        description = "Detects adware injectors, unauthorized toolbars, and search hijackers"
        threat_type = "PUP"
        severity = "Low"
    strings:
        $ad1 = "InjectAdScript" nocase ascii wide
        $ad2 = "SearchHijack" nocase ascii wide
        $ad3 = "OffersWizard" nocase ascii wide
        $ad4 = "Adware.Toolbar" nocase ascii wide
        $ad5 = "InstallBundleOption" nocase ascii wide
    condition:
        1 of ($ad*)
}

rule Rootkit_Indicator_Driver
{
    meta:
        description = "Detects rootkit drivers, SSDT manipulation, and process hiding hooks"
        threat_type = "Rootkit"
        severity = "Critical"
    strings:
        $rk1 = "ZwQuerySystemInformation" ascii wide
        $rk2 = "KeServiceDescriptorTable" ascii wide
        $rk3 = "ObRegisterCallbacks" ascii wide
        $rk4 = "PhysicalMemory" ascii wide
        $rk5 = "DKOM" nocase ascii wide
        $rk6 = "HideProcess" nocase ascii wide
    condition:
        2 of ($rk*)
}

rule EICAR_Standard_Test_File
{
    meta:
        description = "Standard Antivirus Test File"
        threat_type = "Test Virus"
        severity = "Critical"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" ascii
    condition:
        $eicar
}
"""


class YaraEngine:
    """Manages YARA rule compilation and scanning."""

    def __init__(self):
        self.rules = None
        self._compiled = False
        self._init_rules()

    def _init_rules(self):
        if not HAS_YARA:
            return
        try:
            self.rules = yara.compile(source=YARA_RULES_SOURCE)
            self._compiled = True
            logger.info("Successfully compiled built-in YARA malware rules.")
        except Exception as e:
            logger.error(f"YARA rule compilation failed: {e}")
            self._compiled = False

    def scan_file(self, file_path: str) -> List[dict]:
        """Scans a file against compiled YARA rules."""
        findings = []
        if not self._compiled or not self.rules:
            return self._fallback_scan(file_path)

        try:
            matches = self.rules.match(file_path, timeout=5)
            for m in matches:
                rule_name = m.rule
                meta = m.meta or {}
                findings.append({
                    "engine": "YARA Engine",
                    "threat_name": rule_name.replace("_", " "),
                    "threat_type": meta.get("threat_type", "Malware"),
                    "severity": meta.get("severity", "High"),
                    "description": meta.get("description", "Matched YARA pattern"),
                    "file_path": file_path
                })
        except Exception as e:
            logger.debug(f"YARA scan error on {file_path}: {e}")

        return findings

    def _fallback_scan(self, file_path: str) -> List[dict]:
        """Pure-Python basic string fallback matcher if yara is unavailable."""
        findings = []
        try:
            with open(file_path, "rb") as f:
                content = f.read(512 * 1024)

            if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" in content:
                findings.append({
                    "engine": "Fallback Pattern Matcher",
                    "threat_name": "EICAR Standard AV Test String",
                    "threat_type": "Test Virus",
                    "severity": "Critical",
                    "description": "Standard EICAR antivirus test file detected",
                    "file_path": file_path
                })

            if b"vssadmin" in content.lower() and b"delete shadows" in content.lower():
                findings.append({
                    "engine": "Fallback Pattern Matcher",
                    "threat_name": "Ransomware Shadow Deletion",
                    "threat_type": "Ransomware",
                    "severity": "Critical",
                    "description": "Attempted shadow copy deletion pattern detected",
                    "file_path": file_path
                })
        except Exception:
            pass

        return findings


yara_engine = YaraEngine()
