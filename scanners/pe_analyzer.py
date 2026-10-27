"""
Fikrado Security - Portable Executable (PE) & Heuristics Analyzer
Inspects PE headers, section entropy, packed indicators, suspicious import clusters, and digital signatures.
"""
import math
import os
from typing import Dict, List, Optional
from config.security_rules import SUSPICIOUS_PE_IMPORTS
from core.logger import logger

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False
    logger.warning("pefile module not found. PE static analysis will be limited.")


def calculate_entropy(data: bytes) -> float:
    """Computes Shannon entropy (0.0 to 8.0) of a byte sequence."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    occurrences = [0] * 256
    for b in data:
        occurrences[b] += 1
    for count in occurrences:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


class PEAnalyzer:
    """Analyzes Windows PE executables for heuristic threat indicators."""

    def __init__(self, entropy_threshold: float = 7.2):
        self.entropy_threshold = entropy_threshold

    def analyze(self, file_path: str) -> List[dict]:
        """
        Runs comprehensive heuristic analysis on an executable (.exe, .dll, .sys).
        Returns a list of threat finding dicts if anomalies or high-risk indicators are found.
        """
        findings = []
        if not HAS_PEFILE:
            return findings

        # Check extension
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in (".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"):
            return findings

        try:
            pe = pefile.PE(file_path, fast_load=False)
        except Exception as e:
            # Corrupted or invalid PE
            logger.debug(f"pefile parsing failed for {file_path}: {e}")
            return findings

        try:
            # 1. Section Entropy & Packer Check
            packed_sections = []
            known_packer_sections = ["upx", "aspack", "pecompact", "themida", "vmprotect", "mew", "fsg"]
            for section in pe.sections:
                sec_name = section.Name.decode("utf-8", errors="ignore").strip("\x00").lower()
                sec_data = section.get_data()
                sec_entropy = calculate_entropy(sec_data)

                if sec_entropy > self.entropy_threshold:
                    packed_sections.append(f"{sec_name} (Entropy: {sec_entropy:.2f})")

                for kp in known_packer_sections:
                    if kp in sec_name:
                        findings.append({
                            "engine": "PE Packer Detector",
                            "threat_name": f"Suspicious Known Packer: {sec_name.upper()}",
                            "threat_type": "Suspicious",
                            "severity": "Medium",
                            "description": f"Executable is packed with {sec_name.upper()}, often used to evade antivirus detection.",
                            "file_path": file_path
                        })

            if len(packed_sections) >= 2:
                findings.append({
                    "engine": "PE Entropy Heuristics",
                    "threat_name": "High-Entropy Executable Sections (Packed/Encrypted)",
                    "threat_type": "Suspicious",
                    "severity": "Medium",
                    "description": f"Multiple high-entropy sections detected: {', '.join(packed_sections)}. Indicates packed or encrypted payload.",
                    "file_path": file_path
                })

            # 2. Suspicious Import Combinations
            imports_found = set()
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            name_str = imp.name.decode("utf-8", errors="ignore")
                            imports_found.add(name_str)

            # Check injection cluster
            injection_apis = [api for api in SUSPICIOUS_PE_IMPORTS["Process Injection & Memory Manipulation"] if api in imports_found]
            if len(injection_apis) >= 3:
                findings.append({
                    "engine": "PE Behavioral Heuristics",
                    "threat_name": "Process Injection Capabilities",
                    "threat_type": "Trojan",
                    "severity": "High",
                    "description": f"Executable imports high-risk process injection APIs: {', '.join(injection_apis)}.",
                    "file_path": file_path
                })

            # Check keylogging cluster
            keylog_apis = [api for api in SUSPICIOUS_PE_IMPORTS["Keylogging & Hooking"] if api in imports_found]
            if len(keylog_apis) >= 2:
                findings.append({
                    "engine": "PE Behavioral Heuristics",
                    "threat_name": "Keystroke Interception & Hooking",
                    "threat_type": "Keylogger",
                    "severity": "High",
                    "description": f"Executable imports keylogging APIs: {', '.join(keylog_apis)}.",
                    "file_path": file_path
                })

            # 3. Unsigned binary in System Paths Check
            norm_path = file_path.lower().replace("/", "\\")
            is_in_system = ("c:\\windows\\system32" in norm_path or "c:\\windows\\syswow64" in norm_path)
            if is_in_system:
                has_security_dir = False
                if hasattr(pe, "OPTIONAL_HEADER") and hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
                    security_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
                    if security_entry.VirtualAddress != 0 and security_entry.Size > 0:
                        has_security_dir = True

                if not has_security_dir:
                    findings.append({
                        "engine": "PE Signature Heuristics",
                        "threat_name": "Unsigned Executable in Windows System Directory",
                        "threat_type": "Suspicious",
                        "severity": "High",
                        "description": "Binary resides inside Windows system folder but lacks an embedded digital signature directory.",
                        "file_path": file_path
                    })

        except Exception as e:
            logger.debug(f"PE inspection error for {file_path}: {e}")
        finally:
            pe.close()

        return findings


pe_analyzer = PEAnalyzer()
