"""
Fikrado Security - Security Rules, Port Catalog, and Suspicious Patterns
"""

# Common risky ports with plain-language security descriptions
RISKY_PORTS = {
    21: {
        "service": "FTP (File Transfer Protocol)",
        "severity": "Medium",
        "description": "Unencrypted file transfers. Passwords and data are transmitted in cleartext over the network.",
        "recommendation": "Disable unless strictly necessary or migrate to SFTP/FTPS."
    },
    23: {
        "service": "Telnet",
        "severity": "Critical",
        "description": "Legacy unencrypted remote terminal protocol. All credentials and commands are visible to network sniffers.",
        "recommendation": "Immediately disable Telnet service and switch to SSH."
    },
    25: {
        "service": "SMTP (Simple Mail Transfer)",
        "severity": "Low",
        "description": "Mail server port. If exposed unexpectedly, it may indicate a local spam bot or open mail relay.",
        "recommendation": "Verify if a legitimate mail service is running; block external inbound access."
    },
    135: {
        "service": "Microsoft RPC Endpoint Mapper",
        "severity": "High",
        "description": "Windows Remote Procedure Call. Frequently exploited by worms (like Blaster) for remote code execution.",
        "recommendation": "Block port 135 on the firewall for all external interfaces."
    },
    137: {
        "service": "NetBIOS Name Service",
        "severity": "Medium",
        "description": "Legacy Windows networking name resolution. Can leak machine names and workgroup metadata.",
        "recommendation": "Disable NetBIOS over TCP/IP in your network adapter properties."
    },
    139: {
        "service": "NetBIOS Session Service",
        "severity": "High",
        "description": "Legacy file and printer sharing. Susceptible to enumeration and relay attacks.",
        "recommendation": "Disable NetBIOS and block incoming connections on port 139."
    },
    445: {
        "service": "Microsoft SMB (Server Message Block)",
        "severity": "Critical",
        "description": "Windows file sharing port. Prime vector for ransomware (WannaCry, EternalBlue, NotPetya).",
        "recommendation": "Block port 445 on perimeter firewalls. Ensure SMBv1 is completely disabled."
    },
    1433: {
        "service": "Microsoft SQL Server",
        "severity": "High",
        "description": "Database server port. Common target for brute-force password spraying and SQL injection attacks.",
        "recommendation": "Never expose database ports directly to public or untrusted networks."
    },
    3389: {
        "service": "RDP (Remote Desktop Protocol)",
        "severity": "High",
        "description": "Windows Remote Desktop. Top target for brute-force ransomware attacks and credential stuffing.",
        "recommendation": "Restrict RDP to VPN or specific IP addresses, enable MFA and Network Level Authentication (NLA)."
    },
    5900: {
        "service": "VNC (Virtual Network Computing)",
        "severity": "High",
        "description": "Remote desktop screen sharing. Often deployed without encryption or with weak authentication.",
        "recommendation": "Tunnel VNC sessions over SSH or VPN, or disable when not actively needed."
    },
    8080: {
        "service": "HTTP Alternate / Proxy",
        "severity": "Low",
        "description": "Common alternate web server or proxy port. Check owning process to confirm legitimacy.",
        "recommendation": "Inspect owning process to verify if it is an authorized developer tool or application."
    }
}

# Suspicious Win32 APIs commonly leveraged in malware techniques
SUSPICIOUS_PE_IMPORTS = {
    "Process Injection & Memory Manipulation": [
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "QueueUserAPC",
        "NtCreateSection",
        "MapViewOfFile",
        "RtlMoveMemory",
        "SetThreadContext"
    ],
    "Keylogging & Hooking": [
        "SetWindowsHookExA",
        "SetWindowsHookExW",
        "GetAsyncKeyState",
        "GetKeyState",
        "GetKeyboardState",
        "RegisterHotKey"
    ],
    "Evasion & Anti-Analysis": [
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "OutputDebugStringA",
        "FindWindowA",
        "GetTickCount"
    ],
    "Credential & Privilege Operations": [
        "AdjustTokenPrivileges",
        "LookupPrivilegeValueA",
        "OpenProcessToken",
        "LsaEnumerateLogonSessions",
        "SamConnect"
    ],
    "Network Exfiltration": [
        "InternetOpenUrlA",
        "InternetReadFile",
        "HttpSendRequestA",
        "URLDownloadToFileA",
        "WSAStartup"
    ]
}

# Built-in Known Malware & Test Hashes (SHA-256)
BUILTIN_MALWARE_HASHES = {
    # EICAR Standard Antivirus Test File (SHA-256 with and without newline)
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "name": "EICAR-Standard-AV-Test-File",
        "type": "Test Virus",
        "severity": "Critical",
        "description": "Official European Institute for Computer Antivirus Research test string."
    },
    "13db60afb914a2ee9b3649d1947d58046d1a9e9b8e4114d80b1d5c142b4ed7fa": {
        "name": "EICAR-Standard-AV-Test-File",
        "type": "Test Virus",
        "severity": "Critical",
        "description": "Official European Institute for Computer Antivirus Research test string."
    },
    # WannaCry Ransomware sample SHA-256
    "ed01ebf83334a1937330723b4329f550fe08e817748723605637737cded07713": {
        "name": "WannaCry.Ransomware.A",
        "type": "Ransomware",
        "severity": "Critical",
        "description": "Known WannaCry SMB-propagated cryptor binary."
    },
    # Emotet Dropper SHA-256
    "73859665809180f1cb75e2eb27ef57d77b8b209d2241cfb4ea8a0818ae67fa70": {
        "name": "Emotet.BankingTrojan",
        "type": "Trojan",
        "severity": "Critical",
        "description": "Modular banking trojan and botnet loader."
    },
    # Mimikatz Credential Dumper sample SHA-256
    "8587c3e5361307ecab2cf52945d8b85775f0fbe8f1c8a14ec138d3885f8c8574": {
        "name": "HackTool.Mimikatz",
        "type": "Spyware",
        "severity": "Critical",
        "description": "Windows credential extraction and ticket manipulation tool."
    },
    # Cobalt Strike Beacon sample SHA-256
    "e2b9ff9b819e6d0bb116b47c617eb0cc6ff8a8eb6a9d7b929e5a1b32bb394c8b": {
        "name": "Backdoor.CobaltStrike",
        "type": "RAT",
        "severity": "Critical",
        "description": "Command and control beacon implant."
    }
}

# Critical Windows System Directories that must NEVER be deleted automatically
CRITICAL_SYSTEM_PATHS = [
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows\winsxs",
    r"c:\windows\boot",
    r"c:\windows\explorer.exe",
    r"c:\windows\system32\ntoskrnl.exe",
    r"c:\windows\system32\hal.dll",
    r"c:\windows\system32\kernel32.dll",
    r"c:\windows\system32\user32.dll",
    r"c:\windows\system32\csrss.exe",
    r"c:\windows\system32\winlogon.exe",
    r"c:\windows\system32\services.exe",
    r"c:\windows\system32\lsass.exe",
    r"c:\windows\system32\svchost.exe"
]

def is_protected_system_file(file_path: str) -> bool:
    """Returns True if the given file path is a protected Windows core file."""
    norm = file_path.lower().replace("/", "\\").strip()
    for sys_path in CRITICAL_SYSTEM_PATHS:
        if norm == sys_path or (sys_path.endswith(".dll") and norm.endswith(sys_path)):
            return True
        if norm.startswith(sys_path + "\\"):
            # Check if it's directly in Windows core
            parts = norm.split("\\")
            if len(parts) <= 4 and ("system32" in norm or "winsxs" in norm):
                return True
    return False
