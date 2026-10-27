"""
Fikrado Security - Constants and Application Metadata
"""
import os
import sys
from pathlib import Path

APP_NAME = "Fikrado Security"
APP_VERSION = "2.6.87"
APP_AUTHOR = "Fikrado Security"
APP_PUBLISHER = "Fikrado Security"
APP_COPYRIGHT = "Copyright © 2026 Fikrado Security"
APP_DESCRIPTION = "Next-Generation Windows Security & Threat Defense Platform"
APP_ID = "com.fikrado.security"

# Public presence
WEBSITE_URL = "https://fikrado2.github.io"
LINKEDIN_URL = "https://www.linkedin.com/in/yahye-abdirahman/"
GITHUB_URL = "https://github.com/fikrado-orgnasation/"
SOCIAL_LINKS = (
    ("website", "Website", WEBSITE_URL),
    ("linkedin", "LinkedIn", LINKEDIN_URL),
    ("github", "GitHub", GITHUB_URL),
)

# Detect if running as PyInstaller bundle
if getattr(sys, 'frozen', False):
    BUNDLE_DIR = Path(sys._MEIPASS)
    BASE_DIR = Path(sys.executable).parent
else:
    BUNDLE_DIR = Path(__file__).resolve().parent.parent
    BASE_DIR = BUNDLE_DIR

ASSETS_DIR = BUNDLE_DIR / "assets"
LOGO_PNG = ASSETS_DIR / "logo.png"
LOGO_ICO = ASSETS_DIR / "logo.ico"
ICONS_DIR = ASSETS_DIR / "icons"
PLUGINS_DIR = BASE_DIR / "plugins"

# Persistent AppData paths
APPDATA_BASE = Path(os.getenv("APPDATA", os.path.expanduser("~"))) / "FikradoSecurity"
LOGS_DIR = APPDATA_BASE / "logs"
QUARANTINE_DIR = APPDATA_BASE / "quarantine"
DATABASE_DIR = APPDATA_BASE / "database"
REPORTS_DIR = APPDATA_BASE / "reports"
SIGNATURES_DIR = APPDATA_BASE / "signatures"
SETTINGS_FILE = APPDATA_BASE / "settings.json"

for d in (APPDATA_BASE, LOGS_DIR, QUARANTINE_DIR, DATABASE_DIR, REPORTS_DIR, SIGNATURES_DIR):
    d.mkdir(parents=True, exist_ok=True)

# Nord Theme Colors
COLOR_BG_DARKEST = "#242933"    # Polar Night deep
COLOR_BG_DARK = "#2E3440"       # Nord0 - Main Background
COLOR_BG_CARD = "#3B4252"       # Nord1 - Card / Container Background
COLOR_BG_LIGHT = "#434C5E"      # Nord2 - Input / Hover Background
COLOR_BG_BORDER = "#4C566A"     # Nord3 - Borders and separators

COLOR_TEXT_PRIMARY = "#ECEFF4"   # Nord6 - Highest contrast text
COLOR_TEXT_SECONDARY = "#D8DEE9" # Nord4 - Muted text
COLOR_TEXT_MUTED = "#9BA3AF"     # Subtle text

# Nord Frost & Aurora Accents
COLOR_FROST_CYAN = "#88C0D0"     # Nord8 - Frost Light Blue
COLOR_FROST_BLUE = "#81A1C1"     # Nord9 - Frost Deep Blue
COLOR_FROST_DARK = "#5E81AC"     # Nord10 - Frost Darker
COLOR_FROST_TEAL = "#8FBCBB"     # Nord7 - Frost Mint
COLOR_AURORA_RED = "#BF616A"     # Nord11 - Threat Critical / Error
COLOR_AURORA_ORANGE = "#D08770"  # Nord12 - Threat High / Warning
COLOR_AURORA_YELLOW = "#EBCB8B"  # Nord13 - Threat Medium / Caution
COLOR_AURORA_GREEN = "#A3BE8C"   # Nord14 - Safe / Success
COLOR_AURORA_PURPLE = "#B48EAD"  # Nord15 - Info / PUP

# Brand Gradient
BRAND_GRADIENT_START = "#FFD93D" # Brand Yellow
BRAND_GRADIENT_END = "#88C0D0"   # Brand Frost Light Blue

# Severity Definitions
SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]
THREAT_TYPES = [
    "Trojan",
    "Ransomware",
    "Spyware",
    "Keylogger",
    "Backdoor",
    "Worm",
    "RAT",
    "Adware",
    "PUP",
    "Rootkit",
    "Cryptominer",
    "Suspicious"
]
