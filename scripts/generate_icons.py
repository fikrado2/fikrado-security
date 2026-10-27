"""Generates the Fikrado Security vector icon set (SVG) used across the UI.

Run from the project root:
    .venv\\Scripts\\python.exe scripts\\generate_icons.py
"""
from pathlib import Path

ICONS_DIR = Path(__file__).resolve().parent.parent / "assets" / "icons"

BLUE = "#88C0D0"
GREEN = "#A3BE8C"
YELLOW = "#EBCB8B"
GOLD = "#FFD93D"
RED = "#BF616A"
ORANGE = "#D08770"
PURPLE = "#B48EAD"
GREY = "#9BA3AF"

BODIES = {
    "dashboard": f"""
        <rect x="3" y="3" width="7.5" height="7.5" rx="2" fill="{BLUE}"/>
        <rect x="13.5" y="3" width="7.5" height="7.5" rx="2" fill="{GREEN}"/>
        <rect x="3" y="13.5" width="7.5" height="7.5" rx="2" fill="{YELLOW}"/>
        <rect x="13.5" y="13.5" width="7.5" height="7.5" rx="2" fill="{RED}"/>
    """,
    "quick_scan": f"""
        <path d="M13.2 2.5 5 13.2h5.2L9.8 21.5 18.5 10.2h-5.4z"
              fill="{GOLD}" stroke="{ORANGE}" stroke-width="1.6"/>
    """,
    "full_scan": f"""
        <circle cx="10.5" cy="10.5" r="6.4" stroke="{BLUE}" stroke-width="2"/>
        <path d="m15.4 15.4 5 5" stroke="{BLUE}" stroke-width="2"/>
        <path d="m7.8 10.6 1.8 1.9 3.4-4" stroke="{GREEN}" stroke-width="1.8"/>
    """,
    "custom_scan": f"""
        <path d="M3 7.2c0-1.1.9-2 2-2h3.6l1.8 2H19c1.1 0 2 .9 2 2v9.6c0 1.1-.9 2-2 2H5c-1.1 0-2-.9-2-2z"
              fill="{YELLOW}" fill-opacity=".18" stroke="{YELLOW}" stroke-width="1.8"/>
        <circle cx="14" cy="13" r="2.7" stroke="{BLUE}" stroke-width="1.7"/>
        <path d="m16 15 2.2 2.2" stroke="{BLUE}" stroke-width="1.7"/>
    """,
    "port_scanner": f"""
        <circle cx="12" cy="12" r="8.6" stroke="{BLUE}" stroke-width="1.8"/>
        <ellipse cx="12" cy="12" rx="4" ry="8.6" stroke="{BLUE}" stroke-width="1.5"/>
        <path d="M3.6 12h16.8M5 7.2h14M5 16.8h14" stroke="{BLUE}" stroke-width="1.4"/>
        <circle cx="18.6" cy="5.4" r="2" fill="{GREEN}"/>
    """,
    "vuln": f"""
        <path d="M12 3.2 22 20H2z" fill="{YELLOW}" fill-opacity=".18" stroke="{YELLOW}" stroke-width="1.8"/>
        <path d="M12 9v5" stroke="{RED}" stroke-width="2"/>
        <circle cx="12" cy="17" r="1.1" fill="{RED}"/>
    """,
    "ai_scan": f"""
        <rect x="7" y="7" width="10" height="10" rx="2.2" fill="{GREEN}" fill-opacity=".2"
              stroke="{GREEN}" stroke-width="1.7"/>
        <rect x="10" y="10" width="4" height="4" rx="1" fill="{BLUE}"/>
        <path d="M9.5 3v4M14.5 3v4M9.5 17v4M14.5 17v4M3 9.5h4M3 14.5h4M17 9.5h4M17 14.5h4"
              stroke="{BLUE}" stroke-width="1.6"/>
    """,
    "tools": f"""
        <rect x="3" y="8" width="18" height="11" rx="2.2" fill="{RED}" fill-opacity=".2"
              stroke="{ORANGE}" stroke-width="1.8"/>
        <path d="M8.5 8V6.2c0-1 .8-1.8 1.8-1.8h3.4c1 0 1.8.8 1.8 1.8V8"
              stroke="{ORANGE}" stroke-width="1.7"/>
        <path d="M3 12.5h18" stroke="{ORANGE}" stroke-width="1.4"/>
        <rect x="10" y="11" width="4" height="3" rx="1" fill="{YELLOW}"/>
    """,
    "quarantine": f"""
        <rect x="4.5" y="10" width="15" height="10.5" rx="2.4" fill="{GREEN}" fill-opacity=".18"
              stroke="{GREEN}" stroke-width="1.8"/>
        <path d="M8 10V7.6a4 4 0 0 1 8 0V10" stroke="{GREEN}" stroke-width="1.8"/>
        <circle cx="12" cy="14.6" r="1.3" fill="{GREEN}"/>
        <path d="M12 15.9v2.2" stroke="{GREEN}" stroke-width="1.6"/>
    """,
    "reports": f"""
        <path d="M6 2.8h7.5L19 8.3v11.5c0 1-.8 1.8-1.8 1.8H6c-1 0-1.8-.8-1.8-1.8V4.6c0-1 .8-1.8 1.8-1.8z"
              fill="{BLUE}" fill-opacity=".12" stroke="{BLUE}" stroke-width="1.7"/>
        <path d="M13.5 2.8v5.5H19" stroke="{BLUE}" stroke-width="1.6"/>
        <path d="M8 12.5h5M8 15.5h7" stroke="{GREEN}" stroke-width="1.6"/>
        <path d="M8 18.5h3" stroke="{YELLOW}" stroke-width="1.6"/>
    """,
    "settings": f"""
        <circle cx="12" cy="12" r="3.2" stroke="{BLUE}" stroke-width="1.8"/>
        <path d="M12 2.8v2.4M12 18.8v2.4M2.8 12h2.4M18.8 12h2.4M5.5 5.5l1.7 1.7M16.8 16.8l1.7 1.7M18.5 5.5l-1.7 1.7M7.2 16.8l-1.7 1.7"
              stroke="{BLUE}" stroke-width="1.7"/>
    """,
    "stat_files": f"""
        <rect x="5" y="5" width="12" height="15" rx="2" fill="{BLUE}" fill-opacity=".15"
              stroke="{BLUE}" stroke-width="1.6"/>
        <path d="M8 2.8h8.2c1 0 1.8.8 1.8 1.8V17" stroke="{YELLOW}" stroke-width="1.6"/>
        <path d="M8 9h6M8 12h6M8 15h4" stroke="{BLUE}" stroke-width="1.4"/>
    """,
    "stat_threats": f"""
        <path d="M12 2.8 20 6v5.5c0 4.8-3.2 8-8 9.7-4.8-1.7-8-4.9-8-9.7V6z"
              fill="{RED}" fill-opacity=".2" stroke="{RED}" stroke-width="1.8"/>
        <path d="m9 9.5 6 6M15 9.5l-6 6" stroke="{RED}" stroke-width="2"/>
    """,
    "stat_realtime": f"""
        <circle cx="12" cy="12" r="8.8" fill="{GREEN}" fill-opacity=".10" stroke="{GREEN}" stroke-width="1.4"/>
        <path d="M5 12h3l2-4 3.2 8 2.2-5H19" stroke="{GREEN}" stroke-width="2"/>
    """,
    "stat_vulns": f"""
        <path d="M12 3.2 22 20H2z" fill="{YELLOW}" fill-opacity=".18" stroke="{YELLOW}" stroke-width="1.8"/>
        <path d="M12 9v5" stroke="{RED}" stroke-width="2"/>
        <circle cx="12" cy="17" r="1.1" fill="{RED}"/>
    """,
    "refresh": f"""
        <path d="M20 11a8 8 0 1 0-2.2 6.2" stroke="{BLUE}" stroke-width="2"/>
        <path d="M20 4.5V11h-6.3" stroke="{BLUE}" stroke-width="2"/>
    """,
    "folder": f"""
        <path d="M3 7.2c0-1.1.9-2 2-2h3.6l1.8 2H19c1.1 0 2 .9 2 2v9.6c0 1.1-.9 2-2 2H5c-1.1 0-2-.9-2-2z"
              fill="{YELLOW}" fill-opacity=".2" stroke="{YELLOW}" stroke-width="1.8"/>
    """,
    "file": f"""
        <path d="M6 2.8h7.5L19 8.3v11.5c0 1-.8 1.8-1.8 1.8H6c-1 0-1.8-.8-1.8-1.8V4.6c0-1 .8-1.8 1.8-1.8z"
              stroke="{BLUE}" stroke-width="1.7"/>
        <path d="M13.5 2.8v5.5H19" stroke="{BLUE}" stroke-width="1.6"/>
    """,
    "report": f"""
        <path d="M6 2.8h7.5L19 8.3v11.5c0 1-.8 1.8-1.8 1.8H6c-1 0-1.8-.8-1.8-1.8V4.6c0-1 .8-1.8 1.8-1.8z"
              fill="{BLUE}" fill-opacity=".12" stroke="{BLUE}" stroke-width="1.7"/>
        <path d="M13.5 2.8v5.5H19" stroke="{BLUE}" stroke-width="1.6"/>
        <path d="M8 12.5h5M8 15.5h7" stroke="{GREEN}" stroke-width="1.6"/>
        <path d="M8 18.5h3" stroke="{YELLOW}" stroke-width="1.6"/>
    """,
    "play": f"""
        <path d="M8 5.5 18 12 8 18.5z" fill="{GREEN}" stroke="{GREEN}" stroke-width="1.4"/>
    """,
    "pause": f"""
        <rect x="7" y="5" width="3.4" height="14" rx="1.4" fill="{YELLOW}"/>
        <rect x="13.6" y="5" width="3.4" height="14" rx="1.4" fill="{YELLOW}"/>
    """,
    "cancel": f"""
        <path d="M6 6l12 12M18 6 6 18" stroke="{RED}" stroke-width="2.2"/>
    """,
    "search": f"""
        <circle cx="10.5" cy="10.5" r="6.4" stroke="{BLUE}" stroke-width="2"/>
        <path d="m15.4 15.4 5 5" stroke="{BLUE}" stroke-width="2"/>
    """,
    "globe": f"""
        <circle cx="12" cy="12" r="8.6" stroke="{BLUE}" stroke-width="1.8"/>
        <ellipse cx="12" cy="12" rx="4" ry="8.6" stroke="{BLUE}" stroke-width="1.5"/>
        <path d="M3.6 12h16.8M5 7.2h14M5 16.8h14" stroke="{BLUE}" stroke-width="1.4"/>
    """,
    "shield": f"""
        <path d="M12 2.8 20 6v5.5c0 4.8-3.2 8-8 9.7-4.8-1.7-8-4.9-8-9.7V6z"
              fill="{GREEN}" fill-opacity=".18" stroke="{GREEN}" stroke-width="1.8"/>
        <path d="m8.5 11.8 2.4 2.5 4.6-5" stroke="{GREEN}" stroke-width="2"/>
    """,
    "warning": f"""
        <path d="M12 3.2 22 20H2z" fill="{YELLOW}" fill-opacity=".18" stroke="{YELLOW}" stroke-width="1.8"/>
        <path d="M12 9v5" stroke="{RED}" stroke-width="2"/>
        <circle cx="12" cy="17" r="1.1" fill="{RED}"/>
    """,
    "lock": f"""
        <rect x="4.5" y="10" width="15" height="10.5" rx="2.4" fill="{GREEN}" fill-opacity=".18"
              stroke="{GREEN}" stroke-width="1.8"/>
        <path d="M8 10V7.6a4 4 0 0 1 8 0V10" stroke="{GREEN}" stroke-width="1.8"/>
        <circle cx="12" cy="14.6" r="1.3" fill="{GREEN}"/>
    """,
    "trash": f"""
        <path d="M4 6.5h16M9 6.5V4.8c0-.9.7-1.6 1.6-1.6h2.8c.9 0 1.6.7 1.6 1.6v1.7"
              stroke="{RED}" stroke-width="1.8"/>
        <path d="M6.2 6.5 7 19.4c.1 1 .9 1.8 1.9 1.8h6.2c1 0 1.8-.8 1.9-1.8l.8-12.9"
              stroke="{RED}" stroke-width="1.8"/>
        <path d="M10 10.5v6M14 10.5v6" stroke="{RED}" stroke-width="1.6"/>
    """,
    "restore": f"""
        <path d="M4 11a8 8 0 1 1 2.2 6.2" stroke="{GREEN}" stroke-width="2"/>
        <path d="M4 4.5V11h6.3" stroke="{GREEN}" stroke-width="2"/>
    """,
    "save": f"""
        <path d="M4.5 3.5h12L20.5 7.5v13h-17z" fill="{BLUE}" fill-opacity=".12"
              stroke="{BLUE}" stroke-width="1.7"/>
        <rect x="8" y="3.5" width="8" height="5.5" rx="1" fill="{YELLOW}" fill-opacity=".8"/>
        <rect x="7" y="13" width="10" height="7.5" rx="1" stroke="{GREEN}" stroke-width="1.5"/>
    """,
    "plug": f"""
        <path d="M9 3v5M15 3v5" stroke="{GREEN}" stroke-width="2"/>
        <path d="M6.5 8h11v3.5a5.5 5.5 0 0 1-11 0z" fill="{GREEN}" fill-opacity=".16"
              stroke="{GREEN}" stroke-width="1.8"/>
        <path d="M12 17v4" stroke="{GREEN}" stroke-width="1.8"/>
    """,
    "key": f"""
        <circle cx="8" cy="12" r="4" stroke="{YELLOW}" stroke-width="1.8"/>
        <path d="M12 12h9M18 12v3M15.5 12v2.2" stroke="{YELLOW}" stroke-width="1.8"/>
    """,
    "eye": f"""
        <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"
              stroke="{BLUE}" stroke-width="1.7"/>
        <circle cx="12" cy="12" r="3" fill="{BLUE}" fill-opacity=".25" stroke="{BLUE}" stroke-width="1.6"/>
    """,
    "eye_off": f"""
        <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"
              stroke="{GREY}" stroke-width="1.7"/>
        <circle cx="12" cy="12" r="3" fill="{GREY}" fill-opacity=".2" stroke="{GREY}" stroke-width="1.6"/>
        <path d="M4 4l16 16" stroke="{RED}" stroke-width="2"/>
    """,
    "fire": f"""
        <path d="M12 2.5c3.8 4 6.2 6.6 6.2 10.2A6.2 6.2 0 0 1 12 19a6.2 6.2 0 0 1-6.2-6.3c0-2 .8-3.6 2.2-5.2.3 1.5 1 2.5 2.1 3.1.2-2.6 1.2-4.8 1.9-8.1z"
              fill="{RED}" fill-opacity=".22" stroke="{ORANGE}" stroke-width="1.6"/>
    """,
    "update": f"""
        <path d="M12 3v12" stroke="{GREEN}" stroke-width="2"/>
        <path d="m7 10 5 5 5-5" stroke="{GREEN}" stroke-width="2"/>
        <path d="M4 20h16" stroke="{BLUE}" stroke-width="1.8"/>
    """,
    "browser": f"""
        <rect x="3" y="4" width="18" height="16" rx="2.4" fill="{BLUE}" fill-opacity=".10"
              stroke="{BLUE}" stroke-width="1.7"/>
        <path d="M3 8.5h18" stroke="{BLUE}" stroke-width="1.6"/>
        <circle cx="6" cy="6.3" r=".8" fill="{RED}"/>
        <circle cx="8.5" cy="6.3" r=".8" fill="{YELLOW}"/>
        <circle cx="11" cy="6.3" r=".8" fill="{GREEN}"/>
        <path d="M7 12h10M7 15.5h6" stroke="{GREEN}" stroke-width="1.5"/>
    """,
    "monitor": f"""
        <rect x="2.5" y="4" width="19" height="13" rx="2.2" stroke="{BLUE}" stroke-width="1.7"/>
        <path d="M9 21h6M12 17v4" stroke="{BLUE}" stroke-width="1.7"/>
        <path d="M6 12.5h2.5l1.5-3 2.5 5 1.6-2H18" stroke="{GREEN}" stroke-width="1.8"/>
    """,
    "network": f"""
        <circle cx="12" cy="4.5" r="2.2" fill="{BLUE}"/>
        <circle cx="5" cy="19" r="2.2" fill="{GREEN}"/>
        <circle cx="19" cy="19" r="2.2" fill="{YELLOW}"/>
        <path d="M12 6.7v5.3M12 12 5 17M12 12l7 5" stroke="{BLUE}" stroke-width="1.6"/>
    """,
    "dns": f"""
        <circle cx="12" cy="12" r="2" fill="{BLUE}"/>
        <path d="M7.8 7.8a6 6 0 0 0 0 8.4M16.2 7.8a6 6 0 0 1 0 8.4" stroke="{BLUE}" stroke-width="1.7"/>
        <path d="M4.8 4.8a10 10 0 0 0 0 14.4M19.2 4.8a10 10 0 0 1 0 14.4" stroke="{GREEN}" stroke-width="1.6"/>
    """,
    "startup": f"""
        <path d="M12 2.8c3.2 2 5 5.2 5 9.2l-2.4 2.4H9.4L7 12c0-4 1.8-7.2 5-9.2z"
              fill="{GREEN}" fill-opacity=".16" stroke="{GREEN}" stroke-width="1.7"/>
        <circle cx="12" cy="9" r="1.8" stroke="{BLUE}" stroke-width="1.5"/>
        <path d="M9.4 14.4 7 18l3.4-1M14.6 14.4 17 18l-3.4-1M12 16v5"
              stroke="{ORANGE}" stroke-width="1.6"/>
    """,
    "process": f"""
        <rect x="6" y="6" width="12" height="12" rx="2" fill="{BLUE}" fill-opacity=".12"
              stroke="{BLUE}" stroke-width="1.7"/>
        <circle cx="12" cy="12" r="2.4" stroke="{GREEN}" stroke-width="1.6"/>
        <path d="M9 2.8v3.2M15 2.8v3.2M9 18v3.2M15 18v3.2M2.8 9h3.2M2.8 15h3.2M18 9h3.2M18 15h3.2"
              stroke="{BLUE}" stroke-width="1.5"/>
    """,
    "firewall": f"""
        <rect x="3" y="5" width="18" height="14" rx="2" fill="{RED}" fill-opacity=".12"
              stroke="{ORANGE}" stroke-width="1.7"/>
        <path d="M3 9.5h18M3 14.5h18M9 5v4.5M15 5v4.5M6 9.5V14.5M12 9.5V14.5M18 9.5V14.5M9 14.5V19M15 14.5V19"
              stroke="{ORANGE}" stroke-width="1.3"/>
    """,
    "realtime": f"""
        <circle cx="12" cy="12" r="8.8" fill="{GREEN}" fill-opacity=".10" stroke="{GREEN}" stroke-width="1.4"/>
        <path d="M5 12h3l2-4 3.2 8 2.2-5H19" stroke="{GREEN}" stroke-width="2"/>
    """,
    "shredder": f"""
        <path d="M4 6.5h16M9 6.5V4.8c0-.9.7-1.6 1.6-1.6h2.8c.9 0 1.6.7 1.6 1.6v1.7"
              stroke="{RED}" stroke-width="1.8"/>
        <path d="M6.5 6.5 7.3 19c.1 1 .9 1.8 1.9 1.8h5.6c1 0 1.8-.8 1.9-1.8l.8-12.5"
              stroke="{RED}" stroke-width="1.8"/>
        <path d="M9.5 10v6.5M12 10v6.5M14.5 10v6.5" stroke="{ORANGE}" stroke-width="1.4"/>
    """,
    "hardening": f"""
        <path d="M12 2.8 20 6v5.5c0 4.8-3.2 8-8 9.7-4.8-1.7-8-4.9-8-9.7V6z"
              fill="{GREEN}" fill-opacity=".18" stroke="{GREEN}" stroke-width="1.8"/>
        <path d="m8.5 11.8 2.4 2.5 4.6-5" stroke="{GREEN}" stroke-width="2"/>
    """,
    "password": f"""
        <circle cx="8" cy="12" r="4" stroke="{YELLOW}" stroke-width="1.8"/>
        <path d="M12 12h9M18 12v3M15.5 12v2.2" stroke="{YELLOW}" stroke-width="1.8"/>
    """,
    "info": f"""
        <circle cx="12" cy="12" r="9" stroke="{BLUE}" stroke-width="1.8"/>
        <path d="M12 10.5V17" stroke="{BLUE}" stroke-width="2"/>
        <circle cx="12" cy="7.2" r="1.1" fill="{BLUE}"/>
    """,
    "link": f"""
        <path d="M10 14a4 4 0 0 0 5.7 0l2.6-2.6a4 4 0 1 0-5.7-5.7L11.4 7"
              stroke="{BLUE}" stroke-width="1.8"/>
        <path d="M14 10a4 4 0 0 0-5.7 0l-2.6 2.6a4 4 0 1 0 5.7 5.7L12.6 17"
              stroke="{GREEN}" stroke-width="1.8"/>
    """,
    "website": f"""
        <circle cx="12" cy="12" r="8.6" stroke="{BLUE}" stroke-width="1.8"/>
        <ellipse cx="12" cy="12" rx="4" ry="8.6" stroke="{BLUE}" stroke-width="1.5"/>
        <path d="M3.6 12h16.8" stroke="{BLUE}" stroke-width="1.4"/>
        <circle cx="18.6" cy="5.4" r="2" fill="{GREEN}"/>
    """,
    "linkedin": """
        <rect x="2.5" y="2.5" width="19" height="19" rx="4" fill="#0A66C2"/>
        <circle cx="7.4" cy="7.4" r="1.5" fill="#FFFFFF"/>
        <rect x="6.1" y="9.6" width="2.6" height="9.4" rx="1.2" fill="#FFFFFF"/>
        <path d="M11 19V9.6h2.5v1.3c.7-1 1.8-1.6 3.1-1.6 2.4 0 3.9 1.6 3.9 4.4V19h-2.7v-4.8c0-1.4-.6-2.2-1.8-2.2-1.3 0-2.1.9-2.1 2.4V19z"
              fill="#FFFFFF"/>
    """,
    "github": """
        <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"
              fill="#ECEFF4"/>
    """,
    "cloud": f"""
        <path d="M7.2 18.5h9.6a3.7 3.7 0 0 0 .5-7.4 5.6 5.6 0 0 0-10.8-1.4A4.4 4.4 0 0 0 7.2 18.5z"
              fill="{BLUE}" fill-opacity=".12" stroke="{BLUE}" stroke-width="1.7"/>
    """,
    "brain": f"""
        <path d="M9.5 4.2a3 3 0 0 0-3 3 3 3 0 0 0-1.3 5.4A3.2 3.2 0 0 0 7.5 18a3 3 0 0 0 4.5 2.2V4.9a3 3 0 0 0-2.5-.7z"
              stroke="{GREEN}" stroke-width="1.5"/>
        <path d="M14.5 4.2a3 3 0 0 1 3 3 3 3 0 0 1 1.3 5.4A3.2 3.2 0 0 1 16.5 18a3 3 0 0 1-4.5 2.2"
              stroke="{BLUE}" stroke-width="1.5"/>
        <path d="M6.5 9.5h3M14.5 9.5h3M7.5 14h3M13.5 14h3" stroke="{BLUE}" stroke-width="1.2"/>
    """,
    "check": f"""
        <circle cx="12" cy="12" r="9" fill="{GREEN}" fill-opacity=".14" stroke="{GREEN}" stroke-width="1.6"/>
        <path d="m7.5 12.2 3 3 6-6.5" stroke="{GREEN}" stroke-width="2"/>
    """,
    "clock": f"""
        <circle cx="12" cy="12" r="8.8" fill="{BLUE}" fill-opacity=".10" stroke="{BLUE}" stroke-width="1.7"/>
        <path d="M12 7.2V12l3.4 2.1" stroke="{YELLOW}" stroke-width="1.9"/>
    """,
    "minimize": f"""
        <path d="M5 12h14" stroke="{GREY}" stroke-width="1.8"/>
    """,
    "maximize": f"""
        <rect x="5.5" y="5.5" width="13" height="13" rx="2" stroke="{GREY}" stroke-width="1.6"/>
    """,
    "restore": f"""
        <rect x="4.5" y="7.5" width="11" height="11" rx="1.8" stroke="{GREY}" stroke-width="1.5"/>
        <path d="M8 7.5V5.5c0-.8.7-1.5 1.5-1.5h9c.8 0 1.5.7 1.5 1.5v9c0 .8-.7 1.5-1.5 1.5h-2" stroke="{GREY}" stroke-width="1.5"/>
    """,
    "close": f"""
        <path d="M6.5 6.5l11 11M17.5 6.5l-11 11" stroke="{GREY}" stroke-width="1.9"/>
    """,
}

WRAPPER = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" '
    'fill="none" stroke-linecap="round" stroke-linejoin="round">{body}</svg>\n'
)


def main():
    ICONS_DIR.mkdir(parents=True, exist_ok=True)
    for name, body in BODIES.items():
        path = ICONS_DIR / f"{name}.svg"
        path.write_text(WRAPPER.format(body=body.strip()), encoding="utf-8")
    print(f"Generated {len(BODIES)} icons in {ICONS_DIR}")


if __name__ == "__main__":
    main()
