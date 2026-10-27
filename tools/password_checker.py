"""
Fikrado Security - Password Strength & Breach Auditor
Uses HaveIBeenPwned k-anonymity API (zero disclosure) and Shannon password entropy analysis.
"""
import hashlib
import math
import re
from typing import Dict, Tuple
import requests
from core.logger import logger


def calculate_password_strength(password: str) -> dict:
    """Calculates password entropy, complexity, and crack time estimate."""
    if not password:
        return {"score": 0, "verdict": "Empty", "entropy": 0, "tips": ["Enter a password to evaluate."]}

    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_symbol:
        pool_size += 33

    entropy = length * math.log2(pool_size) if pool_size > 0 else 0

    tips = []
    if length < 12:
        tips.append("Make password at least 12-16 characters long.")
    if not has_upper:
        tips.append("Add uppercase letters (A-Z).")
    if not has_lower:
        tips.append("Add lowercase letters (a-z).")
    if not has_digit:
        tips.append("Include numeric digits (0-9).")
    if not has_symbol:
        tips.append("Include special characters (!@#$%^&*).")

    score = min(100, int((entropy / 80) * 100))

    if score >= 80:
        verdict = "Very Strong"
        color = "#A3BE8C"  # Nord Green
    elif score >= 60:
        verdict = "Strong"
        color = "#88C0D0"  # Nord Frost
    elif score >= 40:
        verdict = "Moderate"
        color = "#EBCB8B"  # Nord Yellow
    else:
        verdict = "Weak"
        color = "#BF616A"  # Nord Red

    return {
        "score": score,
        "verdict": verdict,
        "entropy_bits": round(entropy, 1),
        "color": color,
        "tips": tips if tips else ["Excellent password complexity."]
    }


def check_haveibeenpwned(password: str) -> Tuple[bool, int, str]:
    """
    Checks if password has appeared in known public data breaches using
    HaveIBeenPwned k-anonymity protocol.
    Zero full password or full hash is ever sent over the network.
    Returns: (is_pwned, breach_count, message)
    """
    if not password:
        return False, 0, "No password provided."

    try:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        headers = {"User-Agent": "FikradoSecurity-Auditor"}
        resp = requests.get(url, headers=headers, timeout=6)

        if resp.status_code == 200:
            for line in resp.text.splitlines():
                parts = line.strip().split(":")
                if len(parts) == 2:
                    h_suffix, count_str = parts
                    if h_suffix.upper() == suffix:
                        count = int(count_str)
                        return True, count, f"WARNING: Password found in {count:,} known public data breaches!"
            return False, 0, "SAFE: Password was NOT found in any known public data breaches."
        return False, 0, f"API query returned HTTP {resp.status_code}."
    except Exception as e:
        logger.debug(f"HIBP check error: {e}")
        return False, 0, f"Breach check unavailable: {str(e)}"
