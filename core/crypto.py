"""
Fikrado Security - Cryptographic Utilities
Provides Windows DPAPI key encryption and AES-GCM quarantine encryption.
Zero plaintext credentials or insecure storage.
"""
import base64
import os
import platform
from typing import Optional
from core.logger import logger

# Try importing win32crypt for DPAPI
try:
    import win32crypt
    HAS_DPAPI = True
except ImportError:
    HAS_DPAPI = False

# Try importing AESGCM from cryptography
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    HAS_AES = True
except ImportError:
    HAS_AES = False


def _get_machine_entropy() -> bytes:
    """Derives a stable machine-specific entropy key."""
    # Env fallbacks only apply where the Windows variables are absent, so the
    # derived key on Windows (and therefore stored secrets) is unchanged.
    computer_name = os.getenv("COMPUTERNAME") or os.getenv("HOSTNAME") or platform.node()
    processor = (
        os.getenv("PROCESSOR_IDENTIFIER")
        or os.getenv("PROCESSOR_ARCHITECTURE")
        or platform.machine()
        or "FikradoSecurityMachineKey"
    )
    seed = (platform.node() + computer_name + processor).encode("utf-8")
    if HAS_AES:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"FikradoSecurityDeterministicSalt_v1",
            iterations=100_000,
        )
        return kdf.derive(seed)
    import hashlib
    return hashlib.sha256(seed).digest()


MACHINE_KEY = _get_machine_entropy()


def encrypt_secret(plain_text: str) -> str:
    """
    Encrypts a sensitive string (like an API key) using Windows DPAPI.
    Returns a base64-encoded ciphertext string.
    """
    if not plain_text:
        return ""

    raw_bytes = plain_text.encode("utf-8")

    if HAS_DPAPI:
        try:
            # DPAPI encrypts using the current logged-in Windows user master key
            encrypted_bytes = win32crypt.CryptProtectData(
                raw_bytes, "FikradoSecret", None, None, None, 0
            )
            return "dpapi:" + base64.b64encode(encrypted_bytes).decode("ascii")
        except Exception as e:
            logger.warning(f"DPAPI encryption failed, falling back to AES: {e}")

    # Fallback: AES-GCM with machine-derived key
    if HAS_AES:
        try:
            aesgcm = AESGCM(MACHINE_KEY)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, raw_bytes, None)
            combined = nonce + ciphertext
            return "aesgcm:" + base64.b64encode(combined).decode("ascii")
        except Exception as e:
            logger.error(f"AES encryption failed: {e}")

    # Minimal XOR fallback with machine key
    xor_bytes = bytes([b ^ MACHINE_KEY[i % len(MACHINE_KEY)] for i, b in enumerate(raw_bytes)])
    return "xor:" + base64.b64encode(xor_bytes).decode("ascii")


def decrypt_secret(cipher_text: str) -> str:
    """
    Decrypts a sensitive string previously encrypted by encrypt_secret.
    """
    if not cipher_text:
        return ""

    try:
        if cipher_text.startswith("dpapi:"):
            if not HAS_DPAPI:
                raise RuntimeError("DPAPI required to decrypt this secret")
            raw_data = base64.b64decode(cipher_text[6:])
            _, decrypted_bytes = win32crypt.CryptUnprotectData(raw_data, None, None, None, 0)
            return decrypted_bytes.decode("utf-8")

        elif cipher_text.startswith("aesgcm:"):
            if not HAS_AES:
                raise RuntimeError("Cryptography package required to decrypt this secret")
            raw_data = base64.b64decode(cipher_text[7:])
            nonce = raw_data[:12]
            ciphertext = raw_data[12:]
            aesgcm = AESGCM(MACHINE_KEY)
            return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")

        elif cipher_text.startswith("xor:"):
            raw_data = base64.b64decode(cipher_text[4:])
            decrypted = bytes([b ^ MACHINE_KEY[i % len(MACHINE_KEY)] for i, b in enumerate(raw_data)])
            return decrypted.decode("utf-8")

        # Plaintext or unknown format
        return cipher_text
    except Exception as e:
        logger.error(f"Failed to decrypt secret: {e}")
        return ""


def encrypt_file_data(data: bytes) -> bytes:
    """Encrypts raw file bytes for quarantine storage using AES-GCM."""
    if HAS_AES:
        aesgcm = AESGCM(MACHINE_KEY)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return b"FIKRADO_ENC_V1" + nonce + ciphertext
    # XOR fallback
    xor_bytes = bytes([b ^ MACHINE_KEY[i % len(MACHINE_KEY)] for i, b in enumerate(data)])
    return b"FIKRADO_XOR_V1" + xor_bytes


def decrypt_file_data(data: bytes) -> bytes:
    """Decrypts quarantined file bytes for safe restoration."""
    if data.startswith(b"FIKRADO_ENC_V1") and HAS_AES:
        nonce = data[14:26]
        ciphertext = data[26:]
        aesgcm = AESGCM(MACHINE_KEY)
        return aesgcm.decrypt(nonce, ciphertext, None)
    elif data.startswith(b"FIKRADO_XOR_V1"):
        payload = data[14:]
        return bytes([b ^ MACHINE_KEY[i % len(MACHINE_KEY)] for i, b in enumerate(payload)])
    return data
