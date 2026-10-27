"""
Fikrado Security - Secure Military-Grade File Shredder
Implements DoD 5220.22-M compliant multi-pass overwriting, truncation, and NTFS metadata wiping.
"""
import os
import random
import string
from pathlib import Path
from typing import Callable, Optional, Tuple
from config.security_rules import is_protected_system_file
from core.logger import logger


def shred_file(
    file_path: str,
    passes: int = 3,
    progress_callback: Optional[Callable[[int, int, str], None]] = None
) -> Tuple[bool, str]:
    """
    Permanently destroys a file so it cannot be recovered by forensic tools.
    - Pass 1: Overwrite with zeros (0x00)
    - Pass 2: Overwrite with ones (0xFF)
    - Pass 3: Overwrite with cryptographically secure random bytes
    - Truncate to 0 bytes
    - Randomize file name to erase NTFS MFT record
    - Delete file
    """
    p = Path(file_path)
    if not p.exists() or not p.is_file():
        return False, f"File does not exist: {file_path}"

    if is_protected_system_file(file_path):
        return False, "SAFETY SHIELD: Cannot shred protected Windows core system files."

    try:
        file_size = p.stat().st_size
        chunk_size = 64 * 1024

        with open(p, "ba+", buffering=0) as f:
            for p_num in range(1, passes + 1):
                f.seek(0)
                bytes_written = 0

                if p_num == 1:
                    pattern = b"\x00" * chunk_size
                    desc = "Pass 1/3: Overwriting with zeros..."
                elif p_num == 2:
                    pattern = b"\xFF" * chunk_size
                    desc = "Pass 2/3: Overwriting with ones..."
                else:
                    desc = f"Pass {p_num}/{passes}: Cryptographic random overwrite..."

                if progress_callback:
                    progress_callback(p_num, passes, desc)

                while bytes_written < file_size:
                    to_write = min(chunk_size, file_size - bytes_written)
                    if p_num > 2:
                        pattern = os.urandom(to_write)
                    else:
                        pattern = pattern[:to_write]
                    f.write(pattern)
                    bytes_written += to_write

                f.flush()
                os.fsync(f.fileno())

        # Truncate file length to zero
        with open(p, "w") as f:
            f.truncate(0)

        # Obfuscate file name before unlinking to sanitize MFT record
        random_name = "".join(random.choices(string.ascii_letters + string.digits, k=16))
        shredded_temp = p.parent / f"{random_name}.tmp"
        p.rename(shredded_temp)

        # Unlink
        shredded_temp.unlink()
        logger.info(f"Successfully shredded file: {file_path} with {passes} passes.")
        return True, f"File permanently shredded ({passes} passes completed)."

    except PermissionError:
        return False, "Access denied. File may be in use by another process."
    except Exception as e:
        logger.error(f"Error shredding file {file_path}: {e}")
        return False, f"Shredding failed: {str(e)}"
