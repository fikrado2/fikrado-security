"""
Fikrado Security - Quarantine Manager
Safely isolates, encrypts, and manages identified malicious files.
Reversible and secure against secondary execution.
"""
import hashlib
import json
import os
import shutil
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional
from config.constants import QUARANTINE_DIR
from config.security_rules import is_protected_system_file
from core.crypto import decrypt_file_data, encrypt_file_data
from core.logger import logger


class QuarantineManager:
    """Manages the encrypted isolation of suspicious and malicious files."""

    def __init__(self):
        self.storage_dir = QUARANTINE_DIR
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.index_file = self.storage_dir / "quarantine_index.json"
        self._index: Dict[str, dict] = self._load_index()

    def _load_index(self) -> Dict[str, dict]:
        if self.index_file.exists():
            try:
                with open(self.index_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to read quarantine index: {e}")
        return {}

    def _save_index(self):
        try:
            with open(self.index_file, "w", encoding="utf-8") as f:
                json.dump(self._index, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to write quarantine index: {e}")

    def quarantine_file(
        self,
        file_path: str,
        threat_name: str,
        threat_type: str,
        severity: str,
        detection_engine: str,
        notes: str = ""
    ) -> bool:
        """
        Safely isolates a file by reading its contents, encrypting them,
        storing the encrypted blob, and removing the original file.
        """
        p = Path(file_path)
        if not p.exists() or not p.is_file():
            logger.error(f"Cannot quarantine: File does not exist: {file_path}")
            return False

        if is_protected_system_file(file_path):
            logger.warning(
                f"SAFETY SHIELD: Attempted to quarantine protected system file: {file_path}. Operation aborted."
            )
            return False

        try:
            # Read original bytes
            with open(p, "rb") as f:
                raw_data = f.read()

            sha256_hash = hashlib.sha256(raw_data).hexdigest()
            file_size = len(raw_data)
            quarantine_id = str(uuid.uuid4())
            encrypted_data = encrypt_file_data(raw_data)

            # Store encrypted blob with .qtn extension
            blob_path = self.storage_dir / f"{quarantine_id}.qtn"
            with open(blob_path, "wb") as f:
                f.write(encrypted_data)

            # Record in index
            entry = {
                "id": quarantine_id,
                "original_path": str(p.resolve()),
                "filename": p.name,
                "file_size": file_size,
                "sha256": sha256_hash,
                "threat_name": threat_name,
                "threat_type": threat_type,
                "severity": severity,
                "detection_engine": detection_engine,
                "quarantine_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "notes": notes,
                "status": "Quarantined"
            }
            self._index[quarantine_id] = entry
            self._save_index()

            # Attempt to delete original file
            try:
                # Remove read-only attribute if present
                p.chmod(0o777)
                p.unlink()
                logger.info(f"Successfully quarantined file: {file_path} as {quarantine_id}")
                return True
            except Exception as e:
                logger.warning(f"Quarantined blob stored, but could not remove original file {file_path}: {e}")
                return True

        except Exception as e:
            logger.error(f"Error during quarantine of {file_path}: {e}")
            return False

    def restore_file(self, quarantine_id: str, custom_target_path: Optional[str] = None) -> bool:
        """
        Decrypts and restores a quarantined file back to its original location or a custom path.
        """
        if quarantine_id not in self._index:
            logger.error(f"Quarantine ID not found in index: {quarantine_id}")
            return False

        entry = self._index[quarantine_id]
        blob_path = self.storage_dir / f"{quarantine_id}.qtn"
        if not blob_path.exists():
            logger.error(f"Quarantined blob not found on disk: {blob_path}")
            return False

        target_path = Path(custom_target_path) if custom_target_path else Path(entry["original_path"])

        try:
            with open(blob_path, "rb") as f:
                encrypted_data = f.read()

            decrypted_data = decrypt_file_data(encrypted_data)

            # Ensure parent directories exist
            target_path.parent.mkdir(parents=True, exist_ok=True)

            with open(target_path, "wb") as f:
                f.write(decrypted_data)

            # Remove blob and update index
            blob_path.unlink(missing_ok=True)
            del self._index[quarantine_id]
            self._save_index()

            logger.info(f"Restored {entry['filename']} to {target_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to restore quarantined file {quarantine_id}: {e}")
            return False

    def delete_permanently(self, quarantine_id: str) -> bool:
        """Permanently shreds and deletes a quarantined blob and cleans up index."""
        if quarantine_id not in self._index:
            return False

        blob_path = self.storage_dir / f"{quarantine_id}.qtn"
        if blob_path.exists():
            try:
                # Overwrite before deleting
                size = blob_path.stat().st_size
                with open(blob_path, "wb") as f:
                    f.write(os.urandom(size))
                blob_path.unlink()
            except Exception as e:
                logger.error(f"Failed to delete blob {blob_path}: {e}")

        del self._index[quarantine_id]
        self._save_index()
        logger.info(f"Permanently removed quarantine item: {quarantine_id}")
        return True

    def list_items(self) -> List[dict]:
        """Returns list of all quarantined entries."""
        return list(self._index.values())
