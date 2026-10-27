"""
Fikrado Security - SQLite Database Store
Maintains historical scans, threat events, CISA KEV vulnerability cache, and local signatures.
"""
import sqlite3
import time
from pathlib import Path
from typing import Dict, List, Optional
from config.constants import DATABASE_DIR
from core.logger import logger

DB_PATH = DATABASE_DIR / "security.db"


class Database:
    """Thread-safe SQLite database manager for Fikrado Security."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Scans history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    duration_seconds REAL,
                    files_scanned INTEGER DEFAULT 0,
                    threats_found INTEGER DEFAULT 0,
                    status TEXT,
                    score INTEGER
                )
            """)

            # Detected threats table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS detected_threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    file_path TEXT,
                    threat_name TEXT,
                    threat_type TEXT,
                    severity TEXT,
                    detection_engine TEXT,
                    detected_at TEXT,
                    action_taken TEXT,
                    sha256 TEXT,
                    FOREIGN KEY(scan_id) REFERENCES scan_history(id)
                )
            """)

            # CISA KEV Vulnerabilities cache table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cisa_kev (
                    cve_id TEXT PRIMARY KEY,
                    vendor_project TEXT,
                    product TEXT,
                    vulnerability_name TEXT,
                    date_added TEXT,
                    short_description TEXT,
                    required_action TEXT,
                    due_date TEXT,
                    notes TEXT
                )
            """)

            # Local Known Signatures table (SHA-256)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS malware_signatures (
                    sha256 TEXT PRIMARY KEY,
                    threat_name TEXT,
                    threat_type TEXT,
                    severity TEXT,
                    source TEXT,
                    added_at TEXT
                )
            """)

            conn.commit()

    def record_scan_start(self, scan_type: str) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_history (scan_type, start_time, status)
                VALUES (?, ?, ?)
            """, (scan_type, time.strftime("%Y-%m-%d %H:%M:%S"), "Running"))
            conn.commit()
            return cursor.lastrowid

    def record_scan_finish(
        self,
        scan_id: int,
        files_scanned: int,
        threats_found: int,
        duration: float,
        score: int,
        status: str = "Completed"
    ):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE scan_history
                SET end_time = ?, duration_seconds = ?, files_scanned = ?, threats_found = ?, score = ?, status = ?
                WHERE id = ?
            """, (time.strftime("%Y-%m-%d %H:%M:%S"), duration, files_scanned, threats_found, score, status, scan_id))
            conn.commit()

    def record_threat(
        self,
        scan_id: Optional[int],
        file_path: str,
        threat_name: str,
        threat_type: str,
        severity: str,
        engine: str,
        action: str = "Detected",
        sha256: str = ""
    ) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO detected_threats (
                    scan_id, file_path, threat_name, threat_type, severity,
                    detection_engine, detected_at, action_taken, sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id, file_path, threat_name, threat_type, severity,
                engine, time.strftime("%Y-%m-%d %H:%M:%S"), action, sha256
            ))
            conn.commit()
            return cursor.lastrowid

    def get_recent_scans(self, limit: int = 20) -> List[dict]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scan_history ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_recent_threats(self, limit: int = 50) -> List[dict]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM detected_threats ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def cache_cisa_kev(self, vulnerabilities: List[dict]):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            for v in vulnerabilities:
                cursor.execute("""
                    INSERT OR REPLACE INTO cisa_kev (
                        cve_id, vendor_project, product, vulnerability_name,
                        date_added, short_description, required_action, due_date, notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    v.get("cveID"),
                    v.get("vendorProject"),
                    v.get("product"),
                    v.get("vulnerabilityName"),
                    v.get("dateAdded"),
                    v.get("shortDescription"),
                    v.get("requiredAction"),
                    v.get("dueDate"),
                    v.get("notes")
                ))
            conn.commit()
            logger.info(f"Cached {len(vulnerabilities)} CISA KEV items in database.")

    def search_cisa_kev(self, term: str) -> List[dict]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            q = f"%{term}%"
            cursor.execute("""
                SELECT * FROM cisa_kev
                WHERE product LIKE ? OR vendor_project LIKE ? OR cve_id LIKE ? OR vulnerability_name LIKE ?
                LIMIT 100
            """, (q, q, q, q))
            return [dict(row) for row in cursor.fetchall()]

    def count_stats(self) -> dict:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*), SUM(files_scanned), SUM(threats_found) FROM scan_history")
            total_scans, total_files, total_threats = cursor.fetchone()
            cursor.execute("SELECT COUNT(*) FROM detected_threats WHERE action_taken = 'Quarantined'")
            quarantined = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM cisa_kev")
            kev_count = cursor.fetchone()[0]

            return {
                "total_scans": total_scans or 0,
                "total_files": total_files or 0,
                "total_threats": total_threats or 0,
                "quarantined_count": quarantined or 0,
                "kev_count": kev_count or 0,
            }


db = Database()
