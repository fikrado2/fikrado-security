"""
Fikrado Security - Enterprise Logging Module
Logs all security events, scans, and system audits with log rotation to %APPDATA%/FikradoSecurity/logs.
"""
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from config.constants import LOGS_DIR

def setup_logger(name: str = "FikradoSecurity") -> logging.Logger:
    """Configures and returns the main application logger."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(threadName)s] [%(name)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # 1. Console Handler (INFO+)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # 2. Rotating File Handler (DEBUG+)
    log_file = LOGS_DIR / "fikrado_security.log"
    try:
        file_handler = RotatingFileHandler(
            filename=str(log_file),
            maxBytes=10 * 1024 * 1024,  # 10 MB per log
            backupCount=5,
            encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        console_handler.setLevel(logging.DEBUG)
        logger.warning(f"Failed to initialize rotating file handler at {log_file}: {e}")

    return logger

# Module-level default logger
logger = setup_logger()
