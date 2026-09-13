"""
Q-Shield Configuration and Logging Module
Centralized parameters and environment configuration.
"""

import os
import logging
from pathlib import Path

# Base Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
VAULT_DIR = Path(os.getenv("QSHIELD_VAULT_DIR", PROJECT_ROOT / "vault_storage"))
KEYS_DIR = Path(os.getenv("QSHIELD_KEYS_DIR", PROJECT_ROOT / "vault_keys"))
RESTORE_DIR = Path(os.getenv("QSHIELD_RESTORE_DIR", PROJECT_ROOT / "restored_files"))

# Network Defaults
DEFAULT_HOST = os.getenv("QSHIELD_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.getenv("QSHIELD_PORT", "9123"))

# Cryptographic Tuning
STREAM_CHUNK_SIZE = 64 * 1024  # 64 KB
PBKDF2_ROUNDS = 600_000        # OWASP recommendation
TIMESTAMP_TOLERANCE_SECONDS = 30.0

def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configures centralized logging for Q-Shield framework."""
    logger = logging.getLogger("qshield")
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger
