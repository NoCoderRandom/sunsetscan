"""
NetWatch OUI Vendor Lookup Module.

Loads the IEEE OUI database and provides MAC address → vendor name resolution.
The OUI (Organizationally Unique Identifier) is the first 3 octets of a MAC
address and uniquely identifies the hardware manufacturer.

Data sources (checked in order):
    1. Local cache at data/cache/mac_oui.json (downloaded by module_manager)
    2. Nmap's nmap-mac-prefixes file (if nmap is installed)

Exports:
    OUIDatabase:    Class that loads and queries the OUI database
    lookup_vendor:  Module-level convenience function
"""

import json
import logging
import re
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).parent.parent
_OUI_CACHE_PATH = _PROJECT_ROOT / "data" / "cache" / "mac_oui.json"
_NMAP_OUI_PATHS = [
    Path("/usr/share/nmap/nmap-mac-prefixes"),
    Path("/usr/local/share/nmap/nmap-mac-prefixes"),
    Path("/opt/homebrew/share/nmap/nmap-mac-prefixes"),
]


def _normalize_mac_prefix(mac: str) -> str:
    """Extract and normalize the first 3 octets of a MAC address.

    Accepts formats: AA:BB:CC:DD:EE:FF, AA-BB-CC-DD-EE-FF, AABBCCDDEEFF.
    Returns uppercase colon-separated prefix: "AA:BB:CC".
    """
    mac = mac.upper().strip()
    # Remove all separators
    clean = re.sub(r'[:\-.]', '', mac)
    if len(clean) < 6:
        return ""
    prefix = clean[:6]
    return f"{prefix[0:2]}:{prefix[2:4]}:{prefix[4:6]}"


class OUIDatabase:
    """IEEE OUI database for MAC vendor resolution.

    Lazily loads the database on first lookup. Thread-safe for reads
    after initial load.
    """

    def __init__(self):
        self._db: Optional[Dict[str, str]] = None

    def _load(self) -> Dict[str, str]:
        """Load OUI database from available sources. Returns {prefix: vendor}."""
        db: Dict[str, str] = {}

        # Source 1: Local JSON cache (from module_manager download)
        if _OUI_CACHE_PATH.exists():
            try:
                with open(_OUI_CACHE_PATH, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                # Handle both flat {prefix: vendor} and nested formats
                if isinstance(raw, dict):
                    for key, val in raw.items():
                        prefix = _normalize_mac_prefix(key)
                        if prefix:
                            vendor = val if isinstance(val, str) else str(val)
                            db[prefix] = vendor
                logger.debug(f"OUI database loaded from cache: {len(db)} entries")
                if db:
                    return db
            except Exception as e:
                logger.debug(f"OUI cache load failed: {e}")

        # Source 2: Nmap's mac-prefixes file
        for nmap_path in _NMAP_OUI_PATHS:
            if nmap_path.exists():
                try:
                    with open(nmap_path, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith("#"):
                                continue
                            parts = line.split(None, 1)
                            if len(parts) == 2:
                                hex_prefix = parts[0].upper()
                                vendor = parts[1].strip()
                                if len(hex_prefix) == 6:
                                    prefix = f"{hex_prefix[0:2]}:{hex_prefix[2:4]}:{hex_prefix[4:6]}"
                                    db[prefix] = vendor
                    logger.debug(f"OUI database loaded from nmap: {len(db)} entries ({nmap_path})")
                    if db:
                        return db
                except Exception as e:
                    logger.debug(f"Nmap OUI load failed ({nmap_path}): {e}")

        if not db:
            logger.warning("No OUI database available — vendor lookup will be limited")

        return db

    def lookup(self, mac: str) -> str:
        """Look up the vendor name for a MAC address.

        Args:
            mac: MAC address in any common format.

        Returns:
            Vendor name string, or empty string if not found.
        """
        if self._db is None:
            self._db = self._load()

        prefix = _normalize_mac_prefix(mac)
        if not prefix:
            return ""

        return self._db.get(prefix, "")

    @property
    def size(self) -> int:
        """Number of entries in the loaded database."""
        if self._db is None:
            self._db = self._load()
        return len(self._db)


# Module-level singleton and convenience function
_default_db = OUIDatabase()


def lookup_vendor(mac: str) -> str:
    """Look up vendor name for a MAC address.

    Convenience wrapper around OUIDatabase.lookup().

    Args:
        mac: MAC address (e.g., "AA:BB:CC:DD:EE:FF").

    Returns:
        Vendor name string, or "" if not found.
    """
    return _default_db.lookup(mac)
