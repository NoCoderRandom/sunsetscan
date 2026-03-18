"""
NetWatch Unified Cache Manager.

Manages CVE and EOL data caches with TTL enforcement.
All scans read ONLY from local cache — no external calls happen during scanning.

Cache files (relative to project root):
    data/cache/cve_cache.json   - CVE results keyed by "product:version"
    data/cache/eol_cache.json   - EOL data keyed by product slug
    data/cache/cache_meta.json  - Timestamps of last successful updates

TTL rules:
    CVE data:  7 days maximum before --update-cache is needed
    EOL data:  30 days maximum before --update-cache is needed

The tool continues working offline using stale cached data and warns
the user with a non-blocking message if the data is outdated.
"""

import json
import logging
import socket
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# TTL constants
CVE_TTL_DAYS = 7
EOL_TTL_DAYS = 30

# Resolve cache directory relative to this file's location (core/ -> project root -> data/cache)
_PROJECT_ROOT = Path(__file__).parent.parent
CACHE_DIR = _PROJECT_ROOT / "data" / "cache"


class UnifiedCacheManager:
    """Unified cache layer for CVE and EOL data.

    Stores all data in three simple JSON files.
    Uses lazy loading — files are only read from disk when first accessed.

    Example:
        cache = UnifiedCacheManager()

        # Store CVE results
        cache.set_cve("openssh", "7.4", vulns_list, source="osv")

        # Read CVE results (returns None if not cached)
        vulns = cache.get_cve("openssh", "7.4")

        # Check if cache is fresh
        if not cache.is_cve_cache_current():
            print("Run --update-cache to refresh")
    """

    def __init__(self, cache_dir: Optional[Path] = None):
        self.cache_dir = Path(cache_dir) if cache_dir else CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self._cve_path = self.cache_dir / "cve_cache.json"
        self._eol_path = self.cache_dir / "eol_cache.json"
        self._meta_path = self.cache_dir / "cache_meta.json"

        # Lazy-loaded in-memory copies
        self._cve_data: Optional[Dict] = None
        self._eol_data: Optional[Dict] = None
        self._meta: Optional[Dict] = None

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _load_json(self, path: Path) -> Dict:
        """Load a JSON file, returning empty dict if missing or corrupt."""
        if not path.exists():
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError, ValueError) as e:
            logger.warning(f"Cache file unreadable, starting fresh: {path}: {e}")
            return {}

    def _save_json(self, path: Path, data: Dict) -> bool:
        """Write data to a JSON file atomically."""
        try:
            # Write to a temp file then rename to avoid corrupt writes on crash
            tmp = path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            tmp.replace(path)
            return True
        except OSError as e:
            logger.error(f"Failed to write cache file {path}: {e}")
            return False

    # -------------------------------------------------------------------------
    # Lazy-loaded data properties
    # -------------------------------------------------------------------------

    @property
    def cve_data(self) -> Dict:
        if self._cve_data is None:
            self._cve_data = self._load_json(self._cve_path)
        return self._cve_data

    @property
    def eol_data(self) -> Dict:
        if self._eol_data is None:
            self._eol_data = self._load_json(self._eol_path)
        return self._eol_data

    @property
    def meta(self) -> Dict:
        if self._meta is None:
            self._meta = self._load_json(self._meta_path)
        return self._meta

    # -------------------------------------------------------------------------
    # CVE cache operations
    # -------------------------------------------------------------------------

    def get_cve(self, product: str, version: str) -> Optional[List[Dict]]:
        """Retrieve cached CVE entries for a product:version pair.

        Returns:
            List of CVE dicts if cached (may be empty list = no CVEs found).
            None if no cache entry exists for this product:version.
        """
        key = f"{product.lower().strip()}:{version.lower().strip()}"
        entry = self.cve_data.get(key)
        if entry is None:
            return None
        return entry.get("vulns", [])

    def set_cve(
        self,
        product: str,
        version: str,
        vulns: List[Dict],
        source: str = "osv",
    ) -> None:
        """Store CVE results for a product:version pair."""
        key = f"{product.lower().strip()}:{version.lower().strip()}"
        self.cve_data[key] = {
            "queried_at": datetime.now().isoformat(),
            "source": source,
            "vulns": vulns,
        }
        self._save_json(self._cve_path, self.cve_data)

    # -------------------------------------------------------------------------
    # EOL cache operations
    # -------------------------------------------------------------------------

    def get_eol(self, product: str) -> Optional[Any]:
        """Retrieve cached EOL data for a product slug.

        Returns None if not cached or if the entry is older than EOL_TTL_DAYS.
        """
        entry = self.eol_data.get(product.lower().strip())
        if entry is None:
            return None
        try:
            cached_at = datetime.fromisoformat(entry["cached_at"])
            if datetime.now() - cached_at > timedelta(days=EOL_TTL_DAYS):
                logger.debug(f"EOL cache expired for {product}")
                return None
        except (KeyError, ValueError, TypeError):
            return None
        return entry.get("data")

    def set_eol(self, product: str, data: Any) -> None:
        """Store EOL data for a product slug."""
        self.eol_data[product.lower().strip()] = {
            "cached_at": datetime.now().isoformat(),
            "data": data,
        }
        self._save_json(self._eol_path, self.eol_data)

    def eol_product_count(self) -> int:
        """Return number of products with cached EOL data."""
        return len(self.eol_data)

    # -------------------------------------------------------------------------
    # Metadata (update timestamps, etc.)
    # -------------------------------------------------------------------------

    def get_meta(self, key: str) -> Optional[str]:
        return self.meta.get(key)

    def set_meta(self, key: str, value: str) -> None:
        self.meta[key] = value
        self._save_json(self._meta_path, self.meta)

    def mark_cve_updated(self) -> None:
        """Record that the CVE cache was just refreshed."""
        self.set_meta("cve_osv_last_updated", datetime.now().isoformat())

    def mark_eol_updated(self) -> None:
        """Record that the EOL cache was just refreshed."""
        self.set_meta("eol_last_updated", datetime.now().isoformat())

    # -------------------------------------------------------------------------
    # Freshness checks
    # -------------------------------------------------------------------------

    def is_cve_cache_current(self) -> bool:
        """Return True if CVE cache was updated within CVE_TTL_DAYS."""
        last = self.meta.get("cve_osv_last_updated")
        if not last:
            return False
        try:
            updated = datetime.fromisoformat(last)
            return datetime.now() - updated < timedelta(days=CVE_TTL_DAYS)
        except (ValueError, TypeError):
            return False

    def is_eol_cache_current(self) -> bool:
        """Return True if EOL cache was updated within EOL_TTL_DAYS."""
        last = self.meta.get("eol_last_updated")
        if not last:
            return False
        try:
            updated = datetime.fromisoformat(last)
            return datetime.now() - updated < timedelta(days=EOL_TTL_DAYS)
        except (ValueError, TypeError):
            return False

    def get_cve_cache_age_days(self) -> Optional[int]:
        """Return age of CVE cache in days, or None if never updated."""
        last = self.meta.get("cve_osv_last_updated")
        if not last:
            return None
        try:
            updated = datetime.fromisoformat(last)
            return (datetime.now() - updated).days
        except (ValueError, TypeError):
            return None

    def get_eol_cache_age_days(self) -> Optional[int]:
        """Return age of EOL cache in days, or None if never updated."""
        last = self.meta.get("eol_last_updated")
        if not last:
            return None
        try:
            updated = datetime.fromisoformat(last)
            return (datetime.now() - updated).days
        except (ValueError, TypeError):
            return None

    def cve_entry_count(self) -> int:
        """Return number of product:version entries in the CVE cache."""
        return len(self.cve_data)

    # -------------------------------------------------------------------------
    # Offline detection
    # -------------------------------------------------------------------------

    def check_online(self, timeout: float = 2.0) -> bool:
        """Quick connectivity check by attempting TCP to 8.8.8.8:53.

        Non-blocking. Returns False on any error.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(("8.8.8.8", 53))
            sock.close()
            return True
        except (socket.error, OSError):
            return False

    # -------------------------------------------------------------------------
    # Status summary
    # -------------------------------------------------------------------------

    def get_cache_status(self) -> Dict[str, Any]:
        """Return a human-readable summary dict of the cache state."""
        return {
            "cve_cache_entries": self.cve_entry_count(),
            "cve_cache_age_days": self.get_cve_cache_age_days(),
            "cve_cache_current": self.is_cve_cache_current(),
            "eol_cache_entries": self.eol_product_count(),
            "eol_cache_age_days": self.get_eol_cache_age_days(),
            "eol_cache_current": self.is_eol_cache_current(),
            "cache_dir": str(self.cache_dir),
        }

    def stale_warnings(self) -> List[str]:
        """Return a list of human-readable stale cache warnings (may be empty)."""
        warnings: List[str] = []
        cve_age = self.get_cve_cache_age_days()
        eol_age = self.get_eol_cache_age_days()

        if cve_age is None:
            warnings.append(
                "CVE data has never been downloaded. Run: python netwatch.py --setup"
            )
        elif not self.is_cve_cache_current():
            warnings.append(
                f"CVE data is {cve_age} days old (max {CVE_TTL_DAYS}). "
                "Run: python netwatch.py --update-cache"
            )

        if eol_age is None:
            warnings.append(
                "EOL data has never been downloaded. Run: python netwatch.py --setup"
            )
        elif not self.is_eol_cache_current():
            warnings.append(
                f"EOL data is {eol_age} days old (max {EOL_TTL_DAYS}). "
                "Run: python netwatch.py --update-cache"
            )

        return warnings

    def reload(self) -> None:
        """Force reload all in-memory caches from disk (e.g. after --update-cache)."""
        self._cve_data = None
        self._eol_data = None
        self._meta = None
