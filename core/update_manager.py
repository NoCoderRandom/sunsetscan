"""
NetWatch Update Manager.

Handles two update channels:
  Channel 1 — Tool updates: checks GitHub releases for new code versions.
  Channel 2 — Intelligence updates: refreshes data caches (EOL, CVE, Wappalyzer).

CLI flags:
    --check-version     Print latest available version and exit.
    --update            Pull latest code from GitHub and reinstall requirements.
    --update-cache      Refresh all intelligence caches (EOL + CVE + Wappalyzer).
    --cache-status      Show age and size of each cache file.

Exports:
    UpdateManager: Main class
"""

import json
import logging
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_REPO_URL = "https://github.com/NoCoderRandom/netwatch"
_RELEASES_API = "https://api.github.com/repos/NoCoderRandom/netwatch/releases/latest"
_PROJECT_ROOT = Path(__file__).parent.parent
_CACHE_DIR = _PROJECT_ROOT / "data" / "cache"
_META_FILE = _CACHE_DIR / "cache_meta.json"


class UpdateManager:
    """Manages tool and intelligence cache updates.

    Usage:
        mgr = UpdateManager()
        mgr.check_version()          # print latest GitHub release
        mgr.update_tool()            # git pull + pip install
        mgr.update_cache()           # refresh EOL + CVE caches
        mgr.show_cache_status()      # print cache ages
    """

    def __init__(self):
        self._meta = self._load_meta()

    # ------------------------------------------------------------------
    # Tool version checks
    # ------------------------------------------------------------------

    def get_current_version(self) -> str:
        from config.settings import Settings
        return Settings().version

    def get_latest_version(self) -> Optional[str]:
        """Fetch the latest released version tag from GitHub API."""
        try:
            import requests
            resp = requests.get(_RELEASES_API, timeout=10,
                                headers={"Accept": "application/vnd.github.v3+json"})
            if resp.status_code == 200:
                data = resp.json()
                return data.get("tag_name", "").lstrip("v")
        except Exception as e:
            logger.debug(f"Version check failed: {e}")
        return None

    def check_version(self) -> None:
        """Print current vs latest version."""
        current = self.get_current_version()
        latest = self.get_latest_version()
        print(f"  Current version : {current}")
        if latest:
            if latest != current:
                print(f"  Latest version  : {latest}  [update available — run --update]")
            else:
                print(f"  Latest version  : {latest}  [up to date]")
        else:
            print("  Latest version  : (could not reach GitHub — check internet connection)")

    def update_tool(self) -> int:
        """Pull latest code and reinstall requirements. Returns exit code."""
        print("Updating NetWatch tool code...")
        try:
            # Check git is available
            result = subprocess.run(["git", "rev-parse", "--git-dir"],
                                    capture_output=True, cwd=_PROJECT_ROOT)
            if result.returncode != 0:
                print("  ERROR: NetWatch directory is not a git repository.")
                print(f"  Clone from: {_REPO_URL}")
                return 1

            # Pull latest
            print("  Running: git pull")
            r = subprocess.run(["git", "pull"], cwd=_PROJECT_ROOT)
            if r.returncode != 0:
                print("  git pull failed — resolve conflicts manually.")
                return 1

            # Reinstall requirements
            req = _PROJECT_ROOT / "requirements.txt"
            if req.exists():
                print("  Running: pip install -r requirements.txt --quiet")
                subprocess.run([sys.executable, "-m", "pip", "install",
                                "-r", str(req), "--quiet"])
            print("  Tool updated successfully.")
            return 0
        except Exception as e:
            print(f"  Update failed: {e}")
            return 1

    # ------------------------------------------------------------------
    # Intelligence cache updates
    # ------------------------------------------------------------------

    def update_cache(self, quiet: bool = False) -> None:
        """Refresh EOL and CVE intelligence caches."""
        if not quiet:
            print("Refreshing intelligence caches...")
        self._update_eol_cache(quiet=quiet)
        self._update_cve_cache(quiet=quiet)
        self._update_wappalyzer_cache(quiet=quiet)
        self._save_meta()
        if not quiet:
            print("Cache refresh complete.")

    def _update_eol_cache(self, quiet: bool = False) -> None:
        """Re-fetch EOL data for all mapped products."""
        if not quiet:
            print("  Updating EOL cache...")
        try:
            import requests
            from eol.product_map import PRODUCT_MAP, NOT_TRACKED_PRODUCTS
            from eol.cache import CacheManager
            from config.settings import Settings

            cache = CacheManager(settings=Settings())
            session = requests.Session()
            session.headers.update({"User-Agent": "NetWatch/1.1.0"})
            products = list(set(v for v in PRODUCT_MAP.values()
                                if v not in NOT_TRACKED_PRODUCTS))
            ok = 0
            fail = 0
            for product in products:
                url = f"https://endoflife.date/api/{product}.json"
                try:
                    r = session.get(url, timeout=15)
                    if r.status_code == 200:
                        data = r.json()
                        cache.set(product, data)
                        ok += 1
                    else:
                        fail += 1
                except Exception:
                    fail += 1
            self._meta["eol_last_updated"] = datetime.now(timezone.utc).isoformat()
            if not quiet:
                print(f"    EOL cache: {ok} products updated, {fail} skipped.")
        except Exception as e:
            logger.error(f"EOL cache update failed: {e}")
            if not quiet:
                print(f"    EOL cache update failed: {e}")

    def _update_cve_cache(self, quiet: bool = False) -> None:
        """Refresh CVE cache by re-running the existing run_update_cache workflow."""
        if not quiet:
            print("  Updating CVE cache...")
        try:
            from core.cache_manager import UnifiedCacheManager
            from core.cve_checker import CVECacheBuilder
            um = UnifiedCacheManager()
            # Re-query all existing product:version pairs already in the cache
            existing_pairs = []
            for key in um.cve_data.keys():
                if ":" in str(key):
                    parts = str(key).split(":", 1)
                    existing_pairs.append((parts[0], parts[1]))
            if existing_pairs:
                builder = CVECacheBuilder(um)
                count = builder.build_cache(existing_pairs)
                if not quiet:
                    print(f"    CVE cache: {len(existing_pairs)} pairs refreshed, {count} vulnerabilities.")
            else:
                if not quiet:
                    print("    No existing CVE cache entries. Run --setup first.")
            self._meta["cve_osv_last_updated"] = datetime.now(timezone.utc).isoformat()
        except Exception as e:
            logger.error(f"CVE cache update failed: {e}")
            if not quiet:
                print(f"    CVE cache update failed: {e}")

    def _update_wappalyzer_cache(self, quiet: bool = False) -> None:
        """Download latest Wappalyzer technology fingerprints (all letter files merged)."""
        if not quiet:
            print("  Updating Wappalyzer fingerprints...")
        target = _CACHE_DIR / "wappalyzer_tech.json"
        base_url = (
            "https://raw.githubusercontent.com/enthec/webappanalyzer/"
            "main/src/technologies/"
        )
        try:
            import requests
            session = requests.Session()
            session.headers.update({"User-Agent": "NetWatch/1.2.0"})
            merged: dict = {}
            files = [f"{c}.json" for c in "_abcdefghijklmnopqrstuvwxyz"]
            for fname in files:
                try:
                    r = session.get(base_url + fname, timeout=15)
                    if r.status_code == 200:
                        data = r.json()
                        # Some files wrap in {"technologies": {...}}
                        if "technologies" in data:
                            data = data["technologies"]
                        merged.update(data)
                except Exception:
                    continue
            if merged:
                with open(target, "w", encoding="utf-8") as f:
                    json.dump(merged, f)
                self._meta["wappalyzer_last_updated"] = datetime.now(timezone.utc).isoformat()
                if not quiet:
                    print(f"    Wappalyzer fingerprints updated ({len(merged)} technologies).")
            else:
                if not quiet:
                    print("    Could not fetch Wappalyzer data (skipped).")
        except Exception as e:
            if not quiet:
                print(f"    Wappalyzer update failed: {e}")

    # ------------------------------------------------------------------
    # Cache status display
    # ------------------------------------------------------------------

    def show_cache_status(self) -> None:
        """Print a table of cache file ages and sizes."""
        print("\nNetWatch Cache Status")
        print("=" * 55)
        now = datetime.now(timezone.utc)

        def _age(ts_str: Optional[str]) -> str:
            if not ts_str:
                return "never"
            try:
                ts = datetime.fromisoformat(ts_str)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                delta = now - ts
                h = int(delta.total_seconds() // 3600)
                if h < 24:
                    return f"{h}h ago"
                return f"{delta.days}d ago"
            except Exception:
                return "unknown"

        def _size(path: Path) -> str:
            try:
                kb = path.stat().st_size // 1024
                return f"{kb:,} KB"
            except Exception:
                return "—"

        entries = [
            ("EOL cache",          _CACHE_DIR / "eol_cache.json",     self._meta.get("eol_last_updated")),
            ("CVE cache",          _CACHE_DIR / "cve_cache.json",      self._meta.get("cve_osv_last_updated")),
            ("Wappalyzer",         _CACHE_DIR / "wappalyzer_tech.json",self._meta.get("wappalyzer_last_updated")),
            ("JA3 signatures",     _CACHE_DIR / "ja3_signatures.json", self._meta.get("ja3_last_updated")),
        ]
        for name, path, last_ts in entries:
            exists = "[OK]" if path.exists() else "[--]"
            size = _size(path) if path.exists() else "not found"
            age = _age(last_ts)
            print(f"  {exists} {name:<22} {size:<12} last updated: {age}")
        print()

    # ------------------------------------------------------------------
    # Meta helpers
    # ------------------------------------------------------------------

    def _load_meta(self) -> dict:
        try:
            if _META_FILE.exists():
                with open(_META_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_meta(self) -> None:
        try:
            _CACHE_DIR.mkdir(parents=True, exist_ok=True)
            with open(_META_FILE, "w", encoding="utf-8") as f:
                json.dump(self._meta, f, indent=2)
        except Exception as e:
            logger.debug(f"Could not save cache meta: {e}")
