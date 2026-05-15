"""
SunsetScan Module Manager.

Central controller for downloadable data modules. Each module represents
a dataset sourced from a maintained public repository or first-party SunsetScan
artifact.

CODE = logic only
DATA = downloaded from trusted public sources

Modules:
    credentials-mini     Top 50 default credentials (from SecLists)
    credentials-full     2860+ credentials all vendors (from DefaultCreds-cheat-sheet)
    wappalyzer-mini      Top 500 web technologies (from enthec/webappanalyzer)
    wappalyzer-full      All 7515 technologies (from enthec/webappanalyzer)
    ja3-signatures       TLS fingerprint database (from salesforce/ja3)
    snmp-community       Extended SNMP community strings (from SecLists)
    camera-credentials   IP camera default credentials (from many-passwords)
    hardware-eol-home    Default smart-pack home hardware lifecycle profile
    hardware-eol         Legacy full hardware lifecycle database compatibility module
    hardware-eol-office  Smart-pack home plus small-office profile
    hardware-eol-enterprise
                         Smart-pack home, office, and enterprise profile
    hardware-eol-industrial
                         Smart-pack home, office, and industrial/OT profile
    hardware-eol-service-provider
                         Smart-pack home, office, enterprise, and provider profile
    hardware-eol-full    Full smart-pack hardware lifecycle profile

CLI:
    python3 sunsetscan.py --modules          List all modules with status
    python3 sunsetscan.py --download <name>  Download a specific module
    python3 sunsetscan.py --download all     Download all modules with full hardware EOL profile
"""

import csv
import gzip
import hashlib
import io
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config.settings import Settings

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).parent.parent
_CACHE_DIR = _PROJECT_ROOT / "data" / "cache"
_MODULES_META_PATH = _CACHE_DIR / "modules.json"

# TTL for downloaded module data (days)
MODULE_TTL_DAYS = 30

_HARDWARE_EOL_BASE_URL = "https://raw.githubusercontent.com/NoCoderRandom/sunsetscan/main/data/hardware_eol"
_HARDWARE_EOL_MANIFEST_URL = f"{_HARDWARE_EOL_BASE_URL}/manifest.json.gz"
_HARDWARE_EOL_CACHE_ROOT = "data/cache/hardware_eol"


def _hardware_eol_profile(
    *,
    description: str,
    packs: List[str],
    size_estimate: str,
    default: bool = False,
) -> Dict[str, Any]:
    return {
        "description": description,
        "source": "NoCoderRandom/sunsetscan",
        "url": _HARDWARE_EOL_MANIFEST_URL,
        "local_path": f"{_HARDWARE_EOL_CACHE_ROOT}/manifest.json",
        "size_estimate": size_estimate,
        "default": default,
        "parser": "_parse_hardware_eol_manifest",
        "binary": True,
        "hardware_profile": True,
        "packs": packs,
        "license": "CC BY-NC 4.0",
        "license_url": "https://creativecommons.org/licenses/by-nc/4.0/",
    }


# ---------------------------------------------------------------------------
# Module definitions
# ---------------------------------------------------------------------------

MODULE_REGISTRY: Dict[str, Dict[str, Any]] = {
    "credentials-mini": {
        "description": "Top 50 default credentials",
        "source": "danielmiessler/SecLists",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/default-passwords.csv",
        "local_path": "data/cache/credentials_mini.json",
        "size_estimate": "50KB",
        "default": True,
        "parser": "_parse_credentials_mini",
    },
    "credentials-full": {
        "description": "2860+ credentials all vendors",
        "source": "ihebski/DefaultCreds-cheat-sheet",
        "url": "https://raw.githubusercontent.com/ihebski/DefaultCreds-cheat-sheet/main/DefaultCreds-Cheat-Sheet.csv",
        "local_path": "data/cache/credentials_full.json",
        "size_estimate": "800KB",
        "default": False,
        "parser": "_parse_credentials_full",
    },
    "wappalyzer-mini": {
        "description": "Top 500 web technologies",
        "source": "enthec/webappanalyzer",
        "url": "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/",
        "local_path": "data/cache/wappalyzer_mini.json",
        "size_estimate": "200KB",
        "default": True,
        "parser": "_parse_wappalyzer_mini",
    },
    "wappalyzer-full": {
        "description": "All 7515 technologies",
        "source": "enthec/webappanalyzer",
        "url": "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/",
        "local_path": "data/cache/wappalyzer_tech.json",
        "size_estimate": "2MB",
        "default": False,
        "parser": "_parse_wappalyzer_full",
    },
    "ja3-signatures": {
        "description": "TLS fingerprint database",
        "source": "salesforce/ja3",
        "url": "https://raw.githubusercontent.com/salesforce/ja3/master/lists/osx-nix-ja3.csv",
        "local_path": "data/cache/ja3_signatures.json",
        "size_estimate": "1MB",
        "default": False,
        "parser": "_parse_ja3_signatures",
    },
    "snmp-community": {
        "description": "Extended SNMP community strings",
        "source": "danielmiessler/SecLists",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/SNMP/common-snmp-community-strings.txt",
        "local_path": "data/cache/snmp_communities.json",
        "size_estimate": "10KB",
        "default": False,
        "parser": "_parse_snmp_communities",
    },
    "camera-credentials": {
        "description": "IP camera default credentials",
        "source": "many-passwords/many-passwords",
        "url": "https://raw.githubusercontent.com/many-passwords/many-passwords/main/passwords.csv",
        "local_path": "data/cache/camera_credentials.json",
        "size_estimate": "100KB",
        "default": False,
        "parser": "_parse_camera_credentials",
    },
    "mac-oui": {
        "description": "IEEE MAC address OUI vendor database",
        "source": "IEEE Standards Association",
        "url": "https://standards-oui.ieee.org/oui/oui.csv",
        "local_path": "data/cache/mac_oui.json",
        "size_estimate": "4MB",
        "default": True,
        "parser": "_parse_mac_oui",
    },
    "hardware-eol": {
        "description": "Legacy full network hardware lifecycle/EOL database compatibility module (CC BY-NC 4.0)",
        "source": "NoCoderRandom/sunsetscan",
        "url": "https://raw.githubusercontent.com/NoCoderRandom/sunsetscan/main/data/hardware_eol/sunsetscan_hardware_eol_index.json.gz",
        "local_path": "data/cache/hardware_eol/sunsetscan_hardware_eol_index.json",
        "size_estimate": "21MB download / split installed",
        "default": False,
        "parser": "_parse_hardware_eol",
        "binary": True,
        "parts": [
            {
                "category": "network_infrastructure",
                "url": "https://raw.githubusercontent.com/NoCoderRandom/sunsetscan/main/data/hardware_eol/records/network_infrastructure.json.gz",
                "local_path": "data/cache/hardware_eol/records/network_infrastructure.json",
            },
            {
                "category": "general_network_devices",
                "url": "https://raw.githubusercontent.com/NoCoderRandom/sunsetscan/main/data/hardware_eol/records/general_network_devices.json.gz",
                "local_path": "data/cache/hardware_eol/records/general_network_devices.json",
            },
            {
                "category": "security_surveillance",
                "url": "https://raw.githubusercontent.com/NoCoderRandom/sunsetscan/main/data/hardware_eol/records/security_surveillance.json.gz",
                "local_path": "data/cache/hardware_eol/records/security_surveillance.json",
            },
            {
                "category": "endpoints_peripherals",
                "url": "https://raw.githubusercontent.com/NoCoderRandom/sunsetscan/main/data/hardware_eol/records/endpoints_peripherals.json.gz",
                "local_path": "data/cache/hardware_eol/records/endpoints_peripherals.json",
            },
            {
                "category": "software_services_modules",
                "url": "https://raw.githubusercontent.com/NoCoderRandom/sunsetscan/main/data/hardware_eol/records/software_services_modules.json.gz",
                "local_path": "data/cache/hardware_eol/records/software_services_modules.json",
            },
        ],
        "license": "CC BY-NC 4.0",
        "license_url": "https://creativecommons.org/licenses/by-nc/4.0/",
    },
    "hardware-eol-home": _hardware_eol_profile(
        description="Home/SOHO hardware lifecycle/EOL database profile (CC BY-NC 4.0)",
        packs=["home"],
        size_estimate="~5MB download / smart-pack installed",
        default=True,
    ),
    "hardware-eol-office": _hardware_eol_profile(
        description="Home plus small-office hardware lifecycle/EOL profile (CC BY-NC 4.0)",
        packs=["home", "office"],
        size_estimate="~6.5MB download / smart-pack installed",
    ),
    "hardware-eol-enterprise": _hardware_eol_profile(
        description="Home, office, and enterprise hardware lifecycle/EOL profile (CC BY-NC 4.0)",
        packs=["home", "office", "enterprise"],
        size_estimate="~20MB download / smart-pack installed",
    ),
    "hardware-eol-industrial": _hardware_eol_profile(
        description="Home, office, and industrial/OT hardware lifecycle/EOL profile (CC BY-NC 4.0)",
        packs=["home", "office", "industrial_ot"],
        size_estimate="~7MB download / smart-pack installed",
    ),
    "hardware-eol-service-provider": _hardware_eol_profile(
        description="Home, office, enterprise, and service-provider lifecycle/EOL profile (CC BY-NC 4.0)",
        packs=["home", "office", "enterprise", "service_provider"],
        size_estimate="~22MB download / smart-pack installed",
    ),
    "hardware-eol-full": _hardware_eol_profile(
        description="Full smart-pack hardware lifecycle/EOL database profile (CC BY-NC 4.0)",
        packs=["home", "office", "enterprise", "industrial_ot", "service_provider"],
        size_estimate="~22MB download / smart-pack installed",
    ),
}

# Top 500 web technologies by usage frequency (used for wappalyzer-mini)
# These are the most commonly encountered technologies on the internet
_TOP_TECH_KEYWORDS = [
    "jQuery", "Bootstrap", "React", "WordPress", "PHP", "Apache", "Nginx",
    "Google Analytics", "Font Awesome", "Google Tag Manager", "MySQL",
    "CloudFlare", "Vue.js", "Angular", "Express", "Node.js", "Python",
    "Ruby on Rails", "Laravel", "Django", "ASP.NET", "Spring", "Drupal",
    "Joomla", "Magento", "Shopify", "Wix", "Squarespace", "Cloudflare",
    "Amazon Web Services", "Google Cloud", "Microsoft Azure", "Nginx",
    "Apache HTTP Server", "LiteSpeed", "IIS", "Tomcat", "Caddy",
    "OpenSSL", "mod_ssl", "Let's Encrypt", "Varnish", "Redis",
    "Memcached", "PostgreSQL", "MongoDB", "MariaDB", "SQLite",
    "Elasticsearch", "Grafana", "Prometheus", "Docker", "Kubernetes",
    "Jenkins", "GitLab", "GitHub", "Webpack", "Babel",
]


# ---------------------------------------------------------------------------
# Parser functions — convert raw download data to SunsetScan JSON format
# ---------------------------------------------------------------------------

def _parse_credentials_mini(raw_text: str) -> List[Dict]:
    """Parse SecLists default-passwords.csv and extract top 50 most common."""
    entries = []
    try:
        reader = csv.reader(io.StringIO(raw_text))
        for row in reader:
            if not row or len(row) < 2:
                continue
            # Skip header-like rows
            if row[0].lower().strip() in ("vendor", "product", "#", ""):
                continue
            # Format varies: some have vendor,user,pass — others user,pass
            if len(row) >= 3:
                vendor = row[0].strip()
                username = row[1].strip()
                password = row[2].strip()
            else:
                vendor = "generic"
                username = row[0].strip()
                password = row[1].strip()
            if username or password:
                entries.append({
                    "vendor": vendor,
                    "username": username,
                    "password": password,
                })
    except Exception as e:
        logger.warning(f"credentials-mini parse error: {e}")

    # Deduplicate by (vendor, username, password) and take top 50
    seen = set()
    unique = []
    for e in entries:
        key = (e["vendor"].lower(), e["username"], e["password"])
        if key not in seen:
            seen.add(key)
            unique.append(e)

    # Prioritize common ones
    priority_users = {"admin", "root", "user", "guest", "default", "ubnt", "cisco", "pi"}
    priority = [e for e in unique if e["username"].lower() in priority_users]
    rest = [e for e in unique if e["username"].lower() not in priority_users]
    result = (priority + rest)[:50]

    return result


def _parse_credentials_full(raw_text: str) -> List[Dict]:
    """Parse DefaultCreds-cheat-sheet CSV — all entries."""
    entries = []
    try:
        reader = csv.reader(io.StringIO(raw_text))
        header_skipped = False
        for row in reader:
            if not row or len(row) < 3:
                continue
            if not header_skipped:
                if row[0].lower().strip() in ("product", "vendor", "#"):
                    header_skipped = True
                    continue
            product = row[0].strip()
            username = row[1].strip()
            password = row[2].strip()
            if username or password:
                entries.append({
                    "vendor": product,
                    "username": username,
                    "password": password,
                })
    except Exception as e:
        logger.warning(f"credentials-full parse error: {e}")
    return entries


def _parse_wappalyzer_mini(raw_text: str) -> Dict:
    """Parse Wappalyzer full data and extract top 500 technologies."""
    # raw_text here is actually a merged dict (special handling in download)
    # This parser is called with the merged JSON text
    try:
        data = json.loads(raw_text) if isinstance(raw_text, str) else raw_text
    except (json.JSONDecodeError, TypeError):
        return {}

    if "technologies" in data:
        data = data["technologies"]

    # Score technologies: prefer those with header patterns (more reliable)
    scored = []
    for name, tech in data.items():
        if not isinstance(tech, dict):
            continue
        score = 0
        if tech.get("headers"):
            score += 10
        if tech.get("html"):
            score += 5
        if tech.get("cookies"):
            score += 3
        # Boost well-known technologies
        if any(kw.lower() in name.lower() for kw in _TOP_TECH_KEYWORDS):
            score += 20
        scored.append((score, name, tech))

    scored.sort(key=lambda x: x[0], reverse=True)
    result = {}
    for _, name, tech in scored[:500]:
        result[name] = tech
    return result


def _parse_wappalyzer_full(raw_text: str) -> Dict:
    """Parse full Wappalyzer data — all technologies."""
    try:
        data = json.loads(raw_text) if isinstance(raw_text, str) else raw_text
    except (json.JSONDecodeError, TypeError):
        return {}
    if "technologies" in data:
        data = data["technologies"]
    return data


def _parse_ja3_signatures(raw_text: str) -> List[Dict]:
    """Parse JA3 CSV to list of signature dicts."""
    entries = []
    try:
        reader = csv.reader(io.StringIO(raw_text))
        for row in reader:
            if not row:
                continue
            md5 = row[0].strip().strip('"')
            if len(md5) == 32 and all(c in "0123456789abcdefABCDEF" for c in md5):
                app = row[1].strip().strip('"') if len(row) > 1 else ""
                desc = row[2].strip().strip('"') if len(row) > 2 else ""
                entries.append({"md5": md5.lower(), "App": app, "Desc": desc})
    except Exception as e:
        logger.warning(f"ja3-signatures parse error: {e}")
    return entries


def _parse_snmp_communities(raw_text: str) -> List[str]:
    """Parse plain text community string list."""
    strings = []
    for line in raw_text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            strings.append(line)
    return strings


def _parse_camera_credentials(raw_text: str) -> List[Dict]:
    """Parse many-passwords CSV, filtering for camera/video entries."""
    entries = []
    camera_keywords = [
        "camera", "cam", "video", "surveillance", "dvr", "nvr", "ipcam",
        "hikvision", "dahua", "axis", "foscam", "amcrest", "reolink",
        "vivotek", "hanwha", "samsung techwin", "bosch", "avigilon",
        "pelco", "cctv", "ip cam", "wyze", "ring", "arlo", "eufy",
        "onvif", "rtsp",
    ]
    try:
        reader = csv.reader(io.StringIO(raw_text))
        for row in reader:
            if not row or len(row) < 5:
                continue
            # Skip header
            if row[0].lower().strip() in ("vendor", "#"):
                continue
            vendor = row[0].strip()
            model = row[1].strip() if len(row) > 1 else ""
            username = row[4].strip() if len(row) > 4 else ""
            password = row[5].strip() if len(row) > 5 else ""
            # Filter for camera-related entries
            combined = f"{vendor} {model}".lower()
            if any(kw in combined for kw in camera_keywords):
                if username or password:
                    entries.append({
                        "vendor": vendor,
                        "model": model,
                        "username": username,
                        "password": password,
                    })
    except Exception as e:
        logger.warning(f"camera-credentials parse error: {e}")
    return entries


def _parse_mac_oui(raw_text: str) -> Dict:
    """Parse IEEE OUI CSV into {MAC_PREFIX: vendor_name} mapping.

    The IEEE CSV has columns: Registry, Assignment (hex prefix),
    Organization Name, Organization Address.
    We extract the 3-byte OUI prefix and map it to the organization name.
    """
    oui_map: Dict[str, str] = {}
    try:
        reader = csv.reader(io.StringIO(raw_text))
        header_skipped = False
        for row in reader:
            if not row or len(row) < 3:
                continue
            # Skip header row
            if not header_skipped:
                if row[0].strip().lower() in ("registry", ""):
                    header_skipped = True
                    continue
                header_skipped = True
            # Column 1 = hex assignment (e.g. "AABBCC"), Column 2 = org name
            hex_prefix = row[1].strip().upper()
            org_name = row[2].strip()
            if len(hex_prefix) == 6 and org_name:
                # Convert AABBCC to AA:BB:CC
                formatted = f"{hex_prefix[0:2]}:{hex_prefix[2:4]}:{hex_prefix[4:6]}"
                oui_map[formatted] = org_name
    except Exception as e:
        logger.warning(f"mac-oui parse error: {e}")
    logger.info(f"Parsed {len(oui_map)} OUI entries from IEEE database")
    return oui_map


def _decode_json_payload(raw_data) -> Any:
    if isinstance(raw_data, bytes):
        try:
            raw_text = gzip.decompress(raw_data).decode("utf-8")
        except OSError:
            raw_text = raw_data.decode("utf-8")
    else:
        raw_text = raw_data
    return json.loads(raw_text)


def _parse_hardware_eol(raw_data) -> Dict:
    """Parse a SunsetScan hardware EOL monolith or split index artifact."""
    try:
        data = _decode_json_payload(raw_data)
    except Exception as e:
        logger.warning(f"hardware-eol parse error: {e}")
        return {}

    monolith_required = ("metadata", "summary", "indexes", "records", "model_summaries")
    split_required = (
        "metadata",
        "summary",
        "indexes",
        "model_summaries",
        "record_shards",
        "record_locations",
    )
    if not (
        all(key in data for key in monolith_required)
        or all(key in data for key in split_required)
    ):
        logger.warning("hardware-eol parse error: missing required database sections")
        return {}
    return data


def _parse_hardware_eol_shard(raw_data) -> Dict:
    """Parse one split hardware EOL record shard."""
    try:
        data = _decode_json_payload(raw_data)
    except Exception as e:
        logger.warning(f"hardware-eol shard parse error: {e}")
        return {}

    if "records" not in data or "category" not in data:
        logger.warning("hardware-eol shard parse error: missing required shard sections")
        return {}
    return data


def _parse_hardware_eol_manifest(raw_data) -> Dict:
    """Parse a smart-pack hardware EOL manifest artifact."""
    try:
        data = _decode_json_payload(raw_data)
    except Exception as e:
        logger.warning(f"hardware-eol manifest parse error: {e}")
        return {}

    if "packs" not in data or "profiles" not in data or "metadata" not in data:
        logger.warning("hardware-eol manifest parse error: missing required sections")
        return {}
    return data


def _entry_count(parsed: Any, module_name: str = "") -> int:
    """Return a human-useful entry count for module metadata/output."""
    if module_name.startswith("hardware-eol") and isinstance(parsed, dict):
        summary = parsed.get("summary") or {}
        count = summary.get("total_records")
        if isinstance(count, int):
            return count
        packs = parsed.get("packs") or {}
        if isinstance(packs, dict):
            total = 0
            selected_packs = (MODULE_REGISTRY.get(module_name) or {}).get("packs") or packs.keys()
            for pack_name in selected_packs:
                pack = packs.get(pack_name)
                count = pack.get("record_count") if isinstance(pack, dict) else None
                if isinstance(count, int):
                    total += count
            if total:
                return total
    if isinstance(parsed, (list, dict)):
        return len(parsed)
    return 0


# Map parser names to functions
_PARSERS = {
    "_parse_credentials_mini": _parse_credentials_mini,
    "_parse_credentials_full": _parse_credentials_full,
    "_parse_wappalyzer_mini": _parse_wappalyzer_mini,
    "_parse_wappalyzer_full": _parse_wappalyzer_full,
    "_parse_ja3_signatures": _parse_ja3_signatures,
    "_parse_snmp_communities": _parse_snmp_communities,
    "_parse_camera_credentials": _parse_camera_credentials,
    "_parse_mac_oui": _parse_mac_oui,
    "_parse_hardware_eol": _parse_hardware_eol,
    "_parse_hardware_eol_manifest": _parse_hardware_eol_manifest,
}


# ---------------------------------------------------------------------------
# ModuleManager class
# ---------------------------------------------------------------------------

class ModuleManager:
    """Central controller for downloadable data modules.

    Usage:
        mm = ModuleManager()
        mm.show_modules()               # Print status table
        mm.download("credentials-full")  # Download a module
        mm.download_all()                # Download all optional modules

        creds = mm.get_credentials()     # Get best available credentials
        communities = mm.get_snmp_communities()
    """

    def __init__(self):
        try:
            _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.error("Could not create module cache directory %s: %s", _CACHE_DIR, e)
        self._meta = self._load_meta()

    # ------------------------------------------------------------------
    # Metadata persistence
    # ------------------------------------------------------------------

    def _load_meta(self) -> Dict:
        if _MODULES_META_PATH.exists():
            try:
                with open(_MODULES_META_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_meta(self) -> None:
        try:
            with open(_MODULES_META_PATH, "w", encoding="utf-8") as f:
                json.dump(self._meta, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save modules.json: {e}")

    def is_installed(self, module_name: str) -> bool:
        """Check if a module is installed (file exists on disk)."""
        info = MODULE_REGISTRY.get(module_name)
        if not info:
            return False
        if info.get("hardware_profile"):
            return self._hardware_profile_installed(info)
        path = _PROJECT_ROOT / info["local_path"]
        if info.get("parts"):
            if not (path.exists() and path.stat().st_size > 0):
                return False
            for part in info["parts"]:
                part_path = _PROJECT_ROOT / part["local_path"]
                if not (part_path.exists() and part_path.stat().st_size > 0):
                    return False
            return True
        return path.exists() and path.stat().st_size > 0

    def get_installed_at(self, module_name: str) -> Optional[str]:
        """Return ISO date when module was last downloaded, or None."""
        entry = self._meta.get(module_name, {})
        return entry.get("installed_at")

    def is_expired(self, module_name: str) -> bool:
        """Return True if module data is older than TTL."""
        installed_at = self.get_installed_at(module_name)
        if not installed_at:
            return True
        try:
            dt = datetime.fromisoformat(installed_at)
            age = (datetime.now() - dt).days
            return age > MODULE_TTL_DAYS
        except (ValueError, TypeError):
            return True

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    def show_modules(self) -> None:
        """Print module status table to stdout."""
        try:
            from rich.console import Console
            from rich.table import Table
            console = Console()

            table = Table(title="SunsetScan Modules", show_header=True)
            table.add_column("Module", style="bold")
            table.add_column("Size", justify="right")
            table.add_column("Status", justify="center")
            table.add_column("Description")

            for name, info in MODULE_REGISTRY.items():
                installed = self.is_installed(name)
                expired = self.is_expired(name) if installed else False
                if installed and not expired:
                    status = "[green]installed[/green]"
                elif installed and expired:
                    status = "[yellow]expired[/yellow]"
                else:
                    status = "[dim]not installed[/dim]"
                table.add_row(name, info["size_estimate"], status, info["description"])

            console.print(table)
            console.print("\nInstall: [bold]python3 sunsetscan.py --download <module>[/bold]")
            console.print("Install all: [bold]python3 sunsetscan.py --download all[/bold]")
        except ImportError:
            # Fallback without rich
            print(f"{'Module':<24} {'Size':>6}  {'Status':<15} Description")
            print("-" * 80)
            for name, info in MODULE_REGISTRY.items():
                installed = self.is_installed(name)
                status = "installed" if installed else "not installed"
                print(f"{name:<24} {info['size_estimate']:>6}  {status:<15} {info['description']}")

    # ------------------------------------------------------------------
    # Download
    # ------------------------------------------------------------------

    def _download_targets(self, module_name: str) -> List[Path]:
        """Return files that must be writable to install a module."""
        info = MODULE_REGISTRY[module_name]
        targets = [_PROJECT_ROOT / info["local_path"], _MODULES_META_PATH]
        if info.get("hardware_profile"):
            for pack in info.get("packs", []):
                targets.append(_PROJECT_ROOT / _HARDWARE_EOL_CACHE_ROOT / "indexes" / f"{pack}.json")
                targets.append(_PROJECT_ROOT / _HARDWARE_EOL_CACHE_ROOT / "records" / pack)
            return targets
        for part in info.get("parts", []):
            targets.append(_PROJECT_ROOT / part["local_path"])
        return targets

    def _first_unwritable_target(self, module_names: List[str]) -> Optional[Path]:
        """Return the first target path that cannot be written, if any."""
        for module_name in module_names:
            for target in self._download_targets(module_name):
                try:
                    target.parent.mkdir(parents=True, exist_ok=True)
                except OSError:
                    return target.parent

                if target.exists():
                    if not os.access(target, os.W_OK):
                        return target
                elif not os.access(target.parent, os.W_OK):
                    return target.parent
        return None

    def _cache_permission_message(self, blocked_path: Path) -> str:
        """Build a user-facing repair message for root-owned cache files."""
        user = os.environ.get("SUDO_USER") or os.environ.get("USER") or "$USER"
        group = user if user != "$USER" else "$USER"
        return (
            "  Permission error: SunsetScan cannot write module cache files.\n"
            f"  Blocked path: {blocked_path}\n"
            "  This usually happens after running --setup or --download with sudo.\n"
            "  Fix ownership, then run the download again:\n"
            f"    sudo chown -R {user}:{group} {_CACHE_DIR}\n"
            "    ./sunsetscan --download all"
        )

    def _print_cache_permission_error(self, blocked_path: Path, quiet: bool) -> None:
        if not quiet:
            print(self._cache_permission_message(blocked_path))

    def download(self, module_name: str, quiet: bool = False) -> bool:
        """Download and install a single module.

        Args:
            module_name: Module name from MODULE_REGISTRY.
            quiet: Suppress output.

        Returns:
            True on success.
        """
        if module_name not in MODULE_REGISTRY:
            if not quiet:
                print(f"Unknown module: {module_name}")
                print(f"Available: {', '.join(MODULE_REGISTRY.keys())}")
            return False

        info = MODULE_REGISTRY[module_name]
        blocked_path = self._first_unwritable_target([module_name])
        if blocked_path:
            self._print_cache_permission_error(blocked_path, quiet)
            logger.error(
                "Module cache is not writable for %s: %s",
                module_name,
                blocked_path,
            )
            return False

        if not quiet:
            print(f"Downloading {module_name} ({info['size_estimate']}) from {info['source']}...")

        try:
            import requests
            session = requests.Session()
            session.headers.update({"User-Agent": f"SunsetScan/{Settings().version}"})

            # Special handling for Wappalyzer (multiple files to merge)
            if module_name in ("wappalyzer-mini", "wappalyzer-full"):
                data = self._download_wappalyzer(session, quiet=quiet)
                if not data:
                    if not quiet:
                        print(f"  Failed to download Wappalyzer data")
                    return False
                parser = _PARSERS[info["parser"]]
                parsed = parser(data)
            elif info.get("hardware_profile"):
                parsed = self._download_hardware_eol_profile(session, info, quiet=quiet)
            elif module_name == "hardware-eol" and info.get("parts"):
                parsed = self._download_hardware_eol(session, info, quiet=quiet)
            else:
                resp = session.get(info["url"], timeout=30)
                if resp.status_code != 200:
                    if not quiet:
                        print(f"  Download failed: HTTP {resp.status_code}")
                    return False
                parser = _PARSERS[info["parser"]]
                raw_data = resp.content if info.get("binary") else resp.text
                parsed = parser(raw_data)

            if not parsed:
                if not quiet:
                    print(f"  No data parsed from download")
                return False

            # Save to local path
            target = _PROJECT_ROOT / info["local_path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "w", encoding="utf-8") as f:
                indent = 2 if isinstance(parsed, list) else None
                json.dump(parsed, f, indent=indent)

            # Update metadata
            self._meta[module_name] = {
                "installed": True,
                "version": "1.0",
                "installed_at": datetime.now().isoformat(),
                "source": info["source"],
                "local_path": info["local_path"],
                "entries": _entry_count(parsed, module_name),
            }
            if info.get("license"):
                self._meta[module_name]["license"] = info["license"]
            if info.get("license_url"):
                self._meta[module_name]["license_url"] = info["license_url"]
            self._save_meta()

            if not quiet:
                count = _entry_count(parsed, module_name)
                size_kb = target.stat().st_size // 1024
                print(f"  Installed: {module_name} ({count} entries, {size_kb} KB)")

            return True

        except ImportError:
            if not quiet:
                print("  Error: requests library not installed")
            return False
        except Exception as e:
            if not quiet:
                print(f"  Download error: {e}")
            logger.error(f"Module download failed for {module_name}: {e}")
            return False

    def _download_wappalyzer(self, session, quiet: bool = False) -> Dict:
        """Download and merge all Wappalyzer letter files."""
        base_url = (
            "https://raw.githubusercontent.com/enthec/webappanalyzer/"
            "main/src/technologies/"
        )
        merged = {}
        files = [f"{c}.json" for c in "_abcdefghijklmnopqrstuvwxyz"]
        for fname in files:
            try:
                r = session.get(base_url + fname, timeout=15)
                if r.status_code == 200:
                    data = r.json()
                    if "technologies" in data:
                        data = data["technologies"]
                    merged.update(data)
            except Exception:
                continue
        return merged

    def _download_hardware_eol(self, session, info: Dict[str, Any], quiet: bool = False) -> Dict:
        """Download the split hardware EOL index and record shards."""
        resp = session.get(info["url"], timeout=30)
        if resp.status_code != 200:
            if not quiet:
                print(f"  Download failed: HTTP {resp.status_code}")
            return {}

        parser = _PARSERS[info["parser"]]
        parsed = parser(resp.content)
        if not parsed:
            return {}

        index_base = Path(info["local_path"]).parent
        record_shards = parsed.setdefault("record_shards", {})
        shard_parser = _parse_hardware_eol_shard

        for part in info.get("parts", []):
            category = part["category"]
            if not quiet:
                print(f"  Downloading shard: {category}")
            shard_resp = session.get(part["url"], timeout=60)
            if shard_resp.status_code != 200:
                if not quiet:
                    print(f"  Shard download failed: {category} HTTP {shard_resp.status_code}")
                return {}

            shard = shard_parser(shard_resp.content)
            if not shard:
                return {}
            if shard.get("category") and shard["category"] != category:
                logger.warning(
                    "hardware-eol shard category mismatch: expected %s, got %s",
                    category,
                    shard.get("category"),
                )

            target = _PROJECT_ROOT / part["local_path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "w", encoding="utf-8") as f:
                json.dump(shard, f, separators=(",", ":"))

            shard_info = record_shards.setdefault(category, {})
            try:
                local_rel = Path(part["local_path"]).relative_to(index_base)
            except ValueError:
                local_rel = Path(part["local_path"]).name
            shard_info["path"] = local_rel.as_posix() if isinstance(local_rel, Path) else str(local_rel)
            shard_info["installed_size_bytes"] = target.stat().st_size

        return parsed

    def _hardware_profile_installed(self, info: Dict[str, Any]) -> bool:
        """Return True when a smart hardware EOL profile is installed locally."""
        manifest_path = _PROJECT_ROOT / info["local_path"]
        if not (manifest_path.exists() and manifest_path.stat().st_size > 0):
            return False
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
        except Exception:
            return False

        packs = manifest.get("packs") or {}
        for pack in info.get("packs", []):
            pack_info = packs.get(pack)
            if not isinstance(pack_info, dict):
                return False
            index_path = self._hardware_manifest_file(manifest_path, pack_info.get("index"))
            if not (index_path and index_path.exists() and index_path.stat().st_size > 0):
                return False
            shards = pack_info.get("shards") or {}
            for shard_info in shards.values():
                shard_path = self._hardware_manifest_file(manifest_path, shard_info)
                if not (shard_path and shard_path.exists() and shard_path.stat().st_size > 0):
                    return False
        return True

    def _download_hardware_eol_profile(self, session, info: Dict[str, Any], quiet: bool = False) -> Dict:
        """Download a smart hardware EOL profile manifest, pack indexes, and shards."""
        resp = session.get(info["url"], timeout=30)
        if resp.status_code != 200:
            if not quiet:
                print(f"  Download failed: HTTP {resp.status_code}")
            return {}

        manifest = _parse_hardware_eol_manifest(resp.content)
        if not manifest:
            return {}

        manifest_base_url = str(info["url"]).rsplit("/", 1)[0] + "/"
        manifest_path = _PROJECT_ROOT / info["local_path"]
        selected_packs = info.get("packs") or []
        available_packs = manifest.get("packs") or {}
        pending_writes: List[Tuple[Path, Dict[str, Any]]] = []

        for pack in selected_packs:
            pack_info = available_packs.get(pack)
            if not isinstance(pack_info, dict):
                if not quiet:
                    print(f"  Missing hardware EOL pack in manifest: {pack}")
                return {}

            if not quiet:
                print(f"  Downloading hardware EOL pack: {pack}")

            index_info = pack_info.get("index") or {}
            index = self._download_manifest_json(
                session,
                manifest_base_url,
                index_info,
                parser=_parse_hardware_eol,
                timeout=30,
            )
            if not index:
                return {}
            index_target = self._hardware_manifest_file(manifest_path, index_info)
            if not index_target:
                return {}
            pending_writes.append((index_target, index))

            for category, shard_info in (pack_info.get("shards") or {}).items():
                shard = self._download_manifest_json(
                    session,
                    manifest_base_url,
                    shard_info,
                    parser=_parse_hardware_eol_shard,
                    timeout=60,
                )
                if not shard:
                    return {}
                if shard.get("category") and shard["category"] != category:
                    logger.warning(
                        "hardware-eol smart shard category mismatch: expected %s, got %s",
                        category,
                        shard.get("category"),
                    )
                shard_target = self._hardware_manifest_file(manifest_path, shard_info)
                if not shard_target:
                    return {}
                pending_writes.append((shard_target, shard))

        for target, data in pending_writes:
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "w", encoding="utf-8") as f:
                json.dump(data, f, separators=(",", ":"))

        return manifest

    def _download_manifest_json(
        self,
        session,
        manifest_base_url: str,
        file_info: Dict[str, Any],
        *,
        parser,
        timeout: int,
    ) -> Dict[str, Any]:
        path = str(file_info.get("path") or "")
        if not path:
            return {}
        url = path if path.startswith(("http://", "https://")) else manifest_base_url + path
        resp = session.get(url, timeout=timeout)
        if resp.status_code != 200:
            return {}
        expected_hash = file_info.get("sha256")
        if expected_hash:
            digest = hashlib.sha256(resp.content).hexdigest()
            if digest != expected_hash:
                logger.warning("hardware-eol download hash mismatch for %s", path)
                return {}
        return parser(resp.content)

    @staticmethod
    def _hardware_manifest_file(manifest_path: Path, file_info: Any) -> Optional[Path]:
        if not isinstance(file_info, dict):
            return None
        rel_path = str(file_info.get("path") or "")
        if not rel_path:
            return None
        path = Path(rel_path)
        if path.is_absolute():
            return path
        if path.suffix == ".gz":
            path = path.with_suffix("")
        return manifest_path.parent / path

    def download_all(self, quiet: bool = False) -> int:
        """Download all missing modules.

        Returns:
            Number of successfully downloaded modules.
        """
        success = 0
        candidates = [
            (name, info) for name, info in MODULE_REGISTRY.items()
            if not info.get("hardware_profile") and name != "hardware-eol"
        ]
        candidates.append(("hardware-eol-full", MODULE_REGISTRY["hardware-eol-full"]))
        pending = [
            name for name, info in candidates
            if not self.is_installed(name)
        ]
        blocked_path = self._first_unwritable_target(pending)
        if blocked_path:
            self._print_cache_permission_error(blocked_path, quiet)
            logger.error("Module cache is not writable: %s", blocked_path)
            return 0

        for name, info in candidates:
            if not info["default"] and not self.is_installed(name):
                if self.download(name, quiet=quiet):
                    success += 1
            elif info["default"] and not self.is_installed(name):
                if self.download(name, quiet=quiet):
                    success += 1
        return success

    def download_defaults(self, quiet: bool = False) -> int:
        """Download all default (core) modules.

        Returns:
            Number of successfully downloaded modules.
        """
        success = 0
        pending = [
            name for name, info in MODULE_REGISTRY.items()
            if info["default"] and not self.is_installed(name)
        ]
        blocked_path = self._first_unwritable_target(pending)
        if blocked_path:
            self._print_cache_permission_error(blocked_path, quiet)
            logger.error("Module cache is not writable: %s", blocked_path)
            return 0

        for name, info in MODULE_REGISTRY.items():
            if info["default"] and not self.is_installed(name):
                if self.download(name, quiet=quiet):
                    success += 1
        return success

    def refresh_expired(self, quiet: bool = False) -> Dict[str, str]:
        """Refresh all installed modules that have expired TTL.

        Returns:
            Dict of {module_name: "updated" | "current" | "failed"}
        """
        results = {}
        for name in MODULE_REGISTRY:
            if not self.is_installed(name):
                continue
            if self.is_expired(name):
                if self.download(name, quiet=True):
                    results[name] = "updated"
                    age_str = f"was {self._age_days(name)} days old" if self._age_days(name) else ""
                    if not quiet:
                        print(f"  {name}: updated ({age_str})")
                else:
                    results[name] = "failed"
                    if not quiet:
                        print(f"  {name}: update failed")
            else:
                age = self._age_days(name)
                results[name] = "current"
                if not quiet:
                    print(f"  {name}: current ({age} days old) -- skipped")
        return results

    def _age_days(self, module_name: str) -> Optional[int]:
        installed_at = self.get_installed_at(module_name)
        if not installed_at:
            return None
        try:
            dt = datetime.fromisoformat(installed_at)
            return (datetime.now() - dt).days
        except (ValueError, TypeError):
            return None

    # ------------------------------------------------------------------
    # Data access — transparent mini/full priority
    # ------------------------------------------------------------------

    def get_credentials(self, vendor: Optional[str] = None) -> List[Dict]:
        """Get best available credentials list.

        Priority: credentials-full > credentials-mini > built-in fallback.
        If vendor is specified, filter to that vendor first, then add generics.

        Args:
            vendor: Optional vendor name to prioritize (e.g. "Hikvision").

        Returns:
            List of {"vendor": str, "username": str, "password": str}.
        """
        # Load best available
        data = self._load_module_data("credentials-full")
        if not data:
            data = self._load_module_data("credentials-mini")
        if not data:
            # Built-in minimal fallback
            data = _BUILTIN_CREDENTIALS

        if not isinstance(data, list):
            return _BUILTIN_CREDENTIALS

        if vendor:
            vendor_lower = vendor.lower()
            vendor_creds = [
                e for e in data
                if vendor_lower in e.get("vendor", "").lower()
            ]
            generic_creds = [
                e for e in data
                if e.get("vendor", "").lower() in ("generic", "", "default", "various")
                or e.get("username", "").lower() in ("admin", "root")
            ]
            # Vendor-specific first, then generic, deduplicated
            seen = set()
            result = []
            for e in vendor_creds + generic_creds:
                key = (e.get("username", ""), e.get("password", ""))
                if key not in seen:
                    seen.add(key)
                    result.append(e)
            return result[:100]  # Cap to avoid excessive testing

        return data

    def get_camera_credentials(self) -> List[Dict]:
        """Get camera-specific credentials if installed."""
        data = self._load_module_data("camera-credentials")
        return data if isinstance(data, list) else []

    def get_snmp_communities(self) -> List[str]:
        """Get SNMP community strings.

        Priority: snmp-community module > built-in defaults.
        """
        data = self._load_module_data("snmp-community")
        if isinstance(data, list) and data:
            return data
        return _BUILTIN_SNMP_COMMUNITIES

    def get_ja3_signatures(self) -> Any:
        """Get JA3 signature data."""
        return self._load_module_data("ja3-signatures")

    def get_wappalyzer_data(self) -> Dict:
        """Get Wappalyzer technology data.

        Priority: wappalyzer-full > wappalyzer-mini > empty dict.
        """
        data = self._load_module_data("wappalyzer-full")
        if isinstance(data, dict) and data:
            return data
        data = self._load_module_data("wappalyzer-mini")
        if isinstance(data, dict) and data:
            return data
        return {}

    def _load_module_data(self, module_name: str) -> Any:
        """Load module data from disk."""
        info = MODULE_REGISTRY.get(module_name)
        if not info:
            return None
        path = _PROJECT_ROOT / info["local_path"]
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.debug(f"Failed to load module {module_name}: {e}")
            return None


# ---------------------------------------------------------------------------
# Built-in fallback data (used when no modules are installed)
# ---------------------------------------------------------------------------

_BUILTIN_CREDENTIALS = [
    {"vendor": "generic", "username": "admin", "password": "admin"},
    {"vendor": "generic", "username": "admin", "password": "password"},
    {"vendor": "generic", "username": "admin", "password": "1234"},
    {"vendor": "generic", "username": "admin", "password": ""},
    {"vendor": "generic", "username": "root", "password": "root"},
    {"vendor": "generic", "username": "root", "password": "password"},
    {"vendor": "generic", "username": "root", "password": ""},
    {"vendor": "generic", "username": "user", "password": "user"},
    {"vendor": "generic", "username": "guest", "password": "guest"},
    {"vendor": "generic", "username": "admin", "password": "12345"},
]

_BUILTIN_SNMP_COMMUNITIES = [
    "public", "private", "community", "admin", "default",
    "guest", "snmp", "monitor", "manager", "SNMP_trap",
    "router", "switch", "cisco", "read", "write",
]
