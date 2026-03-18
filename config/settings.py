"""
NetWatch Configuration Settings Module.

This module contains all configurable constants, port lists, timing values,
and thresholds used throughout the NetWatch application. No magic numbers
should exist outside this file.

Exports:
    Settings dataclass with all configuration parameters
    SCAN_PROFILES dict for nmap scan profiles
    COLOR_CODES for terminal output

Example:
    from config.settings import Settings, SCAN_PROFILES
    settings = Settings()
    timeout = settings.banner_timeout
"""

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class Settings:
    """Centralized configuration settings for NetWatch.

    Attributes:
        tool_name: Name of the application
        version: Current version string
        banner_timeout: Socket timeout for banner grabbing (seconds)
        cache_ttl_hours: EOL cache time-to-live (hours) — legacy field, kept for eol/cache.py
        cve_cache_ttl_days: CVE cache refresh interval (days)
        eol_cache_ttl_days: EOL cache refresh interval (days)
        warning_days_threshold: Days until EOL to trigger warning
        critical_days_threshold: Days past EOL to trigger critical
        max_threads: Maximum threads for concurrent banner grabbing
        socket_connect_timeout: TCP connection timeout (seconds)
        default_target: Default network target if none specified
        common_ports: List of common ports for quick scans
        ssl_check_timeout: Timeout for SSL certificate checks (seconds)
        web_check_timeout: Timeout for HTTP checks (seconds)
        upnp_discovery_timeout: Timeout for SSDP UPnP discovery (seconds)
    """
    tool_name: str = "NetWatch"
    version: str = "1.4.0"
    banner_timeout: int = 3
    cache_ttl_hours: int = 24       # legacy — used by eol/cache.py
    cve_cache_ttl_days: int = 7     # CVE data refreshed weekly
    eol_cache_ttl_days: int = 30    # EOL data refreshed monthly
    warning_days_threshold: int = 180
    critical_days_threshold: int = 0
    max_threads: int = 50
    socket_connect_timeout: float = 2.0
    default_target: str = "192.168.1.0/24"
    common_ports: List[int] = None
    ssl_check_timeout: float = 5.0
    web_check_timeout: float = 5.0
    upnp_discovery_timeout: float = 3.0
    history_retention_days: int = 90
    auto_save_history: bool = True
    
    def __post_init__(self):
        # Dataclass is frozen, so we can't modify directly
        object.__setattr__(
            self, 
            'common_ports',
            [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]
        )


# Scan profiles for nmap
# Keys are profile names, values are nmap argument strings
SCAN_PROFILES: Dict[str, str] = {
    "QUICK":  "-T4 -F",                                    # Fast, common ports only
    "FULL":   "-T4 -A -sV -O --osscan-guess",              # OS detect + version + scripts
    "STEALTH":"-sS -T2 -sV",                               # SYN scan, slower, quieter
    "PING":   "-sn",                                       # Ping sweep only
    "IOT":    "-T4 -sV -p 23,80,443,8080,8443,554,1900,5000,5001,7547,49152 --open",
    "SMB":    "-T4 -sV -p 135,139,445,137,138 --script smb-security-mode,smb2-security-mode,smb-vuln-ms17-010 --open",
}

# Scan descriptions for user display
SCAN_DESCRIPTIONS: Dict[str, Dict[str, str]] = {
    "QUICK": {
        "name": "Quick Scan",
        "description": "Fast scan of top 100 ports with aggressive timing",
        "features": ["Top 100 common ports", "Fast timing (-T4)", "Host discovery"],
        "estimated_time": "30 seconds - 2 minutes",
        "requires_root": False,
    },
    "FULL": {
        "name": "Full Scan",
        "description": "Comprehensive scan with OS detection and service versioning",
        "features": [
            "OS fingerprinting enabled",
            "Service version detection",
            "Banner grabbing on all open ports",
            "NSE script scanning",
        ],
        "estimated_time": "3-8 minutes",
        "requires_root": True,
    },
    "STEALTH": {
        "name": "Stealth Scan",
        "description": "SYN scan with slower timing to evade detection",
        "features": [
            "TCP SYN scan (half-open)",
            "Slower timing (-T2)",
            "Service version detection",
            "Reduced noise footprint",
        ],
        "estimated_time": "5-15 minutes",
        "requires_root": True,
    },
    "IOT": {
        "name": "IoT Scan",
        "description": "Targeted scan for IoT/smart device ports (cameras, printers, routers)",
        "features": [
            "IoT-specific ports: Telnet(23), HTTP(80/443/8080/8443)",
            "RTSP(554), UPnP(1900), TR-069(7547)",
            "Only shows open ports",
        ],
        "estimated_time": "1-3 minutes",
        "requires_root": False,
    },
    "SMB": {
        "name": "SMB/Windows Scan",
        "description": "Focused scan for Windows file sharing and SMB vulnerabilities",
        "features": [
            "SMB ports: 135, 137-139, 445",
            "SMB security mode detection",
            "EternalBlue (MS17-010) check",
            "SMB signing status",
        ],
        "estimated_time": "1-3 minutes",
        "requires_root": True,
    },
}

# EOL Status levels
EOL_STATUS = {
    "CRITICAL": {
        "label": "CRITICAL",
        "color": "red",
        "description": "Product has reached End-of-Life",
    },
    "WARNING": {
        "label": "WARNING",
        "color": "yellow",
        "description": "EOL approaching within warning threshold",
    },
    "OK": {
        "label": "OK",
        "color": "green",
        "description": "Product is supported and up-to-date",
    },
    "UNKNOWN": {
        "label": "UNKNOWN",
        "color": "dim",
        "description": "EOL status cannot be determined",
    },
    "N/A": {
        "label": "N/A",
        "color": "dim",
        "description": "Product not tracked by endoflife.date",
    },
}

# API endpoints
ENDOFLIFE_API_BASE = "https://endoflife.date/api"
ENDOFLIFE_API_TIMEOUT = 30  # seconds

# File paths (relative to project root)
# Note: eol/cache.py uses this value. The new core/cache_manager.py
# resolves its own path from __file__ and ignores this setting.
CACHE_DIR = "data/cache"
DEFAULT_EXPORT_DIR = "."

# New cache file paths (used by core/cache_manager.py)
CVE_CACHE_FILENAME = "cve_cache.json"
EOL_CACHE_FILENAME = "eol_cache.json"
CACHE_META_FILENAME = "cache_meta.json"
BASELINE_FILENAME = "baseline.json"

# UI Settings
TABLE_MIN_WIDTH = 120
PROGRESS_REFRESH_RATE = 10  # updates per second

# Menu options
MENU_OPTIONS = [
    ("1", "Quick Scan", "Fast ping sweep + top 100 ports"),
    ("2", "Full Scan", "OS detect + all services + banners"),
    ("3", "Stealth Scan", "SYN scan (requires root/admin)"),
    ("4", "Custom Target", "Specify IP, range, or CIDR"),
    ("5", "Recheck EOL", "Reload last scan, refresh EOL status"),
    ("6", "Export Report", "Save as JSON or HTML"),
    ("7", "Settings", "View/change timeout, cache TTL, ports"),
    ("8", "Help", "Show usage guide"),
    ("9", "Exit", "Quit NetWatch"),
]

# Banner ASCII art
ASCII_BANNER = """
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║   ███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗ ║
║   ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║ ║
║   ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║ ║
║   ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║ ║
║   ██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║ ║
║   ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝ ║
║                                                                          ║
║              Network EOL Scanner & Security Assessment Tool              ║
║                         Version {version}                                  ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
"""
