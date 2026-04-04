"""
NetWatch Device Identification Engine.

Fuses evidence from multiple detection sources (MAC OUI, nmap OS,
HTTP fingerprinting, TLS certificates, SSH banners, UPnP, SNMP,
Wappalyzer, mDNS, and port heuristics) into a unified per-host
identification result.

Runs as a post-processing step after all security checkers complete.
No new network requests — reads only from data already collected.

Exports:
    DeviceIdentity: Dataclass for the fused identification result
    DeviceIdentifier: Main engine class
"""

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.scanner import HostInfo
from core.findings import Finding

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).parent.parent
_ALIASES_PATH = _PROJECT_ROOT / "data" / "device_aliases.json"
_OUI_CACHE_PATH = _PROJECT_ROOT / "data" / "cache" / "mac_oui.json"
_WAPPALYZER_FULL_PATH = _PROJECT_ROOT / "data" / "cache" / "wappalyzer_tech.json"
_WAPPALYZER_MINI_PATH = _PROJECT_ROOT / "data" / "cache" / "wappalyzer_mini.json"
_DEFAULT_CREDS_PATH = _PROJECT_ROOT / "data" / "default_credentials.json"

# Wappalyzer category ID -> device_type mapping
_WAPPALYZER_CAT_DEVICE_TYPE: Dict[int, str] = {
    1: "Web Application",       # CMS
    2: "Web Application",       # Message boards
    6: "Web Application",       # Ecommerce
    11: "Web Application",      # Blog
    22: "Web Server",           # Web servers
    28: "Operating System",     # Operating systems
    34: "Database Server",      # Database managers
    42: "Web Application",      # DevOps / CI/CD
    44: "Web Application",      # CI
    47: "Web Application",      # Wiki
    55: "Network Device",       # Network storage
    62: "Web Application",      # PaaS
    64: "Network Device",       # Network devices
    78: "Network Device",       # Remote access
    87: "Web Application",      # Hosting panels
    92: "Web Application",      # Web mail
}


@dataclass
class DeviceIdentity:
    """Fused identification result for a single host.

    Attributes:
        vendor:      Canonical vendor name (e.g. "Synology", "Ubiquiti")
        model:       Model name (e.g. "DiskStation DS920+", "UniFi AP-AC-Pro")
        version:     Firmware or OS version string
        device_type: Device category (router, nas, printer, camera, etc.)
        confidence:  Overall confidence 0.0-1.0
        sources:     Which evidence sources contributed
    """
    vendor: str = ""
    model: str = ""
    version: str = ""
    device_type: str = ""
    confidence: float = 0.0
    sources: List[str] = field(default_factory=list)

    def summary(self) -> str:
        """One-line human-readable summary."""
        parts = []
        if self.device_type:
            parts.append(self.device_type)
        if self.vendor:
            parts.append(self.vendor)
        if self.model:
            parts.append(self.model)
        if self.version:
            parts.append(f"v{self.version}")
        return " — ".join(parts) if parts else "Unknown Device"

    def to_dict(self) -> dict:
        return {
            "vendor": self.vendor,
            "model": self.model,
            "version": self.version,
            "device_type": self.device_type,
            "confidence": round(self.confidence, 2),
            "sources": self.sources,
        }


# ---- Partial evidence container (internal) ----

@dataclass
class _Evidence:
    """A single piece of evidence from one source."""
    source: str
    vendor: str = ""
    model: str = ""
    version: str = ""
    device_type: str = ""
    confidence: float = 0.0


# ---- Port heuristic rules ----

_PORT_DEVICE_HINTS: List[Tuple[set, str, float]] = [
    # (required_ports, device_type, confidence)
    ({9100},               "Printer",           0.7),
    ({631},                "Printer",           0.6),
    ({515},                "Printer",           0.5),
    ({554},                "Camera",            0.5),
    ({8554},               "Camera",            0.4),
    ({37777, 37778},       "Camera",            0.6),   # Dahua
    ({1900},               "UPnP Device",       0.2),
    ({5000, 5001},         "NAS",               0.4),
    ({8291, 8728},         "Router",            0.6),   # MikroTik Winbox + API
    ({8291},               "Router",            0.5),   # MikroTik Winbox
    ({53},                 "DNS Resolver",      0.3),
    ({8080, 80, 443},      "Web Device",        0.15),
    ({22, 80},             "Linux Device",      0.1),
    ({3389},               "Windows Device",    0.3),
    ({445, 135},           "Windows Device",    0.3),
    ({548},                "Apple/NAS",         0.3),   # AFP
    ({5353, 548},          "Apple Device",      0.35),
    ({7547},               "ISP Router",        0.5),   # TR-069
    ({5060},               "VoIP Phone",        0.4),   # SIP
    ({4500, 500},          "VPN Gateway",       0.4),   # IPsec
    ({8006},               "Hypervisor",        0.5),   # Proxmox
    ({6443},               "Kubernetes Node",   0.4),
    ({9090},               "Management Console", 0.3),  # Prometheus, Cockpit
    ({32400},              "Media Server",      0.5),   # Plex
    ({8096},               "Media Server",      0.5),   # Jellyfin
    ({51820},              "VPN Device",        0.3),   # WireGuard
    ({1194},               "VPN Device",        0.3),   # OpenVPN
    ({1883},               "IoT Hub",           0.4),   # MQTT
    ({8883},               "IoT Hub",           0.4),   # MQTTS
    ({49152},              "IoT Device",        0.2),
    ({502},                "Industrial/SCADA",  0.5),   # Modbus
]

# SSH banner patterns -> (vendor, device_type, confidence)
_SSH_BANNER_PATTERNS: List[Tuple[re.Pattern, str, str, float]] = [
    (re.compile(r'ROSSSH', re.I),                     "MikroTik", "Router",          0.7),
    (re.compile(r'Cisco-(\d+\.\d+)', re.I),           "Cisco",    "Network Device",  0.6),
    (re.compile(r'MikroTik', re.I),                   "MikroTik", "Router",          0.7),
    (re.compile(r'Synology', re.I),                   "Synology", "NAS",             0.6),
    (re.compile(r'FortiSSH', re.I),                   "Fortinet", "Firewall",        0.6),
    (re.compile(r'HUAWEI', re.I),                     "Huawei",   "Network Device",  0.6),
    (re.compile(r'Comware', re.I),                    "HPE/H3C",  "Switch",          0.6),
    (re.compile(r'lancom', re.I),                     "LANCOM",   "Router",          0.6),
    (re.compile(r'Sun_SSH', re.I),                    "Oracle",   "Solaris Server",  0.5),
    (re.compile(r'IPSSH-(\d+\.\d+)', re.I),          "",         "Embedded Device", 0.35),
    (re.compile(r'dropbear_(\d+\.\d+)', re.I),        "",         "Embedded Device", 0.3),
    (re.compile(r'dropbear', re.I),                   "",         "Embedded Device", 0.3),
    (re.compile(r'Serv-U', re.I),                     "",         "Windows Server",  0.35),
    (re.compile(r'WeOnlyDo', re.I),                   "",         "Embedded Device", 0.3),
    (re.compile(r'OpenSSH.*Ubuntu', re.I),            "",         "Linux Server",    0.25),
    (re.compile(r'OpenSSH.*Debian', re.I),            "",         "Linux Server",    0.25),
    (re.compile(r'OpenSSH_([\d.p]+)', re.I),          "",         "Linux/BSD Device", 0.1),
    (re.compile(r'OpenSSH', re.I),                    "",         "Linux/BSD Device", 0.1),
    (re.compile(r'^SSH-2\.0-xxxxxxx', re.I),          "",         "Honeypot",        0.15),
]

# nmap OS guess patterns -> (vendor, device_type)
_OS_GUESS_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r'Linux\s+\d', re.I),                "",           "Linux Device"),
    (re.compile(r'Windows\s+(10|11|Server)', re.I),  "Microsoft",  "Windows Device"),
    (re.compile(r'FreeBSD', re.I),                   "",           "FreeBSD Device"),
    (re.compile(r'pfSense', re.I),                   "Netgate",    "Firewall"),
    (re.compile(r'OpenWrt', re.I),                   "",           "Router"),
    (re.compile(r'RouterOS', re.I),                  "MikroTik",   "Router"),
    (re.compile(r'Cisco\s+IOS', re.I),              "Cisco",       "Network Device"),
    (re.compile(r'Apple\s+(?:Mac|iPhone|iPad)', re.I), "Apple",    "Apple Device"),
    (re.compile(r'VMware\s+ESXi', re.I),            "VMware",      "Hypervisor"),
    (re.compile(r'Synology', re.I),                 "Synology",    "NAS"),
    (re.compile(r'QNAP', re.I),                     "QNAP",        "NAS"),
    (re.compile(r'Ubiquiti', re.I),                 "Ubiquiti",     "Network Device"),
    (re.compile(r'printer', re.I),                  "",             "Printer"),
    (re.compile(r'camera', re.I),                   "",             "Camera"),
    (re.compile(r'Android', re.I),                  "",             "Mobile Device"),
]

# TLS cert CN/org patterns -> (vendor, device_type)
_CERT_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r'Synology', re.I),     "Synology",    "NAS"),
    (re.compile(r'QNAP', re.I),        "QNAP",        "NAS"),
    (re.compile(r'Ubiquiti', re.I),     "Ubiquiti",    "Network Device"),
    (re.compile(r'UniFi', re.I),        "Ubiquiti",    "Network Device"),
    (re.compile(r'MikroTik', re.I),     "MikroTik",    "Router"),
    (re.compile(r'Fortinet', re.I),     "Fortinet",    "Firewall"),
    (re.compile(r'FortiGate', re.I),    "Fortinet",    "Firewall"),
    (re.compile(r'Cisco', re.I),        "Cisco",       "Network Device"),
    (re.compile(r'Hikvision', re.I),    "Hikvision",   "Camera"),
    (re.compile(r'Dahua', re.I),        "Dahua",       "Camera"),
    (re.compile(r'Axis', re.I),         "Axis",        "Camera"),
    (re.compile(r'HP(?:BEC|[A-F0-9]{6})', re.I), "HP", "Printer"),
    (re.compile(r'Brother', re.I),      "Brother",     "Printer"),
    (re.compile(r'Canon', re.I),        "Canon",       "Printer"),
    (re.compile(r'Epson', re.I),        "Epson",       "Printer"),
    (re.compile(r'Xerox', re.I),        "Xerox",       "Printer"),
    (re.compile(r'Proxmox', re.I),      "Proxmox",     "Hypervisor"),
    (re.compile(r'ESXi', re.I),         "VMware",      "Hypervisor"),
    (re.compile(r'Netgear', re.I),      "Netgear",     "Router"),
    (re.compile(r'TP-Link', re.I),      "TP-Link",     "Router"),
    (re.compile(r'ASUS', re.I),         "ASUS",        "Router"),
    (re.compile(r'D-Link', re.I),       "D-Link",      "Router"),
    (re.compile(r'Linksys', re.I),      "Linksys",     "Router"),
    (re.compile(r'WatchGuard', re.I),   "WatchGuard",  "Firewall"),
    (re.compile(r'SonicWall', re.I),    "SonicWall",   "Firewall"),
    (re.compile(r'Sophos', re.I),       "Sophos",      "Firewall"),
    (re.compile(r'pfSense', re.I),      "Netgate",     "Firewall"),
    (re.compile(r'Grandstream', re.I),  "Grandstream", "VoIP Phone"),
]

# HTTP Server header patterns -> (vendor, device_type, model_group_index_or_None)
_HTTP_SERVER_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r'HP HTTP Server;\s*HP\s+(.+)', re.I),         "HP",          "Printer"),
    (re.compile(r'Brother/(\S+)', re.I),                        "Brother",     "Printer"),
    (re.compile(r'Canon HTTP Server', re.I),                    "Canon",       "Printer"),
    (re.compile(r'Epson_Linux', re.I),                          "Epson",       "Printer"),
    (re.compile(r'Xerox', re.I),                                "Xerox",       "Printer"),
    (re.compile(r'Ubiquiti', re.I),                             "Ubiquiti",    "Network Device"),
    (re.compile(r'UniFi', re.I),                                "Ubiquiti",    "Network Device"),
    (re.compile(r'Synology', re.I),                             "Synology",    "NAS"),
    (re.compile(r'QNAP', re.I),                                "QNAP",        "NAS"),
    (re.compile(r'MikroTik', re.I),                             "MikroTik",    "Router"),
    (re.compile(r'Cisco', re.I),                                "Cisco",       "Network Device"),
    (re.compile(r'Hikvision', re.I),                            "Hikvision",   "Camera"),
    (re.compile(r'Dahua', re.I),                                "Dahua",       "Camera"),
    (re.compile(r'DNVRS-Webs', re.I),                          "Dahua",       "Camera"),
    (re.compile(r'ASUSRT', re.I),                               "ASUS",        "Router"),
    (re.compile(r'WatchGuard', re.I),                           "WatchGuard",  "Firewall"),
    (re.compile(r'SonicWALL', re.I),                            "SonicWall",   "Firewall"),
    (re.compile(r'Zyxel', re.I),                                "Zyxel",       "Router"),
    (re.compile(r'Aruba', re.I),                                "Aruba",       "Access Point"),
    (re.compile(r'Grandstream', re.I),                          "Grandstream", "VoIP Phone"),
    (re.compile(r'Polycom', re.I),                              "Polycom",     "VoIP Phone"),
    (re.compile(r'Yealink', re.I),                              "Yealink",     "VoIP Phone"),
    (re.compile(r'NETGEAR', re.I),                              "Netgear",     "Router"),
    (re.compile(r'TP-LINK', re.I),                              "TP-Link",     "Router"),
    (re.compile(r'D-Link', re.I),                               "D-Link",      "Router"),
    (re.compile(r'Allegro-Software-RomPager', re.I),            "",            "Embedded Device"),
    (re.compile(r'RomPager', re.I),                             "",            "Embedded Device"),
    (re.compile(r'lighttpd', re.I),                             "",            "Embedded Device"),
    (re.compile(r'GoAhead', re.I),                              "",            "Embedded Device"),
    (re.compile(r'mini_httpd', re.I),                           "",            "Embedded Device"),
    (re.compile(r'micro_httpd', re.I),                          "",            "Embedded Device"),
    (re.compile(r'thttpd', re.I),                               "",            "Embedded Device"),
    (re.compile(r'Boa/', re.I),                                 "",            "Embedded Device"),
    (re.compile(r'WebIOPi', re.I),                              "",            "IoT Device"),
    (re.compile(r'AkamaiGHost', re.I),                          "",            "CDN/Proxy"),
    (re.compile(r'nginx', re.I),                                "",            ""),
    (re.compile(r'Apache', re.I),                               "",            ""),
    (re.compile(r'Microsoft-IIS', re.I),                        "Microsoft",   "Windows Server"),
]

# JA3S app name -> (vendor, device_type)
_JA3S_APP_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r'Synology\s+DSM', re.I),      "Synology",  "NAS"),
    (re.compile(r'QNAP', re.I),                "QNAP",      "NAS"),
    (re.compile(r'Cisco\s+AnyConnect', re.I),   "Cisco",     "Network Device"),
    (re.compile(r'Cisco', re.I),                "Cisco",     "Network Device"),
    (re.compile(r'MikroTik', re.I),             "MikroTik",  "Router"),
    (re.compile(r'Fortinet', re.I),             "Fortinet",  "Firewall"),
    (re.compile(r'FortiGate', re.I),            "Fortinet",  "Firewall"),
    (re.compile(r'Ubiquiti', re.I),             "Ubiquiti",  "Network Device"),
    (re.compile(r'UniFi', re.I),                "Ubiquiti",  "Network Device"),
    (re.compile(r'Hikvision', re.I),            "Hikvision", "Camera"),
    (re.compile(r'Dahua', re.I),                "Dahua",     "Camera"),
    (re.compile(r'Proxmox', re.I),              "Proxmox",   "Hypervisor"),
    (re.compile(r'ESXi', re.I),                 "VMware",    "Hypervisor"),
    (re.compile(r'nginx', re.I),                "",          "Web Server"),
    (re.compile(r'Apache', re.I),               "",          "Web Server"),
    (re.compile(r'IIS', re.I),                  "Microsoft", "Windows Server"),
]

# FTP banner patterns -> (vendor, device_type, confidence)
_FTP_BANNER_PATTERNS: List[Tuple[re.Pattern, str, str, float]] = [
    (re.compile(r'vsFTPd\s*([\d.]+)?', re.I),                          "",          "Linux Server",   0.25),
    (re.compile(r'ProFTPD\s*([\d.]+)?', re.I),                         "",          "Linux Server",   0.25),
    (re.compile(r'PureFTPd\s*([\d.]+)?', re.I),                        "",          "Unix Server",    0.25),
    (re.compile(r'FileZilla\s+Server\s*([\d.]+)?', re.I),              "",          "Windows Server", 0.25),
    (re.compile(r'Microsoft\s+FTP\s+Service.*?([\d.]+)?', re.I),       "Microsoft", "Windows Server", 0.35),
    (re.compile(r'wu[- ]?ftpd?\s*([\d.]+)?', re.I),                   "",          "Unix Server",    0.25),
]


class DeviceIdentifier:
    """Fuses evidence from all scan sources into a unified device identity."""

    def __init__(self):
        self._aliases: Dict[str, str] = self._load_aliases()
        self._oui_db: Optional[Dict[str, str]] = None  # lazy-loaded
        self._wappalyzer_db: Optional[Dict[str, dict]] = None  # lazy-loaded
        self._model_vendor_index: Optional[Dict[str, str]] = None  # lazy-loaded

    def identify(
        self,
        ip: str,
        host_info: HostInfo,
        findings: List[Finding],
    ) -> DeviceIdentity:
        """Identify a device by fusing all available evidence.

        Args:
            ip:        Host IP address.
            host_info: Scan result data for this host.
            findings:  All findings for this host (from all checkers).

        Returns:
            DeviceIdentity with fused result.
        """
        evidence: List[_Evidence] = []

        extractors = [
            self._extract_from_mac_oui,
            self._extract_from_nmap_os,
            self._extract_from_http_fingerprint,
            self._extract_from_http_server_headers,
            self._extract_from_tls_cert,
            self._extract_from_ssh_banner,
            self._extract_from_upnp,
            self._extract_from_snmp,
            self._extract_from_wappalyzer,
            self._extract_from_mdns,
            self._extract_from_port_heuristics,
            self._extract_from_nmap_service_info,
            self._extract_from_ja3s,
            self._extract_from_ftp_banner,
        ]

        for extractor in extractors:
            try:
                result = extractor(ip, host_info, findings)
                if result:
                    if isinstance(result, list):
                        evidence.extend(result)
                    else:
                        evidence.append(result)
            except Exception as e:
                logger.debug(f"Extractor {extractor.__name__} failed for {ip}: {e}")

        if not evidence:
            return DeviceIdentity()

        return self._fuse(evidence)

    def identify_preliminary(
        self,
        ip: str,
        host_info: HostInfo,
    ) -> DeviceIdentity:
        """Quick identification using only host-local evidence (no findings needed).

        Uses only extractors that read from host_info directly (MAC, nmap OS,
        HTTP fingerprint, banners, port heuristics, nmap services). Network-wide
        signals (UPnP, mDNS, Wappalyzer) are skipped since they require findings.

        Returns:
            DeviceIdentity with preliminary result.
        """
        evidence: List[_Evidence] = []
        empty_findings: List[Finding] = []

        local_extractors = [
            self._extract_from_mac_oui,
            self._extract_from_nmap_os,
            self._extract_from_http_fingerprint,
            self._extract_from_http_server_headers,
            self._extract_from_ssh_banner,
            self._extract_from_port_heuristics,
            self._extract_from_nmap_service_info,
            self._extract_from_ftp_banner,
            self._extract_from_ja3s,
        ]

        for extractor in local_extractors:
            try:
                result = extractor(ip, host_info, empty_findings)
                if result:
                    if isinstance(result, list):
                        evidence.extend(result)
                    else:
                        evidence.append(result)
            except Exception as e:
                logger.debug(f"Preliminary extractor {extractor.__name__} failed for {ip}: {e}")

        if not evidence:
            return DeviceIdentity()

        return self._fuse(evidence)

    # ---- Evidence Extractors ----

    def _extract_from_mac_oui(
        self, ip: str, host_info: HostInfo, findings: List[Finding]
    ) -> Optional[_Evidence]:
        """Extract vendor from MAC address OUI prefix."""
        mac = host_info.mac
        if not mac or len(mac) < 8:
            return None

        # Also use nmap's vendor field if available
        nmap_vendor = host_info.vendor
        if nmap_vendor:
            canonical = self._normalize_vendor(nmap_vendor)
            return _Evidence(
                source="mac_oui",
                vendor=canonical,
                confidence=0.45,
            )

        # Try OUI database lookup
        oui_vendor = self._lookup_oui(mac)
        if oui_vendor:
            canonical = self._normalize_vendor(oui_vendor)
            return _Evidence(
                source="mac_oui",
                vendor=canonical,
                confidence=0.4,
            )

        return None

    def _extract_from_nmap_os(
        self, ip: str, host_info: HostInfo, findings: List[Finding]
    ) -> Optional[_Evidence]:
        """Extract device type and vendor from nmap OS fingerprinting."""
        os_guess = host_info.os_guess
        if not os_guess:
            return None

        accuracy = 50
        if host_info.os_accuracy:
            try:
                accuracy = int(host_info.os_accuracy)
            except (ValueError, TypeError):
                pass

        confidence = (accuracy / 100) * 0.65

        for pattern, vendor, device_type in _OS_GUESS_PATTERNS:
            if pattern.search(os_guess):
                return _Evidence(
                    source="nmap_os",
                    vendor=self._normalize_vendor(vendor),
                    device_type=device_type,
                    confidence=confidence,
                )

        # Generic — still useful for device_type
        return _Evidence(
            source="nmap_os",
            device_type=os_guess[:50],
            confidence=confidence * 0.5,
        )

    def _extract_from_http_fingerprint(
        self, ip: str, host_info: HostInfo, findings: List[Finding]
    ) -> Optional[List[_Evidence]]:
        """Extract identity from HTTP fingerprinting (HttpFingerprint on PortInfo)."""
        results: List[_Evidence] = []

        for port_info in host_info.ports.values():
            fp = port_info.http_fingerprint
            if fp is None:
                continue

            # HttpFingerprint has: device_type, model, firmware_version, confidence
            vendor = ""
            model = ""
            version = ""
            device_type = ""
            fp_confidence = 0.0

            if hasattr(fp, 'device_type') and fp.device_type:
                device_type = fp.device_type
            if hasattr(fp, 'model') and fp.model:
                model = fp.model
            if hasattr(fp, 'firmware_version') and fp.firmware_version:
                version = fp.firmware_version
            if hasattr(fp, 'confidence') and fp.confidence:
                fp_confidence = fp.confidence

            # Extract from structured fingerprint fields
            if device_type or model or version:
                # Try to extract vendor from device_type field (often "ASUS Router")
                if device_type:
                    parts = device_type.split()
                    if len(parts) >= 2:
                        maybe_vendor = self._normalize_vendor(parts[0])
                        if maybe_vendor != parts[0].lower():
                            vendor = maybe_vendor
                            device_type = " ".join(parts[1:])

                results.append(_Evidence(
                    source="http_fingerprint",
                    vendor=self._normalize_vendor(vendor),
                    model=model,
                    version=version,
                    device_type=device_type,
                    confidence=max(fp_confidence, 0.5),
                ))

            # Also check raw_headers for additional hints
            raw_headers = getattr(fp, 'raw_headers', None) or {}
            if raw_headers:
                # Check Server header against known patterns
                server_val = raw_headers.get("Server", "") or raw_headers.get("server", "")
                if server_val:
                    for pattern, pat_vendor, pat_dtype in _HTTP_SERVER_PATTERNS:
                        m = pattern.search(server_val)
                        if m:
                            h_model = ""
                            if m.lastindex and m.lastindex >= 1:
                                h_model = m.group(1).strip()
                            results.append(_Evidence(
                                source="http_fingerprint_header",
                                vendor=self._normalize_vendor(pat_vendor),
                                model=h_model,
                                device_type=pat_dtype,
                                confidence=0.45 if pat_vendor else 0.2,
                            ))
                            break

                # Check X-Powered-By and similar identifying headers
                for hdr_name in ("X-Powered-By", "X-Generator", "X-Served-By"):
                    hdr_val = raw_headers.get(hdr_name, "") or raw_headers.get(hdr_name.lower(), "")
                    if not hdr_val:
                        continue
                    for pattern, pat_vendor, pat_dtype in _HTTP_SERVER_PATTERNS:
                        m = pattern.search(hdr_val)
                        if m:
                            results.append(_Evidence(
                                source="http_fingerprint_header",
                                vendor=self._normalize_vendor(pat_vendor),
                                device_type=pat_dtype,
                                confidence=0.35 if pat_vendor else 0.15,
                            ))
                            break

        return results if results else None

    def _extract_from_http_server_headers(
        self, ip: str, host_info: HostInfo, findings: List[Finding]
    ) -> Optional[_Evidence]:
        """Extract vendor/type from HTTP Server response headers stored in banners."""
        for port_info in host_info.ports.values():
            if port_info.service not in ("http", "https", "http-proxy"):
                continue

            # Check banner for Server header content
            banner = port_info.banner or ""
            # Also check version field — nmap often puts server info there
            version_str = port_info.version or ""
            server_str = banner if banner else version_str

            # Fallback: check raw_headers from HttpFingerprint if no banner
            if not server_str:
                fp = port_info.http_fingerprint
                if fp is not None:
                    raw_headers = getattr(fp, 'raw_headers', None) or {}
                    server_str = raw_headers.get("Server", "") or raw_headers.get("server", "")

            if not server_str:
                continue

            for pattern, vendor, device_type in _HTTP_SERVER_PATTERNS:
                m = pattern.search(server_str)
                if m:
                    model = ""
                    if m.lastindex and m.lastindex >= 1:
                        model = m.group(1).strip()
                    ev = _Evidence(
                        source="http_server_header",
                        vendor=self._normalize_vendor(vendor),
                        model=model,
                        device_type=device_type,
                        confidence=0.5 if vendor else 0.2,
                    )
                    if ev.vendor or ev.device_type:
                        return ev

        return None

    def _extract_from_tls_cert(
        self, ip: str, host_info: HostInfo, findings: List[Finding]
    ) -> Optional[_Evidence]:
        """Extract vendor/device from TLS certificate CN and issuer in SSL findings."""
        for f in findings:
            if f.category != "SSL/TLS":
                continue
            # Parse evidence and description for CN, issuer, organization
            text = f"{f.evidence} {f.description}"

            for pattern, vendor, device_type in _CERT_PATTERNS:
                if pattern.search(text):
                    return _Evidence(
                        source="tls_cert",
                        vendor=self._normalize_vendor(vendor),
                        device_type=device_type,
                        confidence=0.35,
                    )

        return None

    def _extract_from_ssh_banner(
        self, ip: str, host_info: HostInfo, findings: List[Finding]
    ) -> Optional[_Evidence]:
        """Extract device hints from SSH banners."""
        # Check port banners directly
        for port_info in host_info.ports.values():
            if port_info.service != "ssh":
                continue
            banner = port_info.banner or port_info.version or ""
            if not banner:
                continue

            for pattern, vendor, device_type, conf in _SSH_BANNER_PATTERNS:
                if pattern.search(banner):
                    results = [_Evidence(
                        source="ssh_banner",
                        vendor=self._normalize_vendor(vendor),
                        device_type=device_type,
                        confidence=conf,
                    )]
                    # Try to extract Ubuntu release version from SSH package revision
                    ubuntu_match = re.search(r'(\d+)ubuntu\d+', banner)
                    if ubuntu_match:
                        prefix = ubuntu_match.group(1) + "ubuntu"
                        version_hints = {
                            "4ubuntu": "20.04",
                            "7ubuntu": "22.04",
                            "9ubuntu": "24.04",
                        }
                        ubuntu_ver = version_hints.get(prefix)
                        if ubuntu_ver:
                            results.append(_Evidence(
                                source="ssh_banner_os_hint",
                                vendor="Canonical",
                                version=ubuntu_ver,
                                device_type="Server",
                                confidence=0.15,
                            ))
                    return results

        # Also check SSH findings for banner info
        for f in findings:
            if "SSH" not in f.category:
                continue
            text = f"{f.evidence} {f.description}"
            for pattern, vendor, device_type, conf in _SSH_BANNER_PATTERNS:
                if pattern.search(text):
                    return _Evidence(
                        source="ssh_banner",
                        vendor=self._normalize_vendor(vendor),
                        device_type=device_type,
                        confidence=conf,
                    )

        return None

    def _extract_from_upnp(
        self, ip: str, host_info: HostInfo, findings: List[Finding]
    ) -> Optional[_Evidence]:
        """Extract vendor, model, device type from UPnP findings."""
        for f in findings:
            if f.category != "UPnP":
                continue

            vendor = ""
            model = ""
            device_type = ""

            # Parse structured info from description/evidence
            text = f"{f.description} {f.evidence}"

            # Manufacturer: "vendor"
            mfr_match = re.search(r"Manufacturer:\s*['\"]?([^'\"]+?)['\"]?(?:\s*[,.]|\s*$)", text)
            if mfr_match:
                vendor = mfr_match.group(1).strip()

            # Model: from title or description
            model_match = re.search(r"(?:model|friendlyName):\s*['\"]?([^'\"]+?)['\"]?(?:\s*[,.]|\s*$)", text, re.I)
            if model_match:
                model = model_match.group(1).strip()

            # Device type from UPnP device findings
            if "router" in text.lower() or "gateway" in text.lower() or "InternetGatewayDevice" in text:
                device_type = "Router"
            elif "printer" in text.lower():
                device_type = "Printer"
            elif "mediaserver" in text.lower() or "MediaRenderer" in text:
                device_type = "Media Device"
            elif "camera" in text.lower():
                device_type = "Camera"

            # Extract from title: "UPnP device found: Name"
            if not model and "UPnP device found:" in f.title:
                model = f.title.split("UPnP device found:")[-1].strip()

            if vendor or model or device_type:
                return _Evidence(
                    source="upnp",
                    vendor=self._normalize_vendor(vendor),
                    model=model,
                    device_type=device_type,
                    confidence=0.75,
                )

        return None

    def _extract_from_snmp(
        self, ip: str, host_info: HostInfo, findings: List[Finding]
    ) -> Optional[_Evidence]:
        """Extract vendor, model, version from SNMP sysDescr."""
        try:
            from core.snmp_checker import get_last_sysdescr, parse_sysdescr
        except ImportError:
            return None

        sysdescr = get_last_sysdescr(ip)
        if not sysdescr:
            # Try to find sysDescr in SNMP findings
            for f in findings:
                if f.category == "SNMP" and "sysDescr" in f.title:
                    # Extract sysDescr from evidence
                    match = re.search(r'sysDescr:\s*(.+?)(?:\s*$)', f.evidence)
                    if match:
                        sysdescr = match.group(1).strip()
                        break

        if not sysdescr:
            return None

        parsed = parse_sysdescr(sysdescr)
        vendor = ""
        model = ""
        version = ""
        device_type = ""

        if parsed:
            product_slug, version = parsed
            # Map slug back to vendor
            slug_vendor_map = {
                "synology-dsm": ("Synology", "NAS"),
                "mikrotik": ("MikroTik", "Router"),
                "pfsense": ("Netgate", "Firewall"),
                "cisco-ios-xe": ("Cisco", "Network Device"),
                "vmware-esxi": ("VMware", "Hypervisor"),
                "qnap-qts": ("QNAP", "NAS"),
                "openwrt": ("", "Router"),
                "proxmox-ve": ("Proxmox", "Hypervisor"),
                "junos": ("Juniper", "Network Device"),
                "ubuntu": ("Canonical", "Linux Server"),
                "debian": ("", "Linux Server"),
                "freebsd": ("", "FreeBSD Device"),
                "centos": ("", "Linux Server"),
                "rhel": ("Red Hat", "Linux Server"),
            }
            if product_slug in slug_vendor_map:
                vendor, device_type = slug_vendor_map[product_slug]

        # Also try direct pattern matching on sysDescr for model info
        if not model:
            # Synology model: "synology_228+" or similar in sysDescr
            syn_match = re.search(r'(DS\d+\+?|RS\d+\+?|DVA\d+)', sysdescr, re.I)
            if syn_match:
                model = syn_match.group(1)
                vendor = vendor or "Synology"
                device_type = device_type or "NAS"

        return _Evidence(
            source="snmp",
            vendor=self._normalize_vendor(vendor),
            model=model,
            version=version,
            device_type=device_type,
            confidence=0.85,
        )

    def _extract_from_wappalyzer(
        self, ip: str, host_info: HostInfo, findings: List[Finding]
    ) -> Optional[List[_Evidence]]:
        """Extract vendor/product/type from Wappalyzer technology detection.

        Three evidence strategies:
        1. Parse CPE strings from the Wappalyzer DB for matched technologies
        2. Map Wappalyzer category IDs to device types
        3. Fall back to keyword matching for known device vendors
        """
        wap_db = self._get_wappalyzer_db()
        results: List[_Evidence] = []

        # Collect matched technology names from findings
        matched_techs: List[Tuple[str, str]] = []  # (tech_name, version)
        for f in findings:
            if "wappalyzer" not in " ".join(f.tags):
                continue

            # Extract tech name from title: "Web technology detected: TechName [version]"
            title = f.title
            if title.startswith("Web technology detected: "):
                tech_str = title[len("Web technology detected: "):]
                parts = tech_str.strip().split(" ", 1)
                tech_name = parts[0] if parts else ""
                version = parts[1].strip() if len(parts) > 1 else ""
                # Tech names can have spaces — look up in DB for exact match
                if wap_db:
                    # Try full string first, then first word
                    if tech_str.strip() in wap_db or tech_str.split(" ")[0] in wap_db:
                        actual_name = tech_str.strip() if tech_str.strip() in wap_db else tech_str.split(" ")[0]
                        # Version might be part of the name — re-split
                        if actual_name in wap_db:
                            remainder = tech_str[len(actual_name):].strip()
                            matched_techs.append((actual_name, remainder))
                            continue
                # Also try reconstructing from the tag (tech_name.lower().replace(" ","-"))
                for tag in f.tags:
                    if tag in ("web", "technology", "wappalyzer"):
                        continue
                    # Reverse the tag to find the DB entry
                    tag_lower = tag.lower()
                    for db_name in (wap_db or {}):
                        if db_name.lower().replace(" ", "-") == tag_lower:
                            matched_techs.append((db_name, version))
                            break

        # Process matched technologies against the Wappalyzer DB
        for tech_name, detected_version in matched_techs:
            tech_info = (wap_db or {}).get(tech_name)
            if not tech_info:
                continue

            # Strategy 1: Parse CPE string
            cpe_str = tech_info.get("cpe", "")
            if cpe_str:
                cpe_ev = self._parse_cpe(cpe_str, detected_version)
                if cpe_ev:
                    results.append(cpe_ev)

            # Strategy 2: Map categories to device type
            cats = tech_info.get("cats", [])
            for cat_id in cats:
                device_type = _WAPPALYZER_CAT_DEVICE_TYPE.get(cat_id)
                if device_type:
                    results.append(_Evidence(
                        source="wappalyzer_cat",
                        device_type=device_type,
                        confidence=0.3,
                    ))
                    break  # one device_type per tech is enough

        # Strategy 3: Keyword fallback for known device vendors (original logic)
        if not results:
            wap_hints = [
                ("Synology", "Synology", "NAS"),
                ("QNAP", "QNAP", "NAS"),
                ("Ubiquiti", "Ubiquiti", "Network Device"),
                ("UniFi", "Ubiquiti", "Network Device"),
                ("MikroTik", "MikroTik", "Router"),
                ("Cisco", "Cisco", "Network Device"),
                ("Fortinet", "Fortinet", "Firewall"),
                ("pfSense", "Netgate", "Firewall"),
                ("Proxmox", "Proxmox", "Hypervisor"),
                ("ESXi", "VMware", "Hypervisor"),
            ]
            for f in findings:
                if "wappalyzer" not in " ".join(f.tags):
                    continue
                text = f"{f.description} {f.evidence}"
                for keyword, vendor, device_type in wap_hints:
                    if keyword.lower() in text.lower():
                        results.append(_Evidence(
                            source="wappalyzer",
                            vendor=self._normalize_vendor(vendor),
                            device_type=device_type,
                            confidence=0.35,
                        ))
                        return results

        return results if results else None

    def _extract_from_mdns(
        self, ip: str, host_info: HostInfo, findings: List[Finding]
    ) -> Optional[_Evidence]:
        """Extract device type from mDNS service discovery findings."""
        for f in findings:
            if "mDNS" not in f.category and "mdns" not in " ".join(f.tags):
                continue
            if f.host != ip:
                continue

            text = f"{f.description} {f.title}"
            device_type = ""

            # Map mDNS service categories to device types
            if "Printer" in text or "_ipp" in text or "_pdl" in text:
                device_type = "Printer"
            elif "NAS" in text or "_synology" in text or "_nas" in text:
                device_type = "NAS"
            elif "Smart Home" in text or "_hap" in text or "_hue" in text or "_homekit" in text:
                device_type = "Smart Home Device"
            elif "Media" in text or "Chromecast" in text or "AirPlay" in text or "_plex" in text:
                device_type = "Media Device"
            elif "Apple" in text:
                device_type = "Apple Device"

            # Try to get vendor from device name in finding
            vendor = ""
            name_match = re.search(r"device:\s*(.+?)(?:\s*\(|\s*$)", text, re.I)
            if name_match:
                name = name_match.group(1).strip()
                # Check if name starts with a known vendor
                for alias_key in self._aliases:
                    if name.lower().startswith(alias_key):
                        vendor = self._aliases[alias_key]
                        break

            if device_type or vendor:
                return _Evidence(
                    source="mdns",
                    vendor=self._normalize_vendor(vendor),
                    device_type=device_type,
                    confidence=0.55,
                )

        return None

    def _extract_from_port_heuristics(
        self, ip: str, host_info: HostInfo, findings: List[Finding]
    ) -> Optional[_Evidence]:
        """Infer device type from open port combinations."""
        open_ports = {p.port for p in host_info.ports.values() if p.state == "open"}
        if not open_ports:
            return None

        best: Optional[_Evidence] = None
        best_conf = 0.0

        for required_ports, device_type, conf in _PORT_DEVICE_HINTS:
            if required_ports.issubset(open_ports):
                if conf > best_conf:
                    best = _Evidence(
                        source="port_heuristics",
                        device_type=device_type,
                        confidence=conf,
                    )
                    best_conf = conf

        return best

    def _extract_from_nmap_service_info(
        self, ip: str, host_info: HostInfo, findings: List[Finding]
    ) -> List[_Evidence]:
        """Extract vendor/model from nmap service product and version fields."""
        results: List[_Evidence] = []

        for port_info in host_info.ports.values():
            if port_info.state != "open":
                continue

            product = port_info.service or ""
            version = port_info.version or ""

            if not product and not version:
                continue

            # nmap service fields often contain vendor/product info
            combined = f"{product} {version}"

            # Specific product patterns
            nmap_svc_patterns = [
                (re.compile(r'Synology\s+DSM', re.I),   "Synology", "NAS",     ""),
                (re.compile(r'MikroTik\s+(\S+)', re.I),  "MikroTik", "Router",  ""),
                (re.compile(r'APC\s+(\S+)', re.I),       "APC",      "UPS",     ""),
                (re.compile(r'iLO\s+(\d)', re.I),        "HPE",      "Server",  ""),
                (re.compile(r'IPMI', re.I),              "",          "Server",  ""),
            ]

            for pattern, vendor, device_type, model in nmap_svc_patterns:
                m = pattern.search(combined)
                if m:
                    results.append(_Evidence(
                        source="nmap_service",
                        vendor=self._normalize_vendor(vendor),
                        model=m.group(1).strip() if m.lastindex else model,
                        device_type=device_type,
                        confidence=0.45,
                    ))
                    break

        return results

    def _extract_from_ja3s(
        self, ip: str, host_info: HostInfo, findings: List[Finding]
    ) -> Optional[List[_Evidence]]:
        """Extract vendor/device type from JA3S TLS fingerprint matches."""
        try:
            from core.ssl_checker import get_last_ja3s_match
        except ImportError:
            return None

        results: List[_Evidence] = []

        for port_info in host_info.ports.values():
            if port_info.state != "open":
                continue
            # Check ports that might have TLS
            port = port_info.port
            match = get_last_ja3s_match(ip, port)
            if not match:
                continue

            app_name, app_desc = match
            if not app_name:
                continue

            # Try to map app name to vendor/device_type
            vendor = ""
            device_type = ""
            for pattern, pat_vendor, pat_dtype in _JA3S_APP_PATTERNS:
                if pattern.search(app_name):
                    vendor = pat_vendor
                    device_type = pat_dtype
                    break

            if vendor or device_type:
                results.append(_Evidence(
                    source="ja3s",
                    vendor=self._normalize_vendor(vendor),
                    device_type=device_type,
                    confidence=0.5,
                ))

        return results if results else None

    def _extract_from_ftp_banner(
        self, ip: str, host_info: HostInfo, findings: List[Finding]
    ) -> Optional[_Evidence]:
        """Extract OS/vendor hints from FTP server banners."""
        for port_info in host_info.ports.values():
            if port_info.service != "ftp":
                continue

            banner = port_info.banner or port_info.version or ""
            if not banner:
                continue

            for pattern, vendor, device_type, conf in _FTP_BANNER_PATTERNS:
                m = pattern.search(banner)
                if m:
                    version = ""
                    if m.lastindex and m.lastindex >= 1 and m.group(1):
                        version = m.group(1).strip()
                    return _Evidence(
                        source="ftp_banner",
                        vendor=self._normalize_vendor(vendor),
                        version=version,
                        device_type=device_type,
                        confidence=conf,
                    )

        return None

    # ---- CPE / Wappalyzer Helpers ----

    @staticmethod
    def _parse_cpe(cpe_str: str, detected_version: str = "") -> Optional[_Evidence]:
        """Parse a CPE 2.3 string into an _Evidence.

        Format: cpe:2.3:a:VENDOR:PRODUCT:VERSION:*:*:*:*:*:*:*
        Vendor and product fields use underscores for spaces and may contain
        escaped characters (e.g. ``joomla\\!``).
        """
        parts = cpe_str.split(":")
        if len(parts) < 6:
            return None

        # parts[3] = vendor, parts[4] = product, parts[5] = version
        raw_vendor = parts[3].replace("_", " ").replace("\\", "").strip()
        raw_product = parts[4].replace("_", " ").replace("\\", "").strip()
        raw_version = parts[5] if len(parts) > 5 else ""

        if raw_version in ("*", "-", ""):
            raw_version = detected_version or ""

        if not raw_vendor and not raw_product:
            return None

        # Capitalize nicely
        vendor = raw_vendor.title() if raw_vendor else ""
        product = raw_product  # keep original casing where possible

        return _Evidence(
            source="wappalyzer_cpe",
            vendor=vendor,
            model=product,
            version=raw_version,
            confidence=0.45,
        )

    def _get_wappalyzer_db(self) -> Dict[str, dict]:
        """Lazy-load the Wappalyzer technology database."""
        if self._wappalyzer_db is not None:
            return self._wappalyzer_db

        for path in (_WAPPALYZER_FULL_PATH, _WAPPALYZER_MINI_PATH):
            if path.exists():
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        self._wappalyzer_db = json.load(f)
                    logger.debug(
                        f"DeviceIdentifier: loaded {len(self._wappalyzer_db)} "
                        f"Wappalyzer entries from {path.name}"
                    )
                    return self._wappalyzer_db
                except Exception as e:
                    logger.debug(f"Failed to load {path.name}: {e}")

        self._wappalyzer_db = {}
        return self._wappalyzer_db

    def _get_model_vendor_index(self) -> Dict[str, str]:
        """Lazy-load a reverse index: {normalized_model_name: vendor} from credentials DB."""
        if self._model_vendor_index is not None:
            return self._model_vendor_index

        index: Dict[str, str] = {}

        # Primary source: default_credentials.json common_models
        if _DEFAULT_CREDS_PATH.exists():
            try:
                with open(_DEFAULT_CREDS_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                creds = data.get("credentials", {})
                for vendor_name, info in creds.items():
                    models = info.get("common_models", [])
                    for model in models:
                        index[model.lower()] = vendor_name
                logger.debug(
                    f"DeviceIdentifier: built model-vendor index with "
                    f"{len(index)} entries from default_credentials.json"
                )
            except Exception as e:
                logger.debug(f"Failed to load default_credentials.json: {e}")

        self._model_vendor_index = index
        return self._model_vendor_index

    # ---- Fusion Algorithm ----

    def _fuse(self, evidence: List[_Evidence]) -> DeviceIdentity:
        """Fuse multiple evidence items into a single DeviceIdentity.

        For each field (vendor, model, version, device_type), collects
        all non-empty values with their confidence weights. Values from
        different sources that agree (after normalization) have their
        confidences summed. The value with the highest total confidence wins.
        """
        fields = ["vendor", "model", "version", "device_type"]
        result = {}
        field_confidences = {}
        contributing_sources = set()

        for field_name in fields:
            # Collect (normalized_value, confidence, source) for this field
            votes: Dict[str, float] = {}
            sources_per_value: Dict[str, List[str]] = {}

            for ev in evidence:
                val = getattr(ev, field_name, "").strip()
                if not val:
                    continue

                # Normalize for comparison
                norm = val.lower()
                if field_name == "vendor":
                    norm = self._normalize_vendor(val).lower()
                    val = self._normalize_vendor(val)

                votes[norm] = votes.get(norm, 0) + ev.confidence
                if norm not in sources_per_value:
                    sources_per_value[norm] = []
                sources_per_value[norm].append(ev.source)

            if not votes:
                result[field_name] = ""
                field_confidences[field_name] = 0.0
                continue

            # Winner = highest total confidence
            winner_norm = max(votes, key=lambda k: votes[k])
            winner_conf = min(votes[winner_norm], 1.0)

            # Agreement bonus: N distinct sources agreeing boost confidence
            n_sources = len(set(sources_per_value.get(winner_norm, [])))
            if n_sources >= 2:
                winner_conf = min(winner_conf * (1 + 0.1 * (n_sources - 1)), 1.0)

            # Conflict penalty: if competing values exist, reduce winner
            if len(votes) > 1:
                loser_total = sum(c for k, c in votes.items() if k != winner_norm)
                winner_conf = max(winner_conf - loser_total * 0.3, 0.0)

            # Get the original (non-normalized) value — use the first seen
            winner_val = ""
            for ev in evidence:
                val = getattr(ev, field_name, "").strip()
                if not val:
                    continue
                norm = val.lower()
                if field_name == "vendor":
                    norm = self._normalize_vendor(val).lower()
                    val = self._normalize_vendor(val)
                if norm == winner_norm:
                    winner_val = val
                    break

            if winner_conf < 0.15:
                result[field_name] = ""
                field_confidences[field_name] = 0.0
            else:
                result[field_name] = winner_val
                field_confidences[field_name] = winner_conf
                contributing_sources.update(sources_per_value.get(winner_norm, []))

        # Post-fusion: validate/boost vendor from model-vendor index
        model_val = result.get("model", "")
        vendor_val = result.get("vendor", "")
        if model_val:
            idx = self._get_model_vendor_index()
            idx_vendor = idx.get(model_val.lower())
            if idx_vendor:
                norm_idx = self._normalize_vendor(idx_vendor)
                if not vendor_val:
                    # No vendor found by extractors — fill from index
                    result["vendor"] = norm_idx
                    field_confidences["vendor"] = 0.3
                    contributing_sources.add("credentials_model_index")
                elif norm_idx.lower() == self._normalize_vendor(vendor_val).lower():
                    # Vendor agrees — boost confidence
                    field_confidences["vendor"] = min(
                        field_confidences.get("vendor", 0) + 0.3, 1.0
                    )
                    contributing_sources.add("credentials_model_index")

        # Overall confidence = weighted average of non-zero field confidences
        non_zero = [(c, f) for f, c in field_confidences.items() if c > 0]
        if non_zero:
            # Weight vendor and device_type more heavily
            weights = {"vendor": 2.0, "model": 1.5, "version": 1.0, "device_type": 1.5}
            total_weight = sum(weights.get(f, 1.0) for c, f in non_zero)
            overall = sum(c * weights.get(f, 1.0) for c, f in non_zero) / total_weight
        else:
            overall = 0.0

        return DeviceIdentity(
            vendor=result.get("vendor", ""),
            model=result.get("model", ""),
            version=result.get("version", ""),
            device_type=result.get("device_type", ""),
            confidence=min(overall, 1.0),
            sources=sorted(contributing_sources),
        )

    # ---- Helper Methods ----

    def _normalize_vendor(self, vendor: str) -> str:
        """Normalize vendor name using alias database."""
        if not vendor:
            return ""
        canonical = self._aliases.get(vendor.lower().strip())
        if canonical:
            return canonical
        # Return with first letter capitalized if no alias found
        return vendor.strip()

    def _lookup_oui(self, mac: str) -> Optional[str]:
        """Look up vendor from MAC address OUI prefix."""
        if self._oui_db is None:
            self._oui_db = self._load_oui_db()

        if not self._oui_db:
            return None

        # Normalize MAC to XX:XX:XX prefix
        clean = mac.upper().replace("-", ":").replace(".", ":")
        parts = clean.split(":")
        if len(parts) >= 3:
            prefix = ":".join(parts[:3])
            return self._oui_db.get(prefix)

        return None

    def _load_oui_db(self) -> Dict[str, str]:
        """Load OUI database from cached JSON."""
        if not _OUI_CACHE_PATH.exists():
            logger.debug("OUI database not found — run --download mac-oui")
            return {}
        try:
            with open(_OUI_CACHE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.debug(f"Failed to load OUI database: {e}")
            return {}

    @staticmethod
    def _load_aliases() -> Dict[str, str]:
        """Load vendor alias mapping from JSON."""
        if not _ALIASES_PATH.exists():
            logger.debug("device_aliases.json not found")
            return {}
        try:
            with open(_ALIASES_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.debug(f"Failed to load device aliases: {e}")
            return {}
