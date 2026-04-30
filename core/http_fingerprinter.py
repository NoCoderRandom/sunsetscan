"""
NetWatch HTTP Fingerprinter Module.

This module provides HTTP-based fingerprinting for network devices,
especially useful for finding firmware versions on routers, access points,
and IoT devices that expose web management interfaces.

Exports:
    HttpFingerprinter: Main class for HTTP fingerprinting
    HttpFingerprint: Dataclass for fingerprint results
    DeviceSignature: Known device signatures database

Example:
    from core.http_fingerprinter import HttpFingerprinter
    fingerprinter = HttpFingerprinter()

    result = fingerprinter.fingerprint("192.168.1.115", 80)
    print(f"Device: {result.device_type}, Firmware: {result.firmware_version}")
"""

import logging
import re
import urllib3
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config.settings import Settings

# Suppress SSL warnings for local device scanning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Suppress urllib3 connection pool warnings (retries, SSL errors, etc.)
logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)
logging.getLogger("urllib3.util.retry").setLevel(logging.ERROR)
logging.getLogger("requests.packages.urllib3").setLevel(logging.ERROR)

logger = logging.getLogger(__name__)


@dataclass
class HttpFingerprint:
    """Result of HTTP fingerprinting.

    Attributes:
        host: Target IP address
        port: Target port
        device_type: Detected device type/manufacturer
        model: Device model name
        firmware_version: Firmware version string
        hardware_version: Hardware version string
        raw_headers: Raw HTTP response headers
        raw_html: Raw HTML content (truncated)
        confidence: Detection confidence (0.0-1.0)
        source: How the info was detected (header/body/title/etc)
    """
    host: str
    port: int
    device_type: str = ""
    model: str = ""
    firmware_version: str = ""
    hardware_version: str = ""
    raw_headers: Dict[str, str] = field(default_factory=dict)
    raw_html: str = ""
    confidence: float = 0.0
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'host': self.host,
            'port': self.port,
            'device_type': self.device_type,
            'model': self.model,
            'firmware_version': self.firmware_version,
            'hardware_version': self.hardware_version,
            'confidence': self.confidence,
            'source': self.source,
        }


class HttpFingerprinter:
    """HTTP fingerprinter for detecting device information from web interfaces.

    This class fetches web pages and analyzes HTTP responses to extract
    firmware versions, device models, and manufacturer information.
    Useful for IoT devices, routers, access points, and other equipment
    with web management interfaces.

    Attributes:
        settings: Configuration settings
        session: requests.Session with retry logic

    Example:
        fingerprinter = HttpFingerprinter()

        # Fingerprint a single device
        result = fingerprinter.fingerprint("192.168.1.115", 80)

        # Extract just version info for banner grabbing
        version = fingerprinter.get_version_string("192.168.1.115", 80)
    """

    # Common paths to check on web servers
    COMMON_PATHS = [
        "/",
        "/Main_Login.asp",       # ASUS routers
        "/message.htm",          # ASUS AiMesh nodes
        "/js/app/url.js",        # ASUS model / firmware hints
        "/locale/language.js",   # ASUS locale/bootstrap data
        "/webman/index.cgi",     # Synology DSM
        "/login",
        "/login.html",
        "/index.html",
        "/status",
        "/info",
        "/system",
        "/admin",
        "/config",
        "/help",
        "/about",
        "/version",
        "/favicon.ico",
        "/robots.txt",
        "/cgi-bin/luci",
        "/cgi-bin/login",
    ]

    # Known device signatures (regex patterns)
    # Format: (name, pattern, extract_group_for_version)
    # group=None means no capture group, just detect presence
    DEVICE_SIGNATURES = [
        # TP-Link
        ("TP-Link", r'(tplink|tp-link|TP-LINK)', 1),  # Capture group for brand
        ("TP-Link Firmware", r'Firmware\s*(?:Version)?[:\s]*V?([\d.]+(?:\s*Build\s*[\d]+)?)', 1),
        ("TP-Link Firmware Alt", r'Firmware[^\d]{0,10}(\d+\.\d+[^\s<]*)', 1),
        ("TP-Link Hardware", r'Hardware\s*(?:Version)?[:\s]*([\w\s\d.]+)', 1),
        ("TP-Link Model", r'(RE\d{3,5}|TL-[A-Z]{2}\d+|Archer\s*[A-Z]\d+|Deco\s*[A-Z]\d+)', 1),
        ("TP-Link Script", r'(tpEncrypt|tplink|su/language)', 1),

        # ASUS
        ("ASUS", r'ASUS|Asus', None),
        ("ASUS", r'Main_Login\.asp', None),              # ASUS redirect page
        ("ASUS", r'AiMesh\s+router', None),              # AiMesh detection page
        ("ASUS Firmware", r'Firmware:\s*([\d.]+)', 1),
        ("ASUS Firmware", r'firmver["\s:=]+([\d.]+)', 1), # ASUS nvram
        ("ASUS Router Model", r'((?:RT|GT|TUF|ROG|ZenWiFi)-[A-Z]{0,3}[0-9]+[A-Z0-9]*)', 1),

        # Synology
        ("Synology", r'Synology', None),
        ("Synology", r'webman/index\.cgi', None),            # DSM path
        ("Synology", r'synoSDSjslib', None),                 # DSM JS lib
        ("Synology Firmware", r'DSM\s+([\d.]+(?:-\d+)?)', 1), # DSM version e.g. "DSM 7.2.1-69057"
        ("Synology Model", r'(DS\d{3,4}\+?|RS\d{3,4}\+?|DVA\d{3,4})', 1),

        # QNAP
        ("QNAP", r'QNAP|QTS|QuTS', None),
        ("QNAP Model", r'(TS-\d{3,4}[A-Z]*)', 1),

        # HP printers
        ("HP", r'\b(?:HP|Hewlett[- ]Packard|DeskJet|LaserJet|OfficeJet|ENVY)\b', None),
        ("HP Printer Model", r'\bHP\s+((?:DeskJet|LaserJet|OfficeJet|ENVY|Smart Tank|PageWide)[^;<\r\n]+)', 1),
        ("HP Printer Model", r'\b((?:DeskJet|LaserJet|OfficeJet|ENVY|Smart Tank|PageWide)\s+[^;<\r\n]+)', 1),

        # Netgear
        ("Netgear", r'NETGEAR|Netgear', None),
        ("Netgear Firmware", r'Firmware[^\d]*(V?[\d.]+)', 1),
        ("Netgear Model", r'(R\d{4,5}|EX\d{4,5}|XR\d{3,4})', 1),

        # Linksys
        ("Linksys", r'Linksys|LINKSYS', None),
        ("Linksys Firmware", r'Firmware[^\d]*([\d.]+)', 1),

        # D-Link
        ("D-Link", r'D-Link|DLink', None),
        ("D-Link Firmware", r'Firmware[^\d]*([\d.]+)', 1),
        ("D-Link Model", r'DIR-\w+', 0),

        # Ubiquiti
        ("Ubiquiti", r'\b(?:Ubiquiti|UniFi|UBNT)\b', None),
        ("Ubiquiti Firmware", r'firmware[^\d]*([\d.]+)', 1),

        # Cisco
        ("Cisco", r'Cisco|CISCO', None),
        ("Cisco IOS", r'IOS[^\d]*([\d.()]+)', 1),

        # MikroTik
        ("MikroTik", r'MikroTik|RouterOS', None),
        ("MikroTik RouterOS", r'RouterOS[^\d]*([\d.]+)', 1),

        # OpenWrt/DD-WRT/Tomato
        ("OpenWrt", r'OpenWrt', None),
        ("OpenWrt Version", r'OpenWrt[^\d]*([\d.]+)', 1),
        ("DD-WRT", r'DD-WRT', None),
        ("Tomato", r'Tomato', None),

        # Generic patterns
        ("Generic Firmware", r'[Ff]irmware\s*[Vv]ersion[:\s]+([\d.]+)', 1),
        ("Generic Firmware Alt", r'[Ff]irmware[:\s]+([\d.]+)', 1),
        ("Generic Version", r'[Vv]ersion[:\s]+([\d.]+)', 1),
        ("Generic Hardware", r'[Hh]ardware\s*[Vv]ersion[:\s]+([\w\d.]+)', 1),
        ("Build Number", r'[Bb]uild[:\s]+([\d]+)', 1),
    ]

    # HTTP Header signatures
    HEADER_SIGNATURES = [
        ("Server", r'Apache/?([\d.]+)?', 'apache'),
        ("Server", r'nginx/?([\d.]+)?', 'nginx'),
        ("Server", r'mini_httpd/?([\d.]+)?', 'mini_httpd'),
        ("Server", r'HP HTTP Server;\s*HP\s+([^;]+)', 'HP'),
        ("Server", r'Thd/?([\d.]+)?', 'tp-link-httpd'),
        ("Server", r'httpd/2\.0$', 'ASUS'),          # ASUS routers use httpd/2.0
        ("Server", r'httpd', 'generic-httpd'),
        ("Server", r'Synology', 'Synology'),
        ("X-Powered-By", r'PHP/?([\d.]+)?', 'php'),
        ("WWW-Authenticate", r'Basic realm="([^"]+)"', 'auth-realm'),
    ]

    def __init__(self, settings: Optional[Settings] = None, timeout: Optional[float] = None):
        """Initialize HTTP fingerprinter.

        Args:
            settings: Configuration settings
            timeout: Request timeout in seconds
        """
        self.settings = settings or Settings()
        self.timeout = timeout if timeout is not None else self.settings.banner_timeout

        # Create session with retry logic
        self.session = requests.Session()
        retry_strategy = Retry(total=0)
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Default headers to mimic a browser
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })

        logger.debug("HttpFingerprinter initialized")

    @staticmethod
    def _has_useful_identity(result: HttpFingerprint) -> bool:
        """Return True once the response has enough data for device identity."""
        return bool(
            result.confidence >= 0.6
            and result.device_type
            and (result.model or result.firmware_version)
        )

    @staticmethod
    def _clean_printer_model(model: str) -> str:
        """Trim volatile printer firmware/build data from model strings."""
        model = re.split(r'\s*;\s*', model, maxsplit=1)[0].strip()
        model = re.sub(r'\s+-\s+[A-Z0-9._-]{4,}$', '', model).strip()
        return model

    def _fetch_with_socket(self, host: str, port: int, use_ssl: bool = False) -> Optional[str]:
        """Fetch HTTP response using raw sockets (fallback method).

        Args:
            host: Target host
            port: Target port
            use_ssl: Whether to use SSL/TLS

        Returns:
            Response text or None
        """
        import socket
        import ssl as ssl_module

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))

            if use_ssl:
                context = ssl_module.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl_module.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

            # Send HTTP request
            request = b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
            sock.send(request)

            # Receive response
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 10000:  # Limit size
                        break
                except socket.timeout:
                    break

            return response.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.debug(f"Socket fetch error: {e}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass

    def fingerprint(self, host: str, port: int) -> HttpFingerprint:
        """Perform HTTP fingerprinting on a host:port.

        Tries multiple paths and analyzes responses to extract device info.

        Args:
            host: Target IP address
            port: Target port

        Returns:
            HttpFingerprint with detected information
        """
        result = HttpFingerprint(host=host, port=port)

        # Determine protocol (http vs https)
        # For port 80, try HTTP first. For 443/8443, try HTTPS first
        protocols = ["http", "https"] if port == 80 else ["https", "http"] if port in [443, 8443] else ["http", "https"]

        for protocol in protocols:
            for path in self.COMMON_PATHS:
                try:
                    url = f"{protocol}://{host}:{port}{path}"
                    logger.debug(f"Fetching: {url}")

                    response = self.session.get(
                        url,
                        timeout=self.timeout,
                        verify=False,  # Don't verify SSL for local devices
                        allow_redirects=True
                    )

                    # Store headers
                    result.raw_headers = dict(response.headers)

                    # Store truncated HTML
                    result.raw_html = response.text[:5000]

                    # Analyze response
                    self._analyze_response(result, response)

                    logger.debug(f"Successfully fetched {url}, status: {response.status_code}")

                    # If we found good info, stop here
                    if result.confidence >= 0.8 and result.firmware_version:
                        return result
                    if self._has_useful_identity(result):
                        return result

                except requests.exceptions.SSLError as e:
                    logger.debug(f"SSL error for {url}: {e}")
                    continue
                except requests.exceptions.ConnectionError as e:
                    logger.debug(f"Connection error for {url}: {e}")
                    continue
                except requests.exceptions.Timeout:
                    logger.debug(f"Timeout fetching {url}")
                    continue
                except Exception as e:
                    logger.debug(f"Error fetching {url}: {e}")
                    # Try to extract any info even on error
                    continue

        # Fallback: try raw socket method if requests didn't work
        if not result.raw_html:
            logger.debug("Trying raw socket fallback")
            for use_ssl in [False, True] if port != 80 else [False]:
                html = self._fetch_with_socket(host, port, use_ssl)
                if html:
                    result.raw_html = html[:5000]
                    # Create a mock response for analysis
                    class MockResponse:
                        def __init__(self, text, headers):
                            self.text = text
                            self.headers = headers

                    self._analyze_response(result, MockResponse(html, {}))
                    if result.device_type or result.firmware_version:
                        logger.debug(f"Found data via socket method (ssl={use_ssl})")
                        return result

        return result

    def _analyze_response(self, result: HttpFingerprint, response: requests.Response) -> None:
        """Analyze HTTP response for device information.

        Args:
            result: Fingerprint result to populate
            response: HTTP response object
        """
        text = response.text
        headers = response.headers

        server_header = headers.get("Server", "") or headers.get("server", "")
        hp_server = re.search(r'HP HTTP Server;\s*HP\s+([^;]+)', server_header, re.IGNORECASE)
        if hp_server:
            raw_model = hp_server.group(1).strip()
            firmware_match = re.search(r'\s+-\s+([A-Z0-9._-]{4,})$', raw_model)
            result.device_type = "HP"
            result.model = self._clean_printer_model(raw_model)
            if firmware_match and not result.firmware_version:
                result.firmware_version = firmware_match.group(1)
            result.source = "header:Server"
            result.confidence = max(result.confidence, 0.75)

        # Check headers first
        for header_name, pattern, device_hint in self.HEADER_SIGNATURES:
            header_value = headers.get(header_name, "")
            match = re.search(pattern, header_value, re.IGNORECASE)
            if match:
                if device_hint and not result.device_type:
                    result.device_type = device_hint
                    result.source = f"header:{header_name}"
                    # Vendor-specific headers get higher confidence than generic
                    if device_hint in ("ASUS", "Synology", "QNAP"):
                        result.confidence = 0.5
                    else:
                        result.confidence = 0.3

        # Check for device type signatures
        for name, pattern, group in self.DEVICE_SIGNATURES:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                logger.debug(f"Found matches for {name}: {matches[:2]}")

                # Get the first match
                match = matches[0]

                # Device type detection — vendor-specific body matches override
                # generic header detections (e.g. "Synology" overrides "nginx")
                _VENDOR_NAMES = ["TP-Link", "ASUS", "Netgear", "Linksys", "D-Link",
                                 "Ubiquiti", "Cisco", "MikroTik", "Synology", "QNAP",
                                 "HP"]
                _VENDOR_ASSERTING_SIGNATURES = {
                    "TP-Link",
                    "TP-Link Script",
                    "TP-Link Model",
                    "ASUS",
                    "ASUS Router Model",
                    "Synology",
                    "Synology Model",
                    "QNAP",
                    "QNAP Model",
                    "HP",
                    "HP Printer Model",
                    "Netgear",
                    "Netgear Model",
                    "Linksys",
                    "D-Link",
                    "D-Link Model",
                    "Ubiquiti",
                    "Cisco",
                    "MikroTik",
                    "OpenWrt",
                    "DD-WRT",
                    "Tomato",
                }
                _GENERIC_HEADERS = {"nginx", "apache", "generic-httpd", "mini_httpd",
                                    "tp-link-httpd", "php", "auth-realm"}
                signature_vendor = next(
                    (vendor_name for vendor_name in _VENDOR_NAMES if name.startswith(vendor_name)),
                    "",
                )
                if name in _VENDOR_ASSERTING_SIGNATURES:
                    if not result.device_type or result.device_type.lower() in _GENERIC_HEADERS:
                        result.device_type = name.split()[0]
                        result.source = "body"
                        result.confidence = max(result.confidence, 0.5)

                # Model detection — only accept if model's vendor matches
                # detected device_type (e.g. don't set TP-Link Model on ASUS)
                if "Model" in name and group is not None:
                    model_vendor = name.split(" Model")[0]  # e.g. "ASUS Router"
                    vendor_matches = (not result.device_type or
                                     model_vendor.startswith(result.device_type) or
                                     result.device_type.startswith(model_vendor.split()[0]))
                    if vendor_matches:
                        if isinstance(match, tuple):
                            result.model = match[group-1] if group <= len(match) else match[0]
                        else:
                            result.model = match
                        result.confidence = min(result.confidence + 0.1, 0.9)

                # Firmware version detection
                if "Firmware" in name and group is not None:
                    if signature_vendor and result.device_type != signature_vendor:
                        continue
                    if isinstance(match, tuple):
                        version = match[group-1] if group <= len(match) else match[0]
                    else:
                        version = match

                    if version and not result.firmware_version:
                        result.firmware_version = version
                        result.source = "body:firmware"
                        result.confidence = 0.9

                # Hardware version detection
                if "Hardware" in name and group is not None:
                    if signature_vendor and result.device_type != signature_vendor:
                        continue
                    if isinstance(match, tuple):
                        hw = match[group-1] if group <= len(match) else match[0]
                    else:
                        hw = match

                    if hw and not result.hardware_version:
                        result.hardware_version = hw.strip()

        # Try to extract title
        title_match = re.search(r'<title>([^<]+)</title>', text, re.IGNORECASE)
        if title_match and not result.model:
            title = title_match.group(1).strip()
            # Check if title contains model info
            for name, pattern, _ in self.DEVICE_SIGNATURES:
                if "Model" in name:
                    match = re.search(pattern, title, re.IGNORECASE)
                    if match:
                        result.model = match.group(0)
                        result.source = "title"
                        result.confidence = 0.6

    def get_version_string(self, host: str, port: int) -> str:
        """Get a simple version string for banner integration.

        Args:
            host: Target IP address
            port: Target port

        Returns:
            Version string suitable for EOL checking
        """
        result = self.fingerprint(host, port)

        parts = []
        if result.device_type:
            parts.append(result.device_type.lower())
        if result.model:
            parts.append(result.model)
        if result.firmware_version:
            parts.append(result.firmware_version)

        return " ".join(parts) if parts else ""

    def fingerprint_batch(
        self,
        targets: List[Tuple[str, int]]
    ) -> List[HttpFingerprint]:
        """Fingerprint multiple targets.

        Args:
            targets: List of (host, port) tuples

        Returns:
            List of fingerprint results
        """
        results = []
        for host, port in targets:
            result = self.fingerprint(host, port)
            results.append(result)
        return results
