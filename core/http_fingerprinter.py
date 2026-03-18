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
        "/js/app/url.js",
        "/locale/language.js",
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
        ("TP-Link Model", r'(RE\d+|TL-\w+|Archer\s*\w+|Deco\s*\w+)', 1),
        ("TP-Link Script", r'(tpEncrypt|tplink|su/language)', 1),
        
        # ASUS
        ("ASUS", r'ASUS|Asus', None),
        ("ASUS Firmware", r'Firmware:\s*([\d.]+)', 1),
        ("ASUS Router Model", r'RT-[A-Z]?\d+[A-Z]*', 0),
        
        # Netgear
        ("Netgear", r'NETGEAR|Netgear', None),
        ("Netgear Firmware", r'Firmware[^\d]*(V?[\d.]+)', 1),
        ("Netgear Model", r'(R\d+|EX\d+|XR\d+)', 1),
        
        # Linksys
        ("Linksys", r'Linksys|LINKSYS', None),
        ("Linksys Firmware", r'Firmware[^\d]*([\d.]+)', 1),
        
        # D-Link
        ("D-Link", r'D-Link|DLink', None),
        ("D-Link Firmware", r'Firmware[^\d]*([\d.]+)', 1),
        ("D-Link Model", r'DIR-\w+', 0),
        
        # Ubiquiti
        ("Ubiquiti", r'Ubiquiti|UniFi|UBNT', None),
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
        ("Server", r'Thd/?([\d.]+)?', 'tp-link-httpd'),
        ("Server", r'httpd', 'generic-httpd'),
        ("X-Powered-By", r'PHP/?([\d.]+)?', 'php'),
        ("WWW-Authenticate", r'Basic realm="([^"]+)"', 'auth-realm'),
    ]
    
    def __init__(self, settings: Optional[Settings] = None, timeout: int = 10):
        """Initialize HTTP fingerprinter.
        
        Args:
            settings: Configuration settings
            timeout: Request timeout in seconds
        """
        self.settings = settings or Settings()
        self.timeout = timeout
        
        # Create session with retry logic
        self.session = requests.Session()
        retry_strategy = Retry(
            total=2,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
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
        
        # Check headers first
        for header_name, pattern, device_hint in self.HEADER_SIGNATURES:
            header_value = headers.get(header_name, "")
            match = re.search(pattern, header_value, re.IGNORECASE)
            if match:
                if device_hint and not result.device_type:
                    result.device_type = device_hint
                    result.source = f"header:{header_name}"
                    result.confidence = 0.3
        
        # Check for device type signatures
        for name, pattern, group in self.DEVICE_SIGNATURES:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                logger.debug(f"Found matches for {name}: {matches[:2]}")
                
                # Get the first match
                match = matches[0]
                
                # Device type detection
                if not result.device_type and any(x in name for x in ["TP-Link", "ASUS", "Netgear", "Linksys", "D-Link", "Ubiquiti", "Cisco", "MikroTik"]):
                    result.device_type = name.split()[0]  # First word is manufacturer
                    result.source = "body"
                    result.confidence = 0.5
                
                # Model detection
                if "Model" in name and group is not None:
                    if isinstance(match, tuple):
                        result.model = match[group-1] if group <= len(match) else match[0]
                    else:
                        result.model = match
                    result.confidence = min(result.confidence + 0.1, 0.9)
                
                # Firmware version detection
                if "Firmware" in name and group is not None:
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
