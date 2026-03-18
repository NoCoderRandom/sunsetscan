"""
NetWatch Banner Grabber Module.

This module provides raw socket banner grabbing capabilities for open ports
discovered during network scans. Uses threading for concurrent connections.
For HTTP/HTTPS services, it also performs HTTP fingerprinting to extract
firmware versions from web interfaces.

Exports:
    BannerGrabber: Main class for concurrent banner grabbing
    BannerResult: Dataclass for banner grab results

Example:
    from core.banner_grabber import BannerGrabber
    grabber = BannerGrabber()
    banners = grabber.grab_banners("192.168.1.1", [22, 80, 443])
"""

import logging
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any

from config.settings import Settings

logger = logging.getLogger(__name__)


@dataclass
class BannerResult:
    """Result of a banner grab attempt.
    
    Attributes:
        host: Target IP address
        port: Target port number
        protocol: Protocol used (tcp/udp)
        raw_banner: Raw banner bytes decoded to string
        parsed_name: Parsed product name from banner
        parsed_version: Parsed version from banner
        error: Error message if grab failed
        is_ssl: Whether SSL/TLS was used
        http_fingerprint: HTTP fingerprint data (for web services)
    """
    host: str
    port: int
    protocol: str = "tcp"
    raw_banner: str = ""
    parsed_name: str = ""
    parsed_version: str = ""
    error: str = ""
    is_ssl: bool = False
    http_fingerprint: Optional[Any] = None


class BannerGrabber:
    """Concurrent banner grabber using raw sockets.
    
    This class handles raw socket connections to grab banners from services.
    It supports SSL/TLS connections and handles various error conditions.
    For HTTP/HTTPS services, it also performs HTTP fingerprinting.
    ThreadPoolExecutor is used for concurrent grabbing.
    
    Attributes:
        settings: Settings configuration object
        timeout: Connection timeout in seconds
        max_workers: Maximum concurrent threads
        http_fingerprinter: HttpFingerprinter for web services
        
    Example:
        grabber = BannerGrabber(timeout=5)
        result = grabber.grab_banner("192.168.1.1", 22)
        print(result.raw_banner)
    """
    
    # Common service probes to send
    PROBES = {
        'http': b'GET / HTTP/1.0\r\n\r\n',
        'smtp': b'EHLO netwatch\r\n',
        'ftp': b'',  # FTP usually sends banner immediately
        'ssh': b'',  # SSH sends banner immediately
        'telnet': b'\r\n',
        'generic': b'\r\n\r\n',
    }
    
    # Ports that typically use SSL/TLS
    SSL_PORTS = {443, 465, 587, 636, 993, 995, 3389, 8443}
    
    # Ports that typically serve HTTP/HTTPS
    HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 9000, 8081}
    
    def __init__(
        self, 
        settings: Optional[Settings] = None,
        timeout: Optional[int] = None,
        max_workers: Optional[int] = None,
        enable_http_fingerprinting: bool = True
    ):
        """Initialize the banner grabber.
        
        Args:
            settings: Configuration settings. Uses defaults if not provided.
            timeout: Override for connection timeout (seconds)
            max_workers: Override for max concurrent threads
            enable_http_fingerprinting: Whether to enable HTTP fingerprinting
        """
        self.settings = settings or Settings()
        self.timeout = timeout or self.settings.banner_timeout
        self.max_workers = max_workers or self.settings.max_threads
        self.enable_http_fingerprinting = enable_http_fingerprinting
        
        # Initialize HTTP fingerprinter
        self.http_fingerprinter = None
        if enable_http_fingerprinting:
            try:
                from core.http_fingerprinter import HttpFingerprinter
                self.http_fingerprinter = HttpFingerprinter(settings=self.settings)
                logger.debug("HTTP fingerprinting enabled")
            except ImportError as e:
                logger.warning(f"Could not enable HTTP fingerprinting: {e}")
        
        logger.debug(f"BannerGrabber initialized (timeout={self.timeout}s, "
                    f"max_workers={self.max_workers})")
    
    def grab_banner(
        self, 
        host: str, 
        port: int,
        use_ssl: Optional[bool] = None
    ) -> BannerResult:
        """Grab banner from a single host:port.
        
        Attempts to connect and retrieve service banner. Automatically
        detects SSL/TLS for common ports. For HTTP/HTTPS services, also
        performs HTTP fingerprinting to extract firmware versions.
        
        Args:
            host: Target IP address
            port: Target port number
            use_ssl: Force SSL/TLS (None = auto-detect)
            
        Returns:
            BannerResult with banner data or error information
        """
        result = BannerResult(host=host, port=port)
        
        # Auto-detect SSL if not specified
        if use_ssl is None:
            use_ssl = port in self.SSL_PORTS
        result.is_ssl = use_ssl
        
        # For HTTP ports, try HTTP fingerprinting first
        if port in self.HTTP_PORTS and self.http_fingerprinter:
            try:
                http_fp = self.http_fingerprinter.fingerprint(host, port)
                result.http_fingerprint = http_fp
                
                # If HTTP fingerprinting found good data, use it
                if http_fp.device_type or http_fp.firmware_version:
                    result.raw_banner = http_fp.raw_html[:500] if http_fp.raw_html else ""
                    result.parsed_name = http_fp.device_type or ""
                    
                    # Build version string from firmware + hardware info
                    version_parts = []
                    if http_fp.firmware_version:
                        version_parts.append(f"Firmware: {http_fp.firmware_version}")
                    if http_fp.hardware_version:
                        version_parts.append(f"HW: {http_fp.hardware_version}")
                    if http_fp.model:
                        version_parts.insert(0, http_fp.model)
                    
                    result.parsed_version = " ".join(version_parts)
                    
                    logger.debug(f"HTTP fingerprint from {host}:{port}: "
                               f"{http_fp.device_type} {http_fp.model} {http_fp.firmware_version}")
                    return result
            except Exception as e:
                logger.debug(f"HTTP fingerprinting failed for {host}:{port}: {e}")
        
        # Fall back to socket banner grabbing
        sock = None
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Connect
            sock.connect((host, port))
            
            # Wrap with SSL if needed
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            
            # Determine probe to send
            probe = self._get_probe(port)
            if probe:
                sock.send(probe)
            
            # Receive response
            banner_bytes = sock.recv(1024)
            
            # Decode with error handling
            result.raw_banner = self._decode_banner(banner_bytes)
            
            # Parse banner for product/version
            result.parsed_name, result.parsed_version = self._parse_banner(
                result.raw_banner, port
            )
            
            logger.debug(f"Banner grabbed from {host}:{port}: "
                        f"{result.parsed_name} {result.parsed_version}")
            
        except socket.timeout:
            result.error = "Connection timeout"
            logger.debug(f"Timeout grabbing banner from {host}:{port}")
        except ConnectionRefusedError:
            result.error = "Connection refused"
            logger.debug(f"Connection refused to {host}:{port}")
        except socket.gaierror as e:
            result.error = f"Address error: {e}"
            logger.debug(f"Address error for {host}:{port}: {e}")
        except ssl.SSLError as e:
            result.error = f"SSL error: {e}"
            logger.debug(f"SSL error for {host}:{port}: {e}")
        except UnicodeDecodeError:
            # Binary data - store as hex representation
            result.raw_banner = banner_bytes.hex()[:200]
            result.error = "Binary data"
            logger.debug(f"Binary banner from {host}:{port}")
        except Exception as e:
            result.error = str(e)
            logger.debug(f"Error grabbing banner from {host}:{port}: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
        
        return result
    
    def grab_banners(
        self, 
        host: str, 
        ports: List[int]
    ) -> Dict[int, BannerResult]:
        """Grab banners from multiple ports concurrently.
        
        Uses ThreadPoolExecutor for concurrent connections.
        
        Args:
            host: Target IP address
            ports: List of port numbers to scan
            
        Returns:
            Dictionary mapping port numbers to BannerResult
        """
        results: Dict[int, BannerResult] = {}
        
        if not ports:
            return results
        
        logger.info(f"Grabbing banners from {host}:{ports}")
        
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(ports))) as executor:
            # Submit all tasks
            future_to_port = {
                executor.submit(self.grab_banner, host, port): port 
                for port in ports
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    results[port] = result
                except Exception as e:
                    logger.error(f"Exception grabbing banner from {host}:{port}: {e}")
                    results[port] = BannerResult(
                        host=host, 
                        port=port, 
                        error=str(e)
                    )
        
        return results
    
    def _get_probe(self, port: int) -> bytes:
        """Get appropriate probe for a port.
        
        Args:
            port: Port number
            
        Returns:
            Probe bytes to send
        """
        # Map common ports to probes
        port_probes = {
            21: self.PROBES['ftp'],
            22: self.PROBES['ssh'],
            23: self.PROBES['telnet'],
            25: self.PROBES['smtp'],
            80: self.PROBES['http'],
            443: self.PROBES['http'],
            587: self.PROBES['smtp'],
            8080: self.PROBES['http'],
            8443: self.PROBES['http'],
        }
        return port_probes.get(port, self.PROBES['generic'])
    
    def _decode_banner(self, banner_bytes: bytes) -> str:
        """Decode banner bytes to string with error handling.
        
        Tries multiple encodings and handles binary data gracefully.
        
        Args:
            banner_bytes: Raw bytes from socket
            
        Returns:
            Decoded string (may be truncated)
        """
        encodings = ['utf-8', 'ascii', 'latin-1', 'cp1252']
        
        for encoding in encodings:
            try:
                decoded = banner_bytes.decode(encoding, errors='strict')
                # Clean up control characters except common ones
                cleaned = ''.join(
                    c if c.isprintable() or c in '\r\n\t' else '.'
                    for c in decoded
                )
                return cleaned[:500]  # Limit length
            except UnicodeDecodeError:
                continue
        
        # Fallback: hex representation for binary data
        return banner_bytes.hex()[:200]
    
    def _parse_banner(self, banner: str, port: int) -> Tuple[str, str]:
        """Parse product name and version from banner.
        
        Args:
            banner: Raw banner string
            port: Port number (for context)
            
        Returns:
            Tuple of (product_name, version)
        """
        banner_lower = banner.lower()
        
        # SSH parsing
        if 'ssh' in banner_lower:
            parts = banner.split()
            for i, part in enumerate(parts):
                if 'ssh' in part.lower():
                    version = parts[i + 1] if i + 1 < len(parts) else ""
                    return ('openssh', version.strip())
            return ('openssh', '')
        
        # HTTP server parsing
        if 'server:' in banner_lower:
            lines = banner.split('\r\n')
            for line in lines:
                if line.lower().startswith('server:'):
                    server = line[7:].strip()
                    # Extract version from common formats
                    if '/' in server:
                        parts = server.split('/')
                        name = parts[0].strip().lower()
                        version = parts[1].split()[0] if len(parts) > 1 else ""
                        return (name, version)
                    return (server.lower(), '')
        
        # FTP parsing
        if port == 21 or 'ftp' in banner_lower:
            if 'vsftpd' in banner_lower:
                parts = banner.split()
                for i, part in enumerate(parts):
                    if 'vsftpd' in part.lower():
                        return ('vsftpd', parts[i + 1] if i + 1 < len(parts) else "")
                return ('vsftpd', '')
            if 'proftpd' in banner_lower:
                return ('proftpd', '')
            return ('ftp', '')
        
        # MySQL parsing
        if 'mysql' in banner_lower:
            parts = banner.split()
            for part in parts:
                if '.' in part and any(c.isdigit() for c in part):
                    return ('mysql', part.strip())
            return ('mysql', '')
        
        # PostgreSQL parsing
        if 'postgresql' in banner_lower:
            parts = banner.split()
            for part in parts:
                if '.' in part and part[0].isdigit():
                    return ('postgresql', part.strip())
            return ('postgresql', '')
        
        # Generic version detection
        import re
        version_pattern = r'(\w+)[/\s-]+(\d+\.\d+(?:\.\d+)?)'
        match = re.search(version_pattern, banner)
        if match:
            return (match.group(1).lower(), match.group(2))
        
        return ('', '')
