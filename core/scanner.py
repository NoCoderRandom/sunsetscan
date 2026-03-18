"""
NetWatch Network Scanner Module.

This module provides network scanning capabilities using the python-nmap library.
All scanning operations are performed through nmap.PortScanner() - no raw socket
scanning or subprocess calls to nmap are used.

Exports:
    NetworkScanner: Main scanner class with methods for different scan types
    ScanResult: Dataclass for structured scan results
    HostInfo: Dataclass for host information

Example:
    from core.scanner import NetworkScanner
    scanner = NetworkScanner()
    results = scanner.scan(target="192.168.1.0/24", profile="QUICK")
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime

import nmap

from config.settings import Settings, SCAN_PROFILES

logger = logging.getLogger(__name__)


@dataclass
class PortInfo:
    """Information about a single port/service.
    
    Attributes:
        port: Port number
        protocol: Protocol (tcp/udp)
        state: Port state (open/closed/filtered)
        service: Detected service name
        version: Detected version string
        banner: Raw banner from banner grabbing
        http_fingerprint: HTTP fingerprint data (for web services)
    """
    port: int
    protocol: str = "tcp"
    state: str = "unknown"
    service: str = "unknown"
    version: str = ""
    banner: str = ""
    http_fingerprint: Optional[Any] = None


@dataclass
class HostInfo:
    """Information about a scanned host.
    
    Attributes:
        ip: IP address
        hostname: Resolved hostname
        state: Host state (up/down)
        os_guess: Detected operating system
        os_accuracy: OS detection accuracy percentage
        ports: Dictionary of port info by port number
        mac: MAC address if available
        vendor: Device vendor from MAC OUI
    """
    ip: str
    hostname: str = ""
    state: str = "unknown"
    os_guess: str = ""
    os_accuracy: str = ""
    ports: Dict[int, PortInfo] = field(default_factory=dict)
    mac: str = ""
    vendor: str = ""


@dataclass
class ScanResult:
    """Complete result of a network scan.
    
    Attributes:
        target: Target that was scanned
        profile: Scan profile used
        start_time: When scan began
        end_time: When scan completed
        hosts: Dictionary of HostInfo by IP
        summary: Text summary from nmap
    """
    target: str
    profile: str
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    hosts: Dict[str, HostInfo] = field(default_factory=dict)
    summary: str = ""
    
    @property
    def duration(self) -> float:
        """Calculate scan duration in seconds."""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0


class NetworkScanner:
    """Network scanner using python-nmap library.
    
    This class wraps nmap.PortScanner() to provide a clean interface
    for various scan types. All scanning is done through python-nmap's
    scan() method with appropriate arguments.
    
    Attributes:
        nm: nmap.PortScanner instance
        settings: Settings configuration object
        _progress_callback: Optional callback for progress updates
        
    Example:
        scanner = NetworkScanner()
        scanner.set_progress_callback(lambda msg, pct: print(f"{msg}: {pct}%"))
        result = scanner.quick_scan("192.168.1.0/24")
    """
    
    def __init__(self, settings: Optional[Settings] = None):
        """Initialize the network scanner.
        
        Args:
            settings: Configuration settings. Uses defaults if not provided.
        """
        self.settings = settings or Settings()
        self.nm = nmap.PortScanner()
        self._progress_callback: Optional[Callable[[str, float], None]] = None
        logger.debug("NetworkScanner initialized")
    
    def set_progress_callback(self, callback: Callable[[str, float], None]) -> None:
        """Set a callback function for progress updates.
        
        Args:
            callback: Function accepting (message, percentage) arguments
        """
        self._progress_callback = callback
    
    def _update_progress(self, message: str, percentage: float) -> None:
        """Update progress via callback if set."""
        if self._progress_callback:
            try:
                self._progress_callback(message, percentage)
            except Exception as e:
                logger.warning(f"Progress callback failed: {e}")
    
    def scan(
        self, 
        target: str, 
        profile: str = "QUICK",
        arguments: Optional[str] = None
    ) -> ScanResult:
        """Perform a network scan.
        
        Args:
            target: Target IP, range, or CIDR (e.g., "192.168.1.0/24")
            profile: Scan profile name (QUICK, FULL, STEALTH, PING)
            arguments: Optional custom nmap arguments (overrides profile)
            
        Returns:
            ScanResult containing all scan data
            
        Raises:
            nmap.PortScannerError: If nmap scan fails
            ValueError: If invalid profile specified
        """
        result = ScanResult(target=target, profile=profile)
        result.start_time = datetime.now()
        
        # Determine arguments
        if arguments:
            scan_args = arguments
        elif profile in SCAN_PROFILES:
            scan_args = SCAN_PROFILES[profile]
        else:
            raise ValueError(f"Unknown scan profile: {profile}. "
                           f"Valid profiles: {list(SCAN_PROFILES.keys())}")
        
        logger.info(f"Starting {profile} scan on {target}")
        self._update_progress(f"Starting {profile} scan on {target}", 0.0)
        
        try:
            # Perform scan using python-nmap
            self.nm.scan(hosts=target, arguments=scan_args)
            
            # Check for scan errors
            if self.nm.scaninfo().get('error', []):
                for error in self.nm.scaninfo()['error']:
                    logger.warning(f"nmap scan error: {error}")
            
            # Parse results from nmap result dictionary
            self._parse_results(result)
            
            result.summary = self.nm.get_nmap_last_output()[:500]  # Truncated
            logger.info(f"Scan completed: {len(result.hosts)} hosts found")
            
        except nmap.PortScannerError as e:
            err_msg = str(e)
            # If a profile requires root (OS scan, SYN scan) and we don't
            # have it, retry with a downgraded argument string.
            if "root privileges" in err_msg or "requires root" in err_msg:
                logger.warning(f"Profile {profile} requires root — retrying without OS/SYN flags")
                fallback_args = self._strip_root_flags(scan_args)
                if fallback_args != scan_args:
                    try:
                        self.nm.scan(hosts=target, arguments=fallback_args)
                        self._parse_results(result)
                        result.summary = self.nm.get_nmap_last_output()[:500]
                        logger.info(f"Fallback scan completed: {len(result.hosts)} hosts found")
                        return result
                    except Exception as e2:
                        logger.error(f"Fallback scan also failed: {e2}")
                        raise e2
            logger.error(f"Nmap scan failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during scan: {e}")
            raise
        finally:
            result.end_time = datetime.now()
            self._update_progress("Scan complete", 100.0)
        
        return result
    
    @staticmethod
    def _strip_root_flags(args: str) -> str:
        """Remove nmap flags that require root privileges.

        -A implies -O -sV -sC --traceroute — all of which need root for -O.
        Replace -A with just -sV -sC (version + default scripts).
        Replace -sS (SYN scan) with -sT (connect scan).
        Remove -O and --osscan-guess entirely.
        """
        parts = args.split()
        out = []
        for p in parts:
            if p == '-A':
                out.extend(['-sV', '-sC'])
            elif p == '-O':
                continue
            elif p == '--osscan-guess':
                continue
            elif p == '-sS':
                out.append('-sT')
            else:
                out.append(p)
        # Deduplicate -sV if it was already present alongside -A
        seen = set()
        deduped = []
        for p in out:
            if p in seen and p in ('-sV', '-sC'):
                continue
            seen.add(p)
            deduped.append(p)
        return ' '.join(deduped)

    def _parse_results(self, result: ScanResult) -> None:
        """Parse nmap results into structured format.
        
        Args:
            result: ScanResult object to populate
        """
        all_hosts = self.nm.all_hosts()
        total_hosts = len(all_hosts)
        
        for idx, host in enumerate(all_hosts):
            # Ensure host is a string
            host = str(host)
            self._update_progress(
                f"Processing host {host}", 
                (idx / max(total_hosts, 1)) * 100
            )
            
            host_info = self._parse_host(host)
            result.hosts[host] = host_info
    
    def _parse_host(self, host: str) -> HostInfo:
        """Parse information for a single host.
        
        Args:
            host: IP address string
            
        Returns:
            HostInfo populated with scan data
        """
        # Ensure host is a string
        host = str(host)
        info = HostInfo(ip=host)
        
        # Basic host info from nmap dict
        # Use try/except instead of 'in' check to avoid type issues with python-nmap
        try:
            host_data = self.nm[host]
        except (KeyError, AssertionError):
            # Host not in results or type error
            return info
        
        if host_data:
            info.state = host_data.get('status', {}).get('state', 'unknown')
            info.hostname = host_data.get('hostnames', [{}])[0].get('name', '')
            
            # MAC address and vendor (if available)
            addresses = host_data.get('addresses', {})
            if 'mac' in addresses:
                info.mac = addresses['mac']
            if 'vendor' in host_data and info.mac in host_data['vendor']:
                info.vendor = host_data['vendor'][info.mac]
            
            # OS detection
            osmatch = host_data.get('osmatch', [])
            if osmatch:
                info.os_guess = osmatch[0].get('name', '')
                info.os_accuracy = osmatch[0].get('accuracy', '')
            
            # Port information
            for protocol in ['tcp', 'udp']:
                if protocol in host_data:
                    for port_num, port_data in host_data[protocol].items():
                        port_info = PortInfo(
                            port=int(port_num),
                            protocol=protocol,
                            state=port_data.get('state', 'unknown'),
                            service=port_data.get('name', 'unknown'),
                            version=port_data.get('version', ''),
                        )
                        # Combine version info if available
                        product = port_data.get('product', '')
                        if product:
                            port_info.service = product.lower()
                            if port_data.get('version'):
                                port_info.version = port_data.get('version')
                        
                        info.ports[int(port_num)] = port_info
        
        return info
    
    def quick_scan(self, target: str) -> ScanResult:
        """Perform a quick scan of common ports.
        
        Args:
            target: Target network or host
            
        Returns:
            ScanResult with discovered hosts and services
        """
        return self.scan(target, profile="QUICK")
    
    def full_scan(self, target: str) -> ScanResult:
        """Perform a comprehensive scan with OS detection.
        
        Args:
            target: Target network or host
            
        Returns:
            ScanResult with detailed host information
        """
        return self.scan(target, profile="FULL")
    
    def stealth_scan(self, target: str) -> ScanResult:
        """Perform a stealth SYN scan.
        
        Args:
            target: Target network or host
            
        Returns:
            ScanResult with discovered hosts
        """
        return self.scan(target, profile="STEALTH")
    
    def ping_sweep(self, target: str) -> List[str]:
        """Perform a ping sweep to discover live hosts.
        
        Args:
            target: Target network (e.g., "192.168.1.0/24")
            
        Returns:
            List of IP addresses that responded
        """
        result = self.scan(target, profile="PING")
        return [ip for ip, host in result.hosts.items() if host.state == 'up']
    
    def get_scan_stats(self) -> Dict[str, Any]:
        """Get statistics from the last scan.
        
        Returns:
            Dictionary with scan statistics
        """
        return {
            'command_line': self.nm.command_line() if hasattr(self.nm, 'command_line') else '',
            'scan_info': self.nm.scaninfo() if hasattr(self.nm, 'scaninfo') else {},
        }
