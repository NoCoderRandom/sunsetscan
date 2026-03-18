"""
NetWatch NSE (Nmap Scripting Engine) Scanner Module.

This module extends the basic nmap scanning with NSE scripts for
enhanced device identification, banner grabbing, and information gathering.

Exports:
    NSEScanner: Scanner that uses nmap NSE scripts
    NSEScriptResult: Results from NSE script execution

Example:
    from core.nse_scanner import NSEScanner
    scanner = NSEScanner()
    results = scanner.scan_with_scripts("192.168.1.115", scripts=["http-title", "banner"])
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime

import nmap

from config.settings import Settings

logger = logging.getLogger(__name__)


@dataclass
class NSEScriptResult:
    """Result from an NSE script execution.
    
    Attributes:
        script_name: Name of the NSE script
        port: Port number where script ran
        output: Raw script output
        structured_data: Parsed data from script
        error: Error message if script failed
    """
    script_name: str
    port: Optional[int]
    output: str = ""
    structured_data: Dict[str, Any] = field(default_factory=dict)
    error: str = ""


@dataclass 
class EnhancedHostInfo:
    """Enhanced host information with NSE script results.
    
    Attributes:
        ip: IP address
        hostname: Resolved hostname
        basic_info: Basic nmap scan results
        nse_results: Dictionary of NSE script results by script name
        os_guesses: List of OS guesses from various sources
        device_fingerprints: Combined device identification data
    """
    ip: str
    hostname: str = ""
    basic_info: Dict[str, Any] = field(default_factory=dict)
    nse_results: Dict[str, List[NSEScriptResult]] = field(default_factory=dict)
    os_guesses: List[str] = field(default_factory=list)
    device_fingerprints: Dict[str, str] = field(default_factory=dict)


class NSEScanner:
    """Scanner using nmap NSE scripts for enhanced detection.
    
    This scanner runs nmap with specific NSE scripts to gather
    detailed information about network devices.
    
    Attributes:
        nm: nmap.PortScanner instance
        settings: Settings configuration
        
    Example:
        scanner = NSEScanner()
        
        # Run specific scripts
        host_info = scanner.scan_host("192.168.1.115")
        
        # Get HTTP title if available
        if "http-title" in host_info.nse_results:
            print(host_info.nse_results["http-title"][0].output)
    """
    
    # NSE scripts useful for device identification
    DEVICE_DISCOVERY_SCRIPTS = {
        # HTTP/HTTPS scripts
        "http-title": "Gets the title of the web page",
        "http-server-header": "Extracts Server header from HTTP response",
        "http-headers": "Gets HTTP headers",
        "http-favicon": "Gets favicon and tries to identify device",
        "http-auth": "Checks for HTTP authentication",
        
        # Generic banner scripts
        "banner": "Grabs service banners",
        
        # SNMP scripts
        "snmp-sysdescr": "Gets system description via SNMP",
        "snmp-info": "Extracts SNMP information",
        
        # SMB/Windows scripts
        "smb-os-discovery": "Discovers OS info via SMB",
        "smb-security-mode": "Gets SMB security information",
        "nbstat": "Gets NetBIOS statistics",
        
        # UPnP/DLNA scripts
        "upnp-info": "Extracts UPnP information",
        "broadcast-upnp-info": "Discovers UPnP devices via broadcast",
        
        # SSH scripts
        "ssh-hostkey": "Gets SSH host key information",
        "ssh2-enum-algos": "Enumerates SSH algorithms",
        
        # Telnet scripts
        "telnet-encryption": "Checks Telnet encryption support",
        "telnet-ntlm-info": "Gets NTLM info from Telnet",
        
        # SSL/TLS scripts
        "ssl-cert": "Extracts SSL certificate information",
        "ssl-enum-ciphers": "Enumerates SSL ciphers",
        
        # Database scripts
        "mysql-info": "Gets MySQL server information",
        "pgsql-brute": "Tests PostgreSQL authentication (if enabled)",
        
        # Misc
        "mac-geolocation": "Geolocates based on MAC address",
        "ip-geolocation-geoplugin": "IP geolocation",
    }
    
    # Scripts safe to run by default (non-intrusive)
    SAFE_SCRIPTS = [
        "banner",
        "http-title",
        "http-server-header",
        "http-headers",
        "ssh-hostkey",
        "ssl-cert",
        "snmp-sysdescr",
        "smb-os-discovery",
        "upnp-info",
        "nbstat",
    ]
    
    def __init__(self, settings: Optional[Settings] = None):
        """Initialize NSE scanner.
        
        Args:
            settings: Configuration settings
        """
        self.settings = settings or Settings()
        self.nm = nmap.PortScanner()
        logger.debug("NSEScanner initialized")
    
    def scan_host(
        self, 
        host: str,
        ports: Optional[str] = None,
        scripts: Optional[List[str]] = None,
        run_safe_only: bool = True
    ) -> EnhancedHostInfo:
        """Scan a single host with NSE scripts.
        
        Args:
            host: Target IP address
            ports: Ports to scan (e.g., "22,80,443" or "1-1000")
            scripts: List of script names to run (None = default safe scripts)
            run_safe_only: Only run non-intrusive scripts
            
        Returns:
            EnhancedHostInfo with NSE script results
        """
        result = EnhancedHostInfo(ip=host)
        
        # Determine which scripts to run
        if scripts is None:
            scripts = self.SAFE_SCRIPTS if run_safe_only else list(self.DEVICE_DISCOVERY_SCRIPTS.keys())
        
        script_string = ",".join(scripts)
        port_string = ports if ports else "1-1000"
        
        logger.info(f"Running NSE scan on {host} with scripts: {script_string}")
        
        try:
            # Build nmap arguments
            args = f"-sV --script={script_string} -T4"
            
            self.nm.scan(hosts=host, ports=port_string, arguments=args)
            
            if host in self.nm.all_hosts():
                host_data = self.nm[host]
                result.hostname = host_data.get("hostnames", [{}])[0].get("name", "")
                result.basic_info = dict(host_data)
                
                # Extract NSE script results
                self._extract_nse_results(result, host_data)
                
                # Compile OS guesses from various sources
                self._compile_os_guesses(result, host_data)
                
        except nmap.PortScannerError as e:
            logger.error(f"NSE scan failed for {host}: {e}")
            result.basic_info["error"] = str(e)
        except Exception as e:
            logger.error(f"Unexpected error in NSE scan: {e}")
            result.basic_info["error"] = str(e)
        
        return result
    
    def _extract_nse_results(
        self, 
        result: EnhancedHostInfo, 
        host_data: Dict
    ) -> None:
        """Extract NSE script results from nmap host data.
        
        Args:
            result: EnhancedHostInfo to populate
            host_data: Raw nmap host data
        """
        # NSE scripts return data per protocol/port
        for proto in ["tcp", "udp"]:
            if proto not in host_data:
                continue
                
            for port_num, port_data in host_data[proto].items():
                # Check for script results
                if "script" in port_data:
                    for script_name, script_output in port_data["script"].items():
                        nse_result = NSEScriptResult(
                            script_name=script_name,
                            port=int(port_num),
                            output=str(script_output)
                        )
                        
                        # Parse structured data for known scripts
                        nse_result.structured_data = self._parse_script_output(
                            script_name, script_output
                        )
                        
                        # Add to results
                        if script_name not in result.nse_results:
                            result.nse_results[script_name] = []
                        result.nse_results[script_name].append(nse_result)
                        
                        logger.debug(f"NSE {script_name} on port {port_num}: {script_output[:50]}...")
    
    def _parse_script_output(
        self, 
        script_name: str, 
        output: Any
    ) -> Dict[str, Any]:
        """Parse NSE script output into structured data.
        
        Args:
            script_name: Name of the script
            output: Raw script output
            
        Returns:
            Dictionary of parsed data
        """
        data = {}
        output_str = str(output)
        
        if script_name == "http-title":
            data["title"] = output_str.strip()
            
        elif script_name == "http-server-header":
            data["server"] = output_str.strip()
            # Try to extract server and version
            parts = output_str.split("/")
            if len(parts) >= 2:
                data["server_name"] = parts[0].strip()
                data["server_version"] = parts[1].split()[0].strip()
                
        elif script_name == "banner":
            data["banner"] = output_str.strip()
            
        elif script_name == "ssh-hostkey":
            data["hostkey"] = output_str.strip()
            
        elif script_name == "ssl-cert":
            # Extract certificate fields
            if "Subject:" in output_str:
                for line in output_str.split("\n"):
                    if "commonName=" in line:
                        data["common_name"] = line.split("commonName=")[1].split("/")[0]
                    if "organizationName=" in line:
                        data["organization"] = line.split("organizationName=")[1].split("/")[0]
                        
        elif script_name == "snmp-sysdescr":
            data["system_description"] = output_str.strip()
            
        elif script_name == "smb-os-discovery":
            # Parse SMB OS discovery output
            for line in output_str.split("\n"):
                if ":" in line:
                    key, value = line.split(":", 1)
                    data[key.strip().lower().replace(" ", "_")] = value.strip()
                    
        elif script_name == "upnp-info":
            data["upnp_info"] = output_str.strip()
            
        return data
    
    def _compile_os_guesses(
        self, 
        result: EnhancedHostInfo, 
        host_data: Dict
    ) -> None:
        """Compile OS guesses from various sources.
        
        Args:
            result: EnhancedHostInfo to populate
            host_data: Raw nmap host data
        """
        guesses = []
        
        # From nmap OS detection
        if "osmatch" in host_data and host_data["osmatch"]:
            for match in host_data["osmatch"]:
                guesses.append(match.get("name", ""))
        
        # From SMB
        if "smb-os-discovery" in result.nse_results:
            for smb_result in result.nse_results["smb-os-discovery"]:
                if "os" in smb_result.structured_data:
                    guesses.append(f"SMB: {smb_result.structured_data['os']}")
        
        # From SNMP
        if "snmp-sysdescr" in result.nse_results:
            for snmp_result in result.nse_results["snmp-sysdescr"]:
                if snmp_result.output:
                    guesses.append(f"SNMP: {snmp_result.output[:50]}")
        
        result.os_guesses = list(set(g for g in guesses if g))
    
    def get_device_summary(self, host_info: EnhancedHostInfo) -> Dict[str, str]:
        """Generate a summary of device identification data.
        
        Args:
            host_info: Enhanced host information
            
        Returns:
            Dictionary with key device identifiers
        """
        summary = {
            "ip": host_info.ip,
            "hostname": host_info.hostname,
            "os": "",
            "device_type": "",
            "web_server": "",
            "http_title": "",
        }
        
        # Get OS from guesses
        if host_info.os_guesses:
            summary["os"] = host_info.os_guesses[0]
        
        # Get web server info
        if "http-server-header" in host_info.nse_results:
            header_result = host_info.nse_results["http-server-header"][0]
            summary["web_server"] = header_result.output.strip()
            if "server_name" in header_result.structured_data:
                summary["device_type"] = header_result.structured_data["server_name"]
        
        # Get HTTP title
        if "http-title" in host_info.nse_results:
            title = host_info.nse_results["http-title"][0].output.strip()
            summary["http_title"] = title
            # Try to extract device name from title
            if not summary["device_type"] and title:
                summary["device_type"] = title.split()[0] if title else ""
        
        return summary
