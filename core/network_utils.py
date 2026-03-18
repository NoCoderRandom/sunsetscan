"""
NetWatch Network Utilities Module.

This module provides helper functions for network operations including
subnet detection, CIDR validation, and IP address manipulation.

Exports:
    get_local_subnet: Detect the local network subnet
    validate_cidr: Validate a CIDR notation string
    expand_cidr: Expand a CIDR to list of IPs
    get_local_ip: Get the primary local IP address
    is_private_ip: Check if IP is in private range

Example:
    from core.network_utils import get_local_subnet, validate_cidr
    subnet = get_local_subnet()
    is_valid = validate_cidr("192.168.1.0/24")
"""

import logging
import ipaddress
import socket
from typing import List, Optional, Tuple
from urllib.request import urlopen
from urllib.error import URLError

logger = logging.getLogger(__name__)


def get_local_ip() -> Optional[str]:
    """Get the primary local IP address.
    
    Attempts to determine the local IP by connecting to an external
    host. Falls back to localhost if unable to determine.
    
    Returns:
        Local IP address string or None if undetermined
    """
    try:
        # Connect to external host to determine interface
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            return local_ip
    except Exception as e:
        logger.debug(f"Could not determine local IP via external connection: {e}")
    
    # Fallback: try to resolve hostname
    try:
        hostname = socket.gethostname()
        local_ip = socket.getaddrinfo(hostname, None, socket.AF_INET)[0][4][0]
        if local_ip != '127.0.0.1':
            return local_ip
    except Exception as e:
        logger.debug(f"Could not resolve hostname: {e}")
    
    return None


def get_local_subnet() -> Optional[str]:
    """Detect the local network subnet in CIDR notation.
    
    Determines the local IP and returns the corresponding /24 subnet.
    This is a best-effort detection and assumes a standard class C network.
    
    Returns:
        CIDR string like "192.168.1.0/24" or None if unable to determine
    """
    local_ip = get_local_ip()
    
    if not local_ip:
        logger.warning("Could not determine local IP, using default")
        return "192.168.1.0/24"
    
    try:
        # Create network address from IP (assume /24 subnet)
        ip_parts = local_ip.split('.')
        network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        
        # Validate it's a private network
        if is_private_ip(local_ip):
            logger.info(f"Detected local subnet: {network}")
            return network
        else:
            logger.warning(f"Local IP {local_ip} is not private, using default")
            return "192.168.1.0/24"
    except Exception as e:
        logger.error(f"Error calculating subnet: {e}")
        return "192.168.1.0/24"


def validate_cidr(cidr: str) -> Tuple[bool, Optional[str]]:
    """Validate a CIDR notation string.
    
    Args:
        cidr: CIDR string (e.g., "192.168.1.0/24")
        
    Returns:
        Tuple of (is_valid, error_message)
        - is_valid: True if valid CIDR
        - error_message: None if valid, error description if invalid
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        
        # Warn if network is too large
        num_addresses = network.num_addresses
        if num_addresses > 65536:
            return (False, f"Network too large ({num_addresses} addresses). "
                          f"Maximum is /16 (65536 addresses)")
        
        if num_addresses < 1:
            return (False, "Invalid network size")
        
        return (True, None)
    except ValueError as e:
        return (False, f"Invalid CIDR format: {e}")
    except Exception as e:
        return (False, f"Validation error: {e}")


def expand_cidr(cidr: str, limit: int = 256) -> List[str]:
    """Expand a CIDR notation to a list of IP addresses.
    
    Args:
        cidr: CIDR string (e.g., "192.168.1.0/24")
        limit: Maximum number of addresses to return
        
    Returns:
        List of IP address strings
        
    Raises:
        ValueError: If CIDR is invalid
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        addresses = []
        
        for i, host in enumerate(network.hosts()):
            if i >= limit:
                logger.warning(f"CIDR expansion limited to {limit} addresses")
                break
            addresses.append(str(host))
        
        return addresses
    except Exception as e:
        raise ValueError(f"Failed to expand CIDR: {e}")


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private (RFC 1918) range.
    
    Args:
        ip: IP address string
        
    Returns:
        True if IP is private, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def is_loopback_ip(ip: str) -> bool:
    """Check if an IP address is loopback.
    
    Args:
        ip: IP address string
        
    Returns:
        True if IP is loopback, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_loopback
    except ValueError:
        return False


def get_network_range(cidr: str) -> Tuple[str, str]:
    """Get the first and last IP of a CIDR range.
    
    Args:
        cidr: CIDR string
        
    Returns:
        Tuple of (first_ip, last_ip)
    """
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = list(network.hosts())
    if hosts:
        return (str(hosts[0]), str(hosts[-1]))
    return (str(network.network_address), str(network.broadcast_address))


def format_cidr_info(cidr: str) -> str:
    """Get formatted information about a CIDR range.
    
    Args:
        cidr: CIDR string
        
    Returns:
        Human-readable description of the network
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        first, last = get_network_range(cidr)
        return (f"Network: {cidr} | "
                f"Range: {first} - {last} | "
                f"Hosts: {network.num_addresses - 2}")
    except Exception as e:
        return f"Invalid network: {e}"


def sanitize_target(target: str) -> str:
    """Sanitize and normalize a target specification.
    
    Handles various input formats and normalizes them.
    
    Args:
        target: Target string (IP, range, CIDR, hostname)
        
    Returns:
        Normalized target string
    """
    target = target.strip()
    
    # Check if it's already a valid CIDR
    is_valid, _ = validate_cidr(target)
    if is_valid:
        return target
    
    # Check if it's a single IP
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    
    # Check for IP range format (e.g., 192.168.1.1-254)
    if '-' in target and target.replace('-', '').replace('.', '').isdigit():
        parts = target.split('-')
        if len(parts) == 2:
            base = parts[0].rsplit('.', 1)[0]
            return f"{base}.{parts[0].split('.')[-1]}-{parts[1]}"
    
    # Return as-is for hostnames or other formats
    return target


def estimate_scan_time(cidr: str, profile: str) -> str:
    """Estimate scan time based on network size and profile.
    
    Args:
        cidr: Target CIDR
        profile: Scan profile name
        
    Returns:
        Human-readable time estimate
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        num_hosts = min(network.num_addresses, 256)
        
        # Rough estimates per profile
        times_per_host = {
            'QUICK': 0.5,
            'FULL': 3.0,
            'STEALTH': 5.0,
            'PING': 0.1,
        }
        
        seconds = num_hosts * times_per_host.get(profile, 1.0)
        
        if seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f} minutes"
        else:
            hours = seconds / 3600
            return f"{hours:.1f} hours"
    except:
        return "unknown"
