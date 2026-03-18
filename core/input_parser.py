"""
NetWatch Input Parser Module.

This module parses various IP address and range formats into
nmap-compatible target specifications.

Supports:
- CIDR notation: 192.168.1.0/24
- Wildcards: 192.168.1.*
- Ranges: 192.168.1.1-100
- Lists: 192.168.1.1,5,10
- Mixed: 192.168.1.1-50,100,200-250
- Hostnames: router.local

Exports:
    parse_target_input: Main function to parse target strings
    expand_wildcard: Expand wildcard patterns
    validate_target: Validate if target is valid

Example:
    from core.input_parser import parse_target_input
    targets = parse_target_input("192.168.1.*")
    # Returns: ["192.168.1.0/24"]
"""

import logging
import re
import ipaddress
from typing import List, Tuple, Optional

logger = logging.getLogger(__name__)


def parse_target_input(target_str: str) -> List[str]:
    """Parse a target input string into nmap-compatible format.
    
    Handles various formats:
    - 192.168.1.0/24 (CIDR)
    - 192.168.1.* (wildcard)
    - 192.168.1.1-100 (range)
    - 192.168.1.1,5,10 (list)
    - 192.168.1.1-50,100 (mixed)
    
    Args:
        target_str: User input string for targets
        
    Returns:
        List of nmap-compatible target specifications
        
    Example:
        >>> parse_target_input("192.168.1.*")
        ['192.168.1.0/24']
        >>> parse_target_input("192.168.1.1-10,50")
        ['192.168.1.1-10', '192.168.1.50']
    """
    if not target_str or not target_str.strip():
        return []
    
    target_str = target_str.strip()
    
    # Check if it's a hostname (contains letters and not an IP pattern)
    if _is_hostname(target_str):
        return [target_str]
    
    # Check if it's already CIDR
    if "/" in target_str:
        try:
            ipaddress.ip_network(target_str, strict=False)
            return [target_str]
        except ValueError:
            pass
    
    # Check for wildcards (*)
    if "*" in target_str:
        return expand_wildcard(target_str)
    
    # Check for ranges or lists in last octet
    if _has_range_or_list(target_str):
        return _parse_range_or_list(target_str)
    
    # Single IP
    try:
        ipaddress.ip_address(target_str)
        return [target_str]
    except ValueError:
        pass
    
    # Return as-is if we can't parse it (nmap might understand it)
    logger.warning(f"Could not parse target '{target_str}', passing to nmap as-is")
    return [target_str]


def _is_hostname(target: str) -> bool:
    """Check if target is a hostname rather than IP.
    
    Args:
        target: String to check
        
    Returns:
        True if it looks like a hostname
    """
    # If it contains letters and doesn't match IP patterns
    if re.search(r'[a-zA-Z]', target):
        # Check it's not a hex IP or something
        if not re.match(r'^[\d./,-]+$', target):
            return True
    return False


def _has_range_or_list(target: str) -> bool:
    """Check if target contains range (-) or list (,) notation.
    
    Args:
        target: String to check
        
    Returns:
        True if contains range or list
    """
    # Check last octet for - or ,
    parts = target.split(".")
    if len(parts) == 4:
        last_octet = parts[3]
        if "-" in last_octet or "," in last_octet:
            return True
    return False


def expand_wildcard(target: str) -> List[str]:
    """Expand wildcard patterns to CIDR notation.
    
    Args:
        target: Pattern like "192.168.1.*" or "192.168.*.*"
        
    Returns:
        List of CIDR notations
        
    Example:
        >>> expand_wildcard("192.168.1.*")
        ['192.168.1.0/24']
        >>> expand_wildcard("192.168.*.*")
        ['192.168.0.0/16']
    """
    if "*" not in target:
        return [target]
    
    # Count wildcards
    wildcard_count = target.count("*")
    
    # Replace wildcards with 0
    ip_with_zeros = target.replace("*", "0")
    
    # Determine prefix based on wildcard count
    if wildcard_count == 1:
        # 192.168.1.* -> /24
        return [f"{ip_with_zeros}/24"]
    elif wildcard_count == 2:
        # 192.168.*.* -> /16
        return [f"{ip_with_zeros}/16"]
    elif wildcard_count == 3:
        # 192.*.*.* -> /8
        return [f"{ip_with_zeros}/8"]
    else:
        logger.error(f"Invalid wildcard pattern: {target}")
        return []


def _parse_range_or_list(target: str) -> List[str]:
    """Parse range or list notation in last octet.
    
    Args:
        target: String like "192.168.1.1-100" or "192.168.1.1,5,10"
        
    Returns:
        List of nmap target strings
        
    Example:
        >>> _parse_range_or_list("192.168.1.1-10")
        ['192.168.1.1-10']
        >>> _parse_range_or_list("192.168.1.1,5,10")
        ['192.168.1.1', '192.168.1.5', '192.168.1.10']
    """
    parts = target.split(".")
    if len(parts) != 4:
        return [target]
    
    base = ".".join(parts[:3]) + "."
    last_octet = parts[3]
    
    results = []
    
    # Handle comma-separated list
    if "," in last_octet:
        items = last_octet.split(",")
        for item in items:
            item = item.strip()
            if "-" in item:
                # Range within list: 1-10
                results.append(f"{base}{item}")
            else:
                # Single IP
                results.append(f"{base}{item}")
    elif "-" in last_octet:
        # Simple range: 1-100
        results.append(target)
    else:
        results.append(target)
    
    return results


def validate_target(target: str) -> Tuple[bool, Optional[str]]:
    """Validate if a target specification is valid.
    
    Args:
        target: Target string to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not target:
        return False, "Empty target"
    
    # Try as IP address
    try:
        ipaddress.ip_address(target)
        return True, None
    except ValueError:
        pass
    
    # Try as network
    try:
        ipaddress.ip_network(target, strict=False)
        return True, None
    except ValueError:
        pass
    
    # Check for valid hostname format
    if _is_hostname(target):
        if re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]$', target):
            return True, None
        return False, "Invalid hostname format"
    
    # Check for range/list format
    if _has_range_or_list(target):
        parts = target.split(".")
        if len(parts) == 4:
            # Validate first three octets are numeric
            for i in range(3):
                try:
                    octet = int(parts[i])
                    if not 0 <= octet <= 255:
                        return False, f"Invalid octet: {parts[i]}"
                except ValueError:
                    return False, f"Non-numeric octet: {parts[i]}"
            return True, None
    
    # Wildcard check
    if "*" in target:
        parts = target.split(".")
        if len(parts) in [3, 4]:
            return True, None
    
    return False, f"Unrecognized target format: {target}"


def format_target_summary(targets: List[str]) -> str:
    """Create a human-readable summary of targets.
    
    Args:
        targets: List of target specifications
        
    Returns:
        Summary string
    """
    if not targets:
        return "No targets specified"
    
    if len(targets) == 1:
        target = targets[0]
        try:
            network = ipaddress.ip_network(target, strict=False)
            num_hosts = network.num_addresses - 2  # Subtract network and broadcast
            return f"{target} ({num_hosts} hosts)"
        except ValueError:
            return target
    
    # Multiple targets
    total_hosts = 0
    for target in targets:
        try:
            network = ipaddress.ip_network(target, strict=False)
            total_hosts += network.num_addresses - 2
        except ValueError:
            total_hosts += 1
    
    return f"{len(targets)} target ranges ({total_hosts}+ hosts)"


def get_local_subnet_suggestion() -> str:
    """Get suggested local subnet for scanning.
    
    Returns:
        Suggested subnet string
    """
    from core.network_utils import get_local_subnet
    
    subnet = get_local_subnet()
    if subnet:
        return subnet
    return "192.168.1.0/24"
