"""
NetWatch Product Mapping Module.

This module maps common detected software names and service banners to their
corresponding endoflife.date API slugs. This allows the EOL checker to
query the correct API endpoint for each detected product.

Exports:
    get_product_slug: Map a detected software name to endoflife.date slug
    PRODUCT_MAP: Dictionary of software name mappings
    NOT_TRACKED_PRODUCTS: Set of slugs confirmed absent from endoflife.date
    normalize_software_name: Normalize software name for matching

Example:
    from eol.product_map import get_product_slug
    slug = get_product_slug("OpenSSH_8.2")
    # Returns: "openssh"
"""

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# Products confirmed NOT tracked by endoflife.date (API returns 404).
# Returning "N/A" for these avoids false UNKNOWN counts.
NOT_TRACKED_PRODUCTS = {
    "openssh",
    "libssh",
    "dropbear",
    "putty",
    "lighttpd",
    "vsftpd",
    "proftpd",
    "pure-ftpd",
    "filezilla-server",
    "bind",
    "powerdns",
    "samba",
    "squid",
    "haproxy",
    "varnish",
    "memcached",
    "nagios",
    "sendmail",
    "activemq",
    "arch-linux",
    "netbsd",
    "openbsd",
    "oracle-linux",
    "linksys",
    "netgear",
    "d-link",
    "ubiquiti",
    "mikrotik",
    "tplink",
    "asus",
}

# Mapping of detected software names/banners to endoflife.date slugs
# Keys should be lowercase for case-insensitive matching
PRODUCT_MAP = {
    # SSH Daemons
    "openssh": "openssh",
    "ssh": "openssh",
    "libssh": "libssh",
    "dropbear": "dropbear",
    "putty": "putty",
    
    # Web Servers
    "apache": "apache-http-server",
    "apache http server": "apache-http-server",
    "apache httpd": "apache-http-server",
    "httpd": "apache-http-server",
    "nginx": "nginx",
    "iis": "iis",
    "microsoft-iis": "iis",
    "lighttpd": "lighttpd",
    "caddy": "caddy",
    "tomcat": "tomcat",
    "apache tomcat": "tomcat",
    
    # Databases
    "mysql": "mysql",
    "mariadb": "mariadb",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "mongodb": "mongodb",
    "redis": "redis",
    "elasticsearch": "elasticsearch",
    "couchdb": "couchdb",
    
    # Operating Systems - Linux
    "ubuntu": "ubuntu",
    "debian": "debian",
    "centos": "centos",
    "rhel": "rhel",
    "red hat": "rhel",
    "redhat": "rhel",
    "fedora": "fedora",
    "alpine": "alpine-linux",
    "alpine linux": "alpine-linux",
    "arch": "arch-linux",
    "arch linux": "arch-linux",
    "opensuse": "opensuse",
    "suse": "sles",
    "sles": "sles",
    "amazon linux": "amazon-linux",
    "oracle linux": "oracle-linux",
    
    # Operating Systems - Other
    "windows": "windows",
    "windows server": "windows-server",
    "freebsd": "freebsd",
    "openbsd": "openbsd",
    "netbsd": "netbsd",
    "macos": "macos",
    "mac os": "macos",
    "osx": "macos",
    
    # Programming Languages / Runtimes
    "python": "python",
    "php": "php",
    "nodejs": "nodejs",
    "node": "nodejs",
    "ruby": "ruby",
    "perl": "perl",
    "java": "oracle-jdk",
    "jdk": "oracle-jdk",
    "go": "go",
    "golang": "go",
    "rust": "rust",
    
    # Container/Orchestration
    "docker": "docker-engine",
    "kubernetes": "kubernetes",
    "k8s": "kubernetes",
    
    # Mail Servers
    "postfix": "postfix",
    "exim": "exim",
    "dovecot": "dovecot",
    "sendmail": "sendmail",
    
    # FTP Servers
    "vsftpd": "vsftpd",
    "proftpd": "proftpd",
    "pure-ftpd": "pure-ftpd",
    "filezilla": "filezilla-server",
    
    # DNS Servers
    "bind": "bind",
    "bind9": "bind",
    "powerdns": "powerdns",
    
    # VPN/Remote Access
    "openvpn": "openvpn",
    "wireguard": "wireguard",
    
    # Version Control
    "git": "git",
    "gitlab": "gitlab",
    "github enterprise": "github-enterprise-server",
    
    # Monitoring
    "nagios": "nagios",
    "zabbix": "zabbix",
    "prometheus": "prometheus",
    "grafana": "grafana",
    
    # Network Devices - Routers/Switches
    "cisco ios": "cisco-ios-xe",
    "cisco ios xe": "cisco-ios-xe",
    "cisco": "cisco-ios-xe",
    "junos": "junos",
    "pfsense": "pfsense",
    
    # TP-Link (many consumer routers don't have EOL pages, but we map them)
    "tp-link": "tplink",
    "tp link": "tplink",
    "tplink": "tplink",
    "tp-link re305": "tplink",
    "tp-link archer": "tplink",
    "tp-link tl": "tplink",
    "tp-link deco": "tplink",
    
    # ASUS Routers
    "asus": "asus",
    "asus router": "asus",
    "asuswrt": "asus",
    
    # Netgear
    "netgear": "netgear",
    
    # Linksys
    "linksys": "linksys",
    
    # D-Link
    "d-link": "d-link",
    "dlink": "d-link",
    
    # Ubiquiti
    "ubiquiti": "ubiquiti",
    "ubnt": "ubiquiti",
    "unifi": "ubiquiti",
    
    # MikroTik
    "mikrotik": "mikrotik",
    "routeros": "mikrotik",
    
    # Message Queue
    "rabbitmq": "rabbitmq",
    "kafka": "apache-kafka",
    "activemq": "activemq",
    
    # CMS
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    
    # Other Common Services
    "samba": "samba",
    "squid": "squid",
    "haproxy": "haproxy",
    "varnish": "varnish",
    "memcached": "memcached",
    "consul": "consul",
    "vault": "vault",
    "jenkins": "jenkins",
}


def normalize_software_name(name: str) -> str:
    """Normalize a software name for matching.
    
    Removes version numbers, converts to lowercase, and strips
    common suffixes/prefixes.
    
    Args:
        name: Raw software name from banner or service detection
        
    Returns:
        Normalized name suitable for lookup in PRODUCT_MAP
    """
    if not name:
        return ""
    
    # Convert to lowercase
    normalized = name.lower()
    
    # Remove common prefixes
    prefixes_to_remove = ['gnu/', 'the ', 'apache ']
    for prefix in prefixes_to_remove:
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):]
    
    # Remove version numbers (e.g., "nginx/1.18" -> "nginx")
    normalized = re.sub(r'[/\s-]\d+\.\d+.*$', '', normalized)
    
    # Remove common suffixes
    suffixes_to_remove = [
        ' server', ' daemon', ' service', ' software',
        '.exe', '.bin', '_service'
    ]
    for suffix in suffixes_to_remove:
        if normalized.endswith(suffix):
            normalized = normalized[:-len(suffix)]
    
    # Clean up whitespace
    normalized = normalized.strip()
    
    return normalized


def get_product_slug(software_name: str) -> Optional[str]:
    """Map a detected software name to endoflife.date slug.
    
    Args:
        software_name: Software name from banner or service detection
        
    Returns:
        endoflife.date API slug or None if no mapping exists
        
    Example:
        >>> get_product_slug("OpenSSH_8.2p1")
        'openssh'
        >>> get_product_slug("nginx/1.18.0")
        'nginx'
    """
    if not software_name:
        return None
    
    # Normalize the input name
    normalized = normalize_software_name(software_name)
    
    # Direct lookup
    if normalized in PRODUCT_MAP:
        logger.debug(f"Found direct mapping: '{normalized}' -> '{PRODUCT_MAP[normalized]}'")
        return PRODUCT_MAP[normalized]
    
    # Try to extract base name from compound strings
    # e.g., "OpenSSH_8.2" -> "openssh"
    base_match = re.match(r'^([a-z]+)', normalized)
    if base_match:
        base = base_match.group(1)
        if base in PRODUCT_MAP:
            logger.debug(f"Found base mapping: '{software_name}' -> '{base}' -> '{PRODUCT_MAP[base]}'")
            return PRODUCT_MAP[base]
    
    # Try partial matching for compound names
    for key, slug in PRODUCT_MAP.items():
        if key in normalized or normalized in key:
            logger.debug(f"Found partial match: '{software_name}' -> '{key}' -> '{slug}'")
            return slug
    
    logger.debug(f"No mapping found for: '{software_name}' (normalized: '{normalized}')")
    return None


def list_supported_products() -> dict:
    """List all supported products and their slugs.
    
    Returns:
        Dictionary mapping categories to product lists
    """
    categories = {
        "SSH Daemons": ["openssh", "libssh", "dropbear", "putty"],
        "Web Servers": ["apache-http-server", "nginx", "iis", "lighttpd", "caddy", "tomcat"],
        "Databases": ["mysql", "mariadb", "postgresql", "mongodb", "redis", "elasticsearch"],
        "Operating Systems": ["ubuntu", "debian", "centos", "redhat-enterprise-linux", 
                             "fedora", "windows", "freebsd"],
        "Programming Languages": ["python", "php", "nodejs", "ruby", "java", "go"],
        "Mail Servers": ["postfix", "exim", "dovecot"],
        "DNS Servers": ["bind", "powerdns"],
        "VPN": ["openvpn", "wireguard"],
        "Container": ["docker-engine", "kubernetes"],
    }
    return categories


def is_supported(software_name: str) -> bool:
    """Check if a software product is supported by endoflife.date.
    
    Args:
        software_name: Software name to check
        
    Returns:
        True if product has EOL data available
    """
    return get_product_slug(software_name) is not None
