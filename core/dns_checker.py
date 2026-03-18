"""
NetWatch DNS Security Checker.

Checks for DNS hijacking/interception by comparing local DNS resolution
against a trusted public resolver (Cloudflare 1.1.1.1).

All checks are read-only. No packets are sent to scanned devices.

Checks performed:
    1. DNS hijack detection: resolve a known hostname via local DNS and
       compare against resolution via 1.1.1.1. Mismatch = potential hijack.
    2. DNS rebinding risk: check if the local DNS resolver returns
       private RFC 1918 addresses for public hostnames.

Findings produced:
    CRITICAL - DNS responses differ significantly from trusted resolver
               (possible DNS hijacking or MitM)
    MEDIUM   - DNS rebinding: private IP returned for a public hostname
    INFO     - DNS resolver information
"""

import logging
import socket
import struct
from typing import Dict, List, Optional, Tuple

from core.findings import Finding, Severity

logger = logging.getLogger(__name__)

# Authoritative IPs for test hostnames (stable, well-known)
# We use multiple to reduce false positives from CDN geo-routing.
TEST_HOSTNAME = "example.com"

# Trusted resolver for comparison
TRUSTED_RESOLVER_IP = "1.1.1.1"  # Cloudflare
TRUSTED_RESOLVER_PORT = 53

# RFC 1918 private ranges (for rebinding detection)
PRIVATE_RANGES = [
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"),
    ("127.0.0.0", "127.255.255.255"),
    ("169.254.0.0", "169.254.255.255"),
]

DNS_QUERY_TIMEOUT = 3.0


def _ip_to_int(ip: str) -> int:
    """Convert dotted IPv4 string to integer."""
    parts = ip.split(".")
    return (int(parts[0]) << 24 | int(parts[1]) << 16 |
            int(parts[2]) << 8 | int(parts[3]))


def _is_private_ip(ip: str) -> bool:
    """Return True if the IP is in a private/RFC1918 range."""
    try:
        ip_int = _ip_to_int(ip)
        for start, end in PRIVATE_RANGES:
            if _ip_to_int(start) <= ip_int <= _ip_to_int(end):
                return True
    except (ValueError, IndexError):
        pass
    return False


def _build_dns_query(hostname: str, query_id: int = 0x1234) -> bytes:
    """Build a minimal DNS A-record query packet."""
    # Header: ID, flags (standard query), questions=1, others=0
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)

    # QNAME: encode each label
    qname = b""
    for label in hostname.rstrip(".").split("."):
        encoded = label.encode("ascii")
        qname += bytes([len(encoded)]) + encoded
    qname += b"\x00"  # Root label

    # QTYPE=A (1), QCLASS=IN (1)
    question = qname + struct.pack(">HH", 1, 1)
    return header + question


def _parse_dns_response_ips(data: bytes, query_id: int = 0x1234) -> List[str]:
    """Extract A-record IP addresses from a raw DNS response packet.

    Very minimal parser — only handles simple, non-compressed responses.
    Returns empty list on parse errors.
    """
    ips: List[str] = []
    try:
        if len(data) < 12:
            return ips
        resp_id = struct.unpack(">H", data[:2])[0]
        if resp_id != query_id:
            return ips
        ancount = struct.unpack(">H", data[6:8])[0]
        if ancount == 0:
            return ips

        # Skip past the question section
        offset = 12
        # Skip QNAME
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            elif length & 0xC0 == 0xC0:  # Pointer
                offset += 2
                break
            offset += length + 1
        offset += 4  # Skip QTYPE + QCLASS

        # Parse answer records
        for _ in range(ancount):
            if offset >= len(data):
                break
            # Skip NAME (could be pointer or label)
            if data[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while offset < len(data) and data[offset] != 0:
                    offset += data[offset] + 1
                offset += 1
            if offset + 10 > len(data):
                break
            rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            if rtype == 1 and rdlength == 4:  # A record
                ip = ".".join(str(b) for b in data[offset:offset + 4])
                ips.append(ip)
            offset += rdlength

    except (struct.error, IndexError, ValueError):
        pass
    return ips


def _query_dns_udp(
    hostname: str,
    resolver_ip: str,
    port: int = 53,
    timeout: float = DNS_QUERY_TIMEOUT,
    query_id: int = 0x1234,
) -> List[str]:
    """Send a UDP DNS A query to resolver_ip:port and return resolved IPs.

    Returns empty list on timeout or any error.
    """
    packet = _build_dns_query(hostname, query_id=query_id)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (resolver_ip, port))
        response, _ = sock.recvfrom(512)
        sock.close()
        return _parse_dns_response_ips(response, query_id=query_id)
    except (socket.timeout, socket.error, OSError) as e:
        logger.debug(f"DNS UDP query to {resolver_ip}:{port} for {hostname} failed: {e}")
        return []


def _get_local_resolver() -> Optional[str]:
    """Attempt to determine the local DNS resolver IP.

    Uses a dummy UDP connection to detect which interface the OS routes to 8.8.8.8,
    which is usually the same interface used for DNS. Falls back to None.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
        sock.close()
        return local_ip
    except Exception:
        return None


def _resolve_via_system(hostname: str) -> List[str]:
    """Resolve a hostname using the OS/system resolver (getaddrinfo)."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_INET)
        return list(set(r[4][0] for r in results))
    except socket.gaierror as e:
        logger.debug(f"System DNS resolution failed for {hostname}: {e}")
        return []


def run_dns_checks(local_network: str = "") -> List[Finding]:
    """Perform DNS hijack and rebinding checks.

    Args:
        local_network: Local network CIDR (informational, e.g. "192.168.1.0/24").

    Returns:
        List of Finding objects.
    """
    findings: List[Finding] = []

    # ---- Step 1: Resolve test hostname via system DNS ----
    system_ips = _resolve_via_system(TEST_HOSTNAME)
    if not system_ips:
        # Can't resolve at all — offline or DNS broken
        findings.append(Finding(
            severity=Severity.INFO,
            title="DNS resolution failed — possibly offline",
            host="local",
            port=53,
            protocol="udp",
            category="DNS Security",
            description=(
                f"Could not resolve {TEST_HOSTNAME!r} using the system DNS resolver. "
                "The system may be offline, or DNS may be blocked."
            ),
            explanation=(
                "NetWatch could not reach the DNS resolver to perform hijack checks. "
                "This is normal if the machine running NetWatch has no internet access."
            ),
            recommendation="Check internet connectivity. Run --update-cache when online.",
            tags=["dns", "offline"],
        ))
        return findings

    # ---- Step 2: Resolve via Cloudflare (trusted) ----
    trusted_ips = _query_dns_udp(TEST_HOSTNAME, TRUSTED_RESOLVER_IP, query_id=0x4E57)

    if not trusted_ips:
        # Could not reach Cloudflare — might be offline or blocked
        findings.append(Finding(
            severity=Severity.INFO,
            title="Could not reach trusted DNS resolver (1.1.1.1) for comparison",
            host="local",
            port=53,
            protocol="udp",
            category="DNS Security",
            description=(
                "NetWatch could not query Cloudflare (1.1.1.1) to compare DNS responses. "
                "DNS hijack detection requires internet access."
            ),
            explanation="DNS comparison checks are skipped when the trusted resolver is unreachable.",
            recommendation="Ensure port 53 UDP to 1.1.1.1 is not blocked by a firewall.",
            tags=["dns", "info"],
        ))
        return findings

    # ---- Step 3: Compare results ----
    # Use /16 prefix comparison to handle CDN geo-routing differences
    def _prefix_16(ip: str) -> str:
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}" if len(parts) >= 2 else ip

    system_prefixes = set(_prefix_16(ip) for ip in system_ips)
    trusted_prefixes = set(_prefix_16(ip) for ip in trusted_ips)

    mismatch = not system_prefixes.intersection(trusted_prefixes)

    # Also check for private IP in system response (DNS rebinding)
    private_in_system = [ip for ip in system_ips if _is_private_ip(ip)]

    if mismatch and not private_in_system:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            title="Possible DNS hijacking detected",
            host="local",
            port=53,
            protocol="udp",
            category="DNS Security",
            description=(
                f"DNS responses differ between your local resolver and Cloudflare (1.1.1.1). "
                f"Your resolver returned: {', '.join(system_ips)} for {TEST_HOSTNAME!r}. "
                f"Cloudflare returned: {', '.join(trusted_ips)}."
            ),
            explanation=(
                "Your network's DNS server is returning different IP addresses for public "
                "websites compared to a trusted, independent resolver. This could mean:\n"
                "  - Your router has been compromised and is redirecting traffic.\n"
                "  - Your ISP is intercepting DNS queries (DNS hijacking).\n"
                "  - A network-level ad blocker or parental control is active (less concerning).\n\n"
                "If you don't have any ad blocker or parental control active, this is a "
                "serious concern and your router should be checked immediately."
            ),
            recommendation=(
                "1. Check your router's DNS settings — they should point to your ISP "
                "or a known resolver like 1.1.1.1 or 8.8.8.8.\n"
                "2. Log into your router admin panel and look for any DNS settings that "
                "seem unfamiliar.\n"
                "3. If your router was recently rebooted or updated, this may have "
                "reset to defaults — re-check DNS settings.\n"
                "4. Run a factory reset on your router if you suspect compromise.\n"
                "5. Contact your ISP if the issue persists."
            ),
            evidence=(
                f"System DNS: {', '.join(system_ips)} | "
                f"Cloudflare 1.1.1.1: {', '.join(trusted_ips)}"
            ),
            tags=["dns", "hijacking", "critical"],
        ))
    elif private_in_system:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title="DNS rebinding risk: private IP returned for public hostname",
            host="local",
            port=53,
            protocol="udp",
            category="DNS Security",
            description=(
                f"Your DNS resolver returned private IP address(es) {', '.join(private_in_system)} "
                f"for the public hostname {TEST_HOSTNAME!r}."
            ),
            explanation=(
                "DNS rebinding is an attack where a malicious DNS server returns a "
                "private (LAN) IP address for a public hostname. This can be used to "
                "make your browser attack other devices on your local network. "
                "This may also indicate a misconfigured local DNS server."
            ),
            recommendation=(
                "1. Check your router DNS settings.\n"
                "2. Ensure your DNS resolver does not return private IPs for public names.\n"
                "3. Enable DNS rebinding protection in your router if available."
            ),
            evidence=f"Private IPs in DNS response: {', '.join(private_in_system)}",
            tags=["dns", "rebinding"],
        ))
    else:
        # All looks good
        findings.append(Finding(
            severity=Severity.INFO,
            title="DNS responses match trusted resolver — no hijacking detected",
            host="local",
            port=53,
            protocol="udp",
            category="DNS Security",
            description=(
                f"DNS resolution for {TEST_HOSTNAME!r} matches between local resolver "
                f"({', '.join(system_ips)}) and Cloudflare 1.1.1.1 ({', '.join(trusted_ips)})."
            ),
            explanation=(
                "Your network's DNS responses match a trusted independent resolver. "
                "No signs of DNS hijacking were detected."
            ),
            recommendation="No action required.",
            tags=["dns", "ok"],
        ))

    return findings
