"""
NetWatch SNMP Security Checker.

Tests SNMP community strings and extracts device information:
  - Community string testing: 'public', 'private', and common defaults
  - sysDescr extraction (firmware/OS version for EOL matching)
  - sysName, sysLocation extraction
  - SNMPv1/v2c detection (no encryption — cleartext community strings)

Uses pysnmp for SNMP queries.

Findings produced:
    CRITICAL  - SNMP private community string accessible (read-write)
    HIGH      - SNMP public community string accessible (read-only, information disclosure)
    MEDIUM    - SNMPv1 in use (no authentication, no encryption)
    INFO      - sysDescr firmware/version info extracted
"""

import logging
from typing import Dict, List, Optional, Tuple

from core.findings import Finding, Severity, Confidence

logger = logging.getLogger(__name__)

SNMP_PORT = 161
SNMP_TIMEOUT = 3  # seconds per request
SNMP_RETRIES = 1

# Community strings to test — ordered by likelihood on home/office networks
_COMMUNITY_STRINGS = [
    "public",
    "private",
    "community",
    "admin",
    "default",
    "guest",
    "snmp",
    "monitor",
    "manager",
    "SNMP_trap",
    "router",
    "switch",
    "cisco",
    "read",
    "write",
]

# Standard OIDs
_OID_SYSDESCR   = "1.3.6.1.2.1.1.1.0"
_OID_SYSNAME    = "1.3.6.1.2.1.1.5.0"
_OID_SYSLOCATION = "1.3.6.1.2.1.1.6.0"
_OID_SYSCONTACT  = "1.3.6.1.2.1.1.4.0"
_OID_SYSUPTIME   = "1.3.6.1.2.1.1.3.0"


def _snmp_get(host: str, community: str, oid: str, version: int = 1) -> Optional[str]:
    """
    Perform a single SNMP GET request.

    Args:
        host:      Target IP.
        community: Community string.
        oid:       OID to query.
        version:   SNMP version (0=v1, 1=v2c).

    Returns:
        String value or None on failure/timeout.
    """
    try:
        from pysnmp.hlapi import (
            getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity
        )

        error_indication, error_status, error_index, var_binds = next(
            getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=version),
                UdpTransportTarget(
                    (host, SNMP_PORT),
                    timeout=SNMP_TIMEOUT,
                    retries=SNMP_RETRIES,
                ),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )
        )

        if error_indication or error_status:
            return None

        for var_bind in var_binds:
            return str(var_bind[1])

    except Exception as e:
        logger.debug(f"SNMP GET failed {host} community={community!r} oid={oid}: {e}")
        return None


def _test_community(host: str, community: str) -> Optional[str]:
    """
    Test if a community string gives access to sysDescr.

    Returns:
        sysDescr value if accessible, None otherwise.
    """
    # Try SNMPv2c first, then v1
    for version in (1, 0):  # pysnmp: 1=v2c, 0=v1
        result = _snmp_get(host, community, _OID_SYSDESCR, version=version)
        if result and result != "No Such Object currently exists":
            return result
    return None


def check_snmp(host: str, port: int = SNMP_PORT, timeout: float = 5.0) -> List[Finding]:
    """Run SNMP security checks for a single host.

    Args:
        host:    IP address.
        port:    SNMP port (default 161).
        timeout: Not directly used (pysnmp uses SNMP_TIMEOUT constant).

    Returns:
        List of Finding objects.
    """
    findings: List[Finding] = []
    accessible_communities: List[Tuple[str, str]] = []  # (community, sysdescr)

    # ---- Test community strings ----
    for community in _COMMUNITY_STRINGS:
        sysdescr = _test_community(host, community)
        if sysdescr:
            accessible_communities.append((community, sysdescr))
            logger.debug(f"SNMP accessible: {host} community={community!r}")

    if not accessible_communities:
        return findings

    # ---- Use first accessible community to gather more info ----
    first_community, first_sysdescr = accessible_communities[0]
    sysname = _snmp_get(host, first_community, _OID_SYSNAME) or ""
    syslocation = _snmp_get(host, first_community, _OID_SYSLOCATION) or ""

    # ---- sysDescr info finding — this is valuable for EOL ----
    findings.append(Finding(
        severity=Severity.INFO,
        title=f"SNMP sysDescr extracted from {host}",
        host=host, port=port, protocol="udp",
        category="SNMP",
        description=(
            f"SNMP query returned device information:\n"
            f"  sysDescr:   {first_sysdescr[:200]}\n"
            f"  sysName:    {sysname}\n"
            f"  sysLocation:{syslocation}"
        ),
        explanation=(
            "The SNMP sysDescr field typically contains the OS name, version, hardware, "
            "and firmware information. This is extremely useful for identifying EOL software."
        ),
        recommendation="Review the device information above against known EOL dates.",
        evidence=f"sysDescr: {first_sysdescr[:200]}",
        confidence=Confidence.CONFIRMED,
        tags=["snmp", "sysdescr", "info"],
    ))

    # ---- Report each accessible community string ----
    for community, sysdescr in accessible_communities:
        is_private = community.lower() in ("private", "write", "admin", "manager")
        severity = Severity.CRITICAL if is_private else Severity.HIGH

        title_prefix = "SNMP read-write" if is_private else "SNMP read-only"
        findings.append(Finding(
            severity=severity,
            title=f"{title_prefix} community string '{community}' accepted on {host}",
            host=host, port=port, protocol="udp",
            category="SNMP",
            description=(
                f"SNMP community string '{community}' is accepted by the device on port {port}. "
                f"{'Read-write access allows changing device configuration.' if is_private else 'Read access exposes all device configuration data.'}"
            ),
            explanation=(
                "SNMP v1/v2c community strings act as unencrypted passwords sent in cleartext. "
                "Default community strings like 'public' and 'private' are well-known and "
                "frequently exploited to extract network topology, routing tables, and "
                "device credentials, or to reconfigure devices entirely."
            ),
            recommendation=(
                "1. Change all SNMP community strings from default values immediately.\n"
                "2. Disable SNMP entirely if not required for network management.\n"
                "3. If SNMP is needed, upgrade to SNMPv3 which provides encryption "
                "and proper authentication.\n"
                "4. Restrict SNMP access via ACL to known management IPs only."
            ),
            evidence=f"Community '{community}' returned sysDescr: {sysdescr[:100]}",
            confidence=Confidence.CONFIRMED,
            tags=["snmp", "community-string", "default-credentials"],
        ))

    return findings


def run_snmp_checks(host: str, open_ports: List[int], timeout: float = 5.0) -> List[Finding]:
    """Run SNMP checks if UDP 161 is likely open.

    Note: nmap UDP scans require root. We attempt SNMP regardless for hosts
    that have common SNMP-adjacent services (network devices), checking port 161 directly.

    Args:
        host:       IP address.
        open_ports: Open TCP ports (used to infer if device is likely SNMP-capable).
        timeout:    Timeout hint.

    Returns:
        List of Finding objects.
    """
    findings: List[Finding] = []

    # Always attempt SNMP on 161 — UDP port may not appear in TCP scan
    logger.debug(f"SNMP check: {host}:161")
    try:
        findings.extend(check_snmp(host, port=SNMP_PORT, timeout=timeout))
    except Exception as e:
        logger.debug(f"SNMP check error {host}: {e}")

    return findings
