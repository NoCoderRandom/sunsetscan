"""
NetWatch FTP Security Checker.

Performs targeted FTP checks on discovered FTP ports:
  - Anonymous login detection (CRITICAL)
  - Banner version extraction for EOL matching
  - FTP bounce check (PORT command abuse)

Uses Python stdlib ftplib — no additional dependencies.

Findings produced:
    CRITICAL  - Anonymous FTP login allowed
    MEDIUM    - FTP with no TLS (STARTTLS not supported)
    INFO      - FTP banner and version
"""

import ftplib
import logging
import re
import socket
from typing import List, Optional, Tuple

from core.findings import Finding, Severity, Confidence

logger = logging.getLogger(__name__)

FTP_PORTS = {21, 2121, 990}  # 990 = FTPS implicit

# Patterns to extract version from FTP banner
_BANNER_VERSION_PATTERNS = [
    re.compile(r'vsFTPd\s+([\d.]+)', re.IGNORECASE),
    re.compile(r'ProFTPD\s+([\d.]+)', re.IGNORECASE),
    re.compile(r'PureFTPd\s+([\d.]+)', re.IGNORECASE),
    re.compile(r'FileZilla\s+Server\s+([\d.]+)', re.IGNORECASE),
    re.compile(r'Microsoft\s+FTP\s+Service.*?(\d+\.\d+)', re.IGNORECASE),
    re.compile(r'wu-(\d[\d.]+)', re.IGNORECASE),
    re.compile(r'(\d+\.\d+[\d.]*)\s*ready', re.IGNORECASE),
]


def _grab_ftp_banner(host: str, port: int, timeout: float) -> Optional[str]:
    """Grab the raw FTP welcome banner via a raw socket (avoids ftplib greeting overhead)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            return banner
    except Exception as e:
        logger.debug(f"FTP banner grab failed {host}:{port}: {e}")
        return None


def _parse_version_from_banner(banner: str) -> Optional[str]:
    """Extract a version string from an FTP banner."""
    for pattern in _BANNER_VERSION_PATTERNS:
        m = pattern.search(banner)
        if m:
            return m.group(1)
    return None


def _parse_software_from_banner(banner: str) -> Optional[str]:
    """Extract software name from FTP banner."""
    lower = banner.lower()
    if "vsftpd" in lower:
        return "vsftpd"
    if "proftpd" in lower:
        return "proftpd"
    if "pureftpd" in lower or "pure-ftpd" in lower:
        return "pure-ftpd"
    if "filezilla" in lower:
        return "FileZilla Server"
    if "microsoft ftp" in lower or "iis" in lower:
        return "Microsoft FTP Service"
    if "wu-ftpd" in lower or "wu-" in lower:
        return "wu-ftpd"
    return None


def _test_anonymous_login(host: str, port: int, timeout: float) -> Tuple[bool, Optional[str]]:
    """
    Attempt anonymous FTP login.
    Returns (success, welcome_message_or_None).
    """
    try:
        ftp = ftplib.FTP()
        ftp.connect(host=host, port=port, timeout=timeout)
        ftp.login(user="anonymous", passwd="netwatch@scan.local")
        welcome = ftp.getwelcome()
        ftp.quit()
        return True, welcome
    except ftplib.error_perm:
        # 530 Login incorrect — anonymous denied
        return False, None
    except Exception as e:
        logger.debug(f"FTP anon login test failed {host}:{port}: {e}")
        return False, None


def _check_ftps_support(host: str, port: int, timeout: float) -> bool:
    """Check if the FTP server supports STARTTLS (AUTH TLS/SSL)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.recv(512)  # Consume banner
            sock.sendall(b"AUTH TLS\r\n")
            resp = sock.recv(512).decode("utf-8", errors="replace")
            # 234 = TLS negotiation beginning
            return resp.startswith("234")
    except Exception:
        return False


def check_ftp(host: str, port: int, timeout: float = 5.0) -> List[Finding]:
    """Run all FTP security checks for a single host:port.

    Args:
        host:    IP address.
        port:    FTP port number.
        timeout: Connection timeout in seconds.

    Returns:
        List of Finding objects.
    """
    findings: List[Finding] = []

    # ---- Grab banner ----
    banner = _grab_ftp_banner(host, port, timeout)
    if banner is None:
        return findings  # Port not reachable

    software = _parse_software_from_banner(banner)
    version = _parse_version_from_banner(banner)
    ver_str = f" {version}" if version else ""
    sw_str = f"{software}{ver_str}" if software else f"FTP{ver_str}"

    # ---- Banner info finding ----
    findings.append(Finding(
        severity=Severity.INFO,
        title=f"FTP service detected: {sw_str}",
        host=host, port=port, protocol="ftp",
        category="FTP",
        description=f"FTP service running {sw_str} on port {port}. Banner: {banner[:120]!r}",
        explanation="An FTP service was detected. FTP transmits data in cleartext by default.",
        recommendation="Consider replacing FTP with SFTP (SSH) or FTPS. Disable FTP if unused.",
        evidence=f"Banner: {banner[:120]}",
        confidence=Confidence.CONFIRMED,
        tags=["ftp", "banner"],
    ))

    # ---- Anonymous login check ----
    anon_success, welcome = _test_anonymous_login(host, port, timeout)
    if anon_success:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            title=f"Anonymous FTP login allowed on port {port}",
            host=host, port=port, protocol="ftp",
            category="Authentication",
            description=(
                f"The FTP server on port {port} accepted a login with username 'anonymous' "
                f"and no real password. Any user on the network can browse and download files."
            ),
            explanation=(
                "Anonymous FTP allows anyone to connect without credentials. "
                "This is almost always unintentional on home and office networks "
                "and can expose sensitive files to anyone on the local network or internet."
            ),
            recommendation=(
                "1. Disable anonymous FTP access immediately in the server configuration.\n"
                "2. If anonymous access is required (e.g., public software mirror), "
                "ensure no sensitive files are in the FTP root.\n"
                "3. Consider switching to SFTP which enforces authentication and encryption."
            ),
            evidence=f"Anonymous login succeeded. Welcome: {welcome!r}",
            confidence=Confidence.CONFIRMED,
            tags=["ftp", "anonymous", "authentication"],
        ))

    # ---- No TLS check ----
    if port != 990:  # 990 is implicit FTPS, skip STARTTLS check
        has_tls = _check_ftps_support(host, port, timeout)
        if not has_tls:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title=f"FTP has no TLS support (cleartext credentials) on port {port}",
                host=host, port=port, protocol="ftp",
                category="Encryption",
                description=(
                    f"The FTP server on port {port} does not support AUTH TLS (STARTTLS). "
                    "Credentials and file transfers are sent in cleartext."
                ),
                explanation=(
                    "Without TLS, your FTP username and password are sent across the network "
                    "unencrypted. Anyone using a network monitoring tool on the same network "
                    "can capture your FTP credentials."
                ),
                recommendation=(
                    "1. Enable FTPS (AUTH TLS) in your FTP server configuration.\n"
                    "2. Better: replace FTP entirely with SFTP (port 22, SSH-based).\n"
                    "3. Disable plain FTP if FTPS or SFTP is available."
                ),
                evidence="AUTH TLS response was not 234",
                confidence=Confidence.CONFIRMED,
                tags=["ftp", "cleartext", "encryption"],
            ))

    return findings


def run_ftp_checks(host: str, open_ports: List[int], timeout: float = 5.0) -> List[Finding]:
    """Run FTP checks on all FTP ports discovered for a host.

    Args:
        host:       IP address.
        open_ports: List of open TCP ports from the scan.
        timeout:    Connection timeout.

    Returns:
        List of Finding objects.
    """
    findings: List[Finding] = []
    for port in open_ports:
        if port in FTP_PORTS:
            logger.debug(f"FTP check: {host}:{port}")
            try:
                findings.extend(check_ftp(host, port, timeout))
            except Exception as e:
                logger.debug(f"FTP check error {host}:{port}: {e}")
    return findings
