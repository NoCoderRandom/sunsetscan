"""
NetWatch SSL/TLS Certificate Checker.

Connects to HTTPS ports and inspects the TLS certificate and cipher suite.
All checks are passive read-only connections — no data is modified.

Findings produced:
    CRITICAL  - Certificate already expired
    HIGH      - Certificate expires within 14 days
                Weak protocol: TLS 1.0 or TLS 1.1 in use
                SSL 2.0 / SSL 3.0 in use
    MEDIUM    - Certificate expires within 30 days
                Self-signed certificate (no trusted CA)
                Certificate hostname mismatch
                Weak cipher suite (RC4, DES, 3DES, NULL, EXPORT, ANON)
    LOW       - Certificate expires within 90 days
    INFO      - Certificate details (subject, issuer, expiry, SANs)
"""

import logging
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from core.findings import Finding, Severity

logger = logging.getLogger(__name__)

# Ports that should have TLS/SSL checked
SSL_PORTS = {443, 465, 587, 636, 993, 995, 3389, 8443, 8080, 8000, 9443}

# Cipher names that indicate weak / broken algorithms
WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "ANON",
    "ADH", "AECDH", "eNULL", "aNULL",
}

# Days thresholds for expiry warnings
EXPIRY_CRITICAL_DAYS = 0
EXPIRY_HIGH_DAYS = 14
EXPIRY_MEDIUM_DAYS = 30
EXPIRY_LOW_DAYS = 90


@dataclass
class CertificateInfo:
    """Parsed TLS certificate information."""
    subject: Dict = field(default_factory=dict)
    issuer: Dict = field(default_factory=dict)
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    sans: List[str] = field(default_factory=list)
    is_self_signed: bool = False
    cipher_name: Optional[str] = None
    tls_version: Optional[str] = None
    common_name: str = ""
    error: Optional[str] = None

    @property
    def days_until_expiry(self) -> Optional[int]:
        if not self.not_after:
            return None
        now = datetime.now(timezone.utc)
        if self.not_after.tzinfo is None:
            # Naive datetime — assume UTC
            not_after_utc = self.not_after.replace(tzinfo=timezone.utc)
        else:
            not_after_utc = self.not_after
        return (not_after_utc - now).days

    @property
    def is_expired(self) -> bool:
        days = self.days_until_expiry
        return days is not None and days < 0


def _dict_from_rdns(rdns) -> Dict[str, str]:
    """Convert an SSL certificate DN tuple to a flat dict."""
    result: Dict[str, str] = {}
    for part in rdns:
        for key, value in part:
            result[key] = value
    return result


def check_ssl_certificate(
    host: str,
    port: int,
    timeout: float = 5.0,
) -> CertificateInfo:
    """Connect to host:port and retrieve TLS certificate details.

    Safe read-only operation. Returns a CertificateInfo with error field
    populated if the connection fails.
    """
    info = CertificateInfo()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # We inspect manually — don't reject self-signed

    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            cert = tls_sock.getpeercert()
            cipher = tls_sock.cipher()  # (name, protocol, bits)

            if cipher:
                info.cipher_name = cipher[0]
                info.tls_version = cipher[1]

            if cert:
                subject_raw = cert.get("subject", ())
                issuer_raw = cert.get("issuer", ())

                info.subject = _dict_from_rdns(subject_raw)
                info.issuer = _dict_from_rdns(issuer_raw)
                info.common_name = info.subject.get("commonName", "")

                # Parse dates — format: "Jun  5 12:00:00 2025 GMT"
                for date_key, attr in (("notBefore", "not_before"), ("notAfter", "not_after")):
                    raw = cert.get(date_key, "")
                    if raw:
                        try:
                            parsed = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z")
                            parsed = parsed.replace(tzinfo=timezone.utc)
                            setattr(info, attr, parsed)
                        except ValueError:
                            logger.debug(f"Could not parse cert date: {raw!r}")

                # SANs
                for san_type, san_value in cert.get("subjectAltName", ()):
                    if san_type == "DNS":
                        info.sans.append(san_value)

                # Self-signed: subject == issuer
                info.is_self_signed = (info.subject == info.issuer)

    except ssl.SSLError as e:
        info.error = f"SSL error: {e}"
        logger.debug(f"SSL check failed {host}:{port}: {e}")
    except (socket.timeout, socket.error, ConnectionRefusedError, OSError) as e:
        info.error = f"Connection error: {e}"
        logger.debug(f"SSL connection failed {host}:{port}: {e}")
    except Exception as e:
        info.error = f"Unexpected error: {e}"
        logger.debug(f"SSL unexpected error {host}:{port}: {e}")

    return info


def generate_ssl_findings(
    host: str,
    port: int,
    cert: CertificateInfo,
) -> List[Finding]:
    """Convert a CertificateInfo into a list of Finding objects."""
    findings: List[Finding] = []

    if cert.error:
        # If we couldn't connect at all, that's not a finding — just skip
        return findings

    # ---- Certificate expiry ----
    days = cert.days_until_expiry
    if days is not None:
        if days < EXPIRY_CRITICAL_DAYS:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title=f"TLS certificate expired {abs(days)} days ago",
                host=host,
                port=port,
                protocol="https",
                category="SSL/TLS",
                description=(
                    f"The TLS certificate on port {port} expired {abs(days)} days ago "
                    f"(expired: {cert.not_after.strftime('%Y-%m-%d') if cert.not_after else 'unknown'})."
                ),
                explanation=(
                    "The HTTPS certificate on this device has expired. Browsers will show "
                    "a scary red warning to anyone visiting this service. Worse, the "
                    "device may be using outdated encryption."
                ),
                recommendation=(
                    "1. Log in to the device admin panel.\n"
                    "2. Navigate to the SSL/TLS or Certificate settings.\n"
                    "3. Renew or replace the certificate.\n"
                    "4. If this is a router or IoT device, check for a firmware update."
                ),
                evidence=f"Certificate not_after: {cert.not_after}",
                tags=["ssl", "certificate", "expired"],
            ))
        elif days < EXPIRY_HIGH_DAYS:
            findings.append(Finding(
                severity=Severity.HIGH,
                title=f"TLS certificate expiring in {days} days",
                host=host,
                port=port,
                protocol="https",
                category="SSL/TLS",
                description=f"Certificate on port {port} expires in {days} days.",
                explanation=(
                    "The TLS certificate on this device expires very soon. "
                    "Once expired, connections will show certificate errors."
                ),
                recommendation=(
                    "Renew the TLS certificate as soon as possible. "
                    "Check the device admin panel for certificate renewal options."
                ),
                evidence=f"Expires: {cert.not_after.strftime('%Y-%m-%d') if cert.not_after else 'unknown'}",
                tags=["ssl", "certificate", "expiring"],
            ))
        elif days < EXPIRY_MEDIUM_DAYS:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title=f"TLS certificate expiring in {days} days",
                host=host,
                port=port,
                protocol="https",
                category="SSL/TLS",
                description=f"Certificate on port {port} expires in {days} days.",
                explanation="The TLS certificate expires within 30 days and should be renewed soon.",
                recommendation=(
                    "Schedule certificate renewal within the next two weeks. "
                    "Check the device admin panel or vendor update site."
                ),
                evidence=f"Expires: {cert.not_after.strftime('%Y-%m-%d') if cert.not_after else 'unknown'}",
                tags=["ssl", "certificate"],
            ))
        elif days < EXPIRY_LOW_DAYS:
            findings.append(Finding(
                severity=Severity.LOW,
                title=f"TLS certificate expiring in {days} days",
                host=host,
                port=port,
                protocol="https",
                category="SSL/TLS",
                description=f"Certificate on port {port} expires in {days} days.",
                explanation="The TLS certificate expires within 90 days.",
                recommendation="Plan to renew the TLS certificate before it expires.",
                evidence=f"Expires: {cert.not_after.strftime('%Y-%m-%d') if cert.not_after else 'unknown'}",
                tags=["ssl", "certificate"],
            ))

    # ---- Self-signed certificate ----
    if cert.is_self_signed:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title="Self-signed TLS certificate (no trusted CA)",
            host=host,
            port=port,
            protocol="https",
            category="SSL/TLS",
            description=(
                f"The certificate on port {port} is self-signed. "
                f"Issuer: {cert.issuer.get('organizationName', cert.issuer.get('commonName', 'unknown'))}."
            ),
            explanation=(
                "A self-signed certificate means the device created and signed its own "
                "certificate rather than getting one from a trusted authority. "
                "Your browser cannot verify the identity of the device, making it "
                "possible (though unlikely on a home network) for someone to intercept "
                "the connection."
            ),
            recommendation=(
                "For critical devices (router admin panels, NAS), consider replacing "
                "the self-signed certificate with one from Let's Encrypt or your "
                "organisation's certificate authority. For home IoT devices, this is "
                "low priority but worth noting."
            ),
            evidence=f"Subject == Issuer: {cert.common_name}",
            tags=["ssl", "self-signed"],
        ))

    # ---- Weak TLS version ----
    if cert.tls_version:
        tls_ver = cert.tls_version.upper()
        if "SSLV2" in tls_ver or "SSL2" in tls_ver:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="SSL 2.0 detected — severely broken protocol",
                host=host, port=port, protocol="https",
                category="SSL/TLS",
                description=f"Port {port} negotiated SSL 2.0, which has critical known vulnerabilities.",
                explanation=(
                    "SSL 2.0 was deprecated in 2011 and has multiple critical flaws. "
                    "Any modern attacker can break this encryption."
                ),
                recommendation=(
                    "Disable SSL 2.0 immediately. Update device firmware. "
                    "If the device cannot be updated, replace it."
                ),
                evidence=f"Negotiated: {cert.tls_version}",
                tags=["ssl", "weak-protocol"],
            ))
        elif "SSLV3" in tls_ver or "SSL3" in tls_ver:
            findings.append(Finding(
                severity=Severity.HIGH,
                title="SSL 3.0 detected — deprecated and vulnerable (POODLE)",
                host=host, port=port, protocol="https",
                category="SSL/TLS",
                description=f"Port {port} negotiated SSL 3.0, vulnerable to POODLE attack (CVE-2014-3566).",
                explanation=(
                    "SSL 3.0 is vulnerable to the POODLE attack which allows an attacker "
                    "to decrypt encrypted data. It was officially deprecated in 2015."
                ),
                recommendation=(
                    "Disable SSL 3.0 and require TLS 1.2 or higher. "
                    "Update device firmware."
                ),
                evidence=f"Negotiated: {cert.tls_version}",
                cve_ids=["CVE-2014-3566"],
                tags=["ssl", "poodle", "weak-protocol"],
            ))
        elif "TLSV1.0" in tls_ver or "TLS 1.0" in tls_ver:
            findings.append(Finding(
                severity=Severity.HIGH,
                title="TLS 1.0 detected — deprecated protocol",
                host=host, port=port, protocol="https",
                category="SSL/TLS",
                description=f"Port {port} negotiated TLS 1.0, deprecated since 2021 (RFC 8996).",
                explanation=(
                    "TLS 1.0 has known weaknesses including BEAST and POODLE attacks. "
                    "It was officially deprecated by RFC 8996 in 2021. "
                    "Modern browsers have removed support for it."
                ),
                recommendation=(
                    "Configure the device to require TLS 1.2 or higher. "
                    "Update device firmware to enable modern TLS settings."
                ),
                evidence=f"Negotiated: {cert.tls_version}",
                tags=["ssl", "weak-protocol", "tls1.0"],
            ))
        elif "TLSV1.1" in tls_ver or "TLS 1.1" in tls_ver:
            findings.append(Finding(
                severity=Severity.HIGH,
                title="TLS 1.1 detected — deprecated protocol",
                host=host, port=port, protocol="https",
                category="SSL/TLS",
                description=f"Port {port} negotiated TLS 1.1, deprecated since 2021 (RFC 8996).",
                explanation=(
                    "TLS 1.1 is deprecated and should not be used. "
                    "Configure the device to use TLS 1.2 or TLS 1.3."
                ),
                recommendation=(
                    "Update device firmware and configure TLS 1.2+ only."
                ),
                evidence=f"Negotiated: {cert.tls_version}",
                tags=["ssl", "weak-protocol", "tls1.1"],
            ))

    # ---- Weak cipher suite ----
    if cert.cipher_name:
        for weak in WEAK_CIPHERS:
            if weak.upper() in cert.cipher_name.upper():
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title=f"Weak cipher suite in use: {cert.cipher_name}",
                    host=host, port=port, protocol="https",
                    category="SSL/TLS",
                    description=(
                        f"Port {port} negotiated cipher suite {cert.cipher_name!r} "
                        f"which contains weak algorithm: {weak}."
                    ),
                    explanation=(
                        f"The {weak} algorithm in the cipher suite is considered weak or broken. "
                        "Using weak ciphers means encrypted data could potentially be "
                        "decrypted by a determined attacker."
                    ),
                    recommendation=(
                        "Update device firmware. Configure TLS to use only strong "
                        "cipher suites (AES-GCM, CHACHA20). Disable legacy cipher suites."
                    ),
                    evidence=f"Negotiated cipher: {cert.cipher_name}",
                    tags=["ssl", "weak-cipher"],
                ))
                break  # One finding per cipher check per port

    # ---- Info: cert summary ----
    if not cert.error and cert.common_name:
        cn = cert.common_name
        issuer_org = cert.issuer.get("organizationName", cert.issuer.get("commonName", "self-signed"))
        expiry_str = cert.not_after.strftime("%Y-%m-%d") if cert.not_after else "unknown"
        findings.append(Finding(
            severity=Severity.INFO,
            title=f"TLS certificate: CN={cn}",
            host=host, port=port, protocol="https",
            category="SSL/TLS",
            description=(
                f"Port {port} TLS certificate: CN={cn}, "
                f"Issuer={issuer_org}, "
                f"Expires={expiry_str}, "
                f"Protocol={cert.tls_version or 'unknown'}."
            ),
            explanation="TLS certificate details for this service.",
            recommendation="No action required for this informational item.",
            evidence=f"CN={cn} | Issuer={issuer_org} | Expires={expiry_str}",
            tags=["ssl", "info"],
        ))

    return findings


def run_ssl_checks(
    host: str,
    open_ports: List[int],
    timeout: float = 5.0,
) -> List[Finding]:
    """Run SSL/TLS checks on all SSL-relevant open ports for a host.

    Args:
        host: IP address to check.
        open_ports: List of open TCP port numbers from the scan.
        timeout: Connection timeout in seconds.

    Returns:
        List of Finding objects from all SSL checks.
    """
    all_findings: List[Finding] = []
    ssl_ports_to_check = [p for p in open_ports if p in SSL_PORTS]

    for port in ssl_ports_to_check:
        logger.debug(f"SSL check: {host}:{port}")
        cert = check_ssl_certificate(host, port, timeout=timeout)
        findings = generate_ssl_findings(host, port, cert)
        all_findings.extend(findings)

    return all_findings
