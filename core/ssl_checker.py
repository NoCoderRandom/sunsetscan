"""
NetWatch SSL/TLS Certificate Checker.

Connects to HTTPS ports and inspects the TLS certificate, cipher suite,
and computes a JA3S server fingerprint for each port.

All checks are passive read-only connections — no data is modified.

Findings produced:
    CRITICAL  - Certificate already expired
                MD5-signed certificate
                NULL cipher / SSL 2.0
    HIGH      - Certificate expires within 14 days
                SSL 3.0 (POODLE)
                TLS 1.0 / TLS 1.1 in use
                RSA public key under 2048 bits
                Weak cipher suite (RC4, DES, 3DES, NULL, EXPORT, ANON)
    MEDIUM    - Certificate expires within 30 days
                Self-signed certificate
                Certificate hostname mismatch
                SHA-1 signed certificate
    LOW       - Certificate expires within 90 days
    INFO      - Certificate details (subject, issuer, expiry, SANs)
                JA3S fingerprint (+ signature match if found in database)
"""

import hashlib
import json
import logging
import socket
import ssl
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.findings import Finding, Severity, Confidence

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

# GREASE extension types to skip when computing JA3S
_GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
}

# Path to JA3 signatures cache
_CACHE_DIR = Path(__file__).parent.parent / "data" / "cache"
_JA3_DB_PATH = _CACHE_DIR / "ja3_signatures.json"

# Module-level cache for JA3S matches: {(host, port): (matched_app, matched_desc)}
_ja3s_match_cache: Dict[Tuple[str, int], Tuple[str, str]] = {}


def get_last_ja3s_match(host: str, port: int) -> Optional[Tuple[str, str]]:
    """Return (app_name, description) if a JA3S match was found, else None."""
    return _ja3s_match_cache.get((host, port))


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
    # Certificate signature algorithm (e.g. "sha256WithRSAEncryption")
    signature_algorithm: Optional[str] = None
    # Public key info
    public_key_type: Optional[str] = None   # "RSA", "EC", "DSA", etc.
    public_key_bits: Optional[int] = None

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



def _parse_cert_from_der(der_cert: bytes, info: "CertificateInfo") -> None:
    """Parse all certificate fields from DER bytes using the cryptography library.

    With ssl.CERT_NONE, getpeercert() returns an empty dict so we cannot rely
    on it for subject/issuer/dates. This function populates all CertificateInfo
    fields from the raw DER cert. Safe to call if cryptography is not installed.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448

        cert_obj = x509.load_der_x509_certificate(der_cert)

        # Subject
        subject = {}
        for attr in cert_obj.subject:
            subject[attr.oid._name] = attr.value  # e.g. "commonName" -> "example.com"
        info.subject = subject
        info.common_name = subject.get("commonName", "")

        # Issuer
        issuer = {}
        for attr in cert_obj.issuer:
            issuer[attr.oid._name] = attr.value
        info.issuer = issuer

        # Validity dates — cryptography 41.x returns naive datetimes (UTC assumed)
        # cryptography 42.x uses not_valid_before_utc (timezone-aware)
        try:
            info.not_before = cert_obj.not_valid_before_utc
            info.not_after = cert_obj.not_valid_after_utc
        except AttributeError:
            # cryptography < 42: naive datetimes, treat as UTC
            nb = cert_obj.not_valid_before
            na = cert_obj.not_valid_after
            info.not_before = nb.replace(tzinfo=timezone.utc) if nb else None
            info.not_after = na.replace(tzinfo=timezone.utc) if na else None

        # SANs
        try:
            san_ext = cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            info.sans = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        # Self-signed: subject == issuer
        info.is_self_signed = (cert_obj.subject == cert_obj.issuer)

        # Signature algorithm
        sig_alg = cert_obj.signature_hash_algorithm
        if sig_alg:
            info.signature_algorithm = sig_alg.name  # "sha256", "sha1", "md5"

        # Public key
        pub_key = cert_obj.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            info.public_key_type = "RSA"
            info.public_key_bits = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            info.public_key_type = "EC"
            info.public_key_bits = pub_key.key_size
        elif isinstance(pub_key, dsa.DSAPublicKey):
            info.public_key_type = "DSA"
            info.public_key_bits = pub_key.key_size
        elif isinstance(pub_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            info.public_key_type = "EdDSA"

    except Exception as e:
        logger.debug(f"Certificate DER parsing failed: {e}")


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
            der_cert = tls_sock.getpeercert(binary_form=True)
            cipher = tls_sock.cipher()  # (name, protocol, bits)

            if cipher:
                info.cipher_name = cipher[0]
                info.tls_version = cipher[1]

            # Parse all certificate fields from DER using cryptography library.
            # getpeercert() (non-binary) returns {} with CERT_NONE, so we rely
            # entirely on DER parsing for subject/issuer/dates/SANs/key info.
            if der_cert:
                _parse_cert_from_der(der_cert, info)

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


# ---------------------------------------------------------------------------
# JA3S fingerprinting via raw TLS handshake
# ---------------------------------------------------------------------------

def _build_client_hello(host: str) -> bytes:
    """Build a TLS 1.2 ClientHello for maximum device compatibility.

    Uses TLS 1.2 without the supported_versions extension to avoid triggering
    TLS 1.3 negotiation failures on devices with strict handshake requirements
    (e.g. home routers, NAS devices). The SNI is included for proper response.
    This design maximises the chance of receiving a ServerHello and computing
    the JA3S hash.
    """
    # Broad cipher suite list — both ECDHE and RSA key exchange for compatibility
    cipher_suites = [
        0xc02f, 0xc02b,  # TLS_ECDHE_RSA/ECDSA_WITH_AES_128_GCM_SHA256
        0xc030, 0xc02c,  # TLS_ECDHE_RSA/ECDSA_WITH_AES_256_GCM_SHA384
        0x009c, 0x009d,  # TLS_RSA_WITH_AES_128/256_GCM_SHA256/SHA384
        0xc027, 0xc028,  # TLS_ECDHE_RSA_WITH_AES_128/256_CBC_SHA256/SHA384
        0x002f, 0x0035,  # TLS_RSA_WITH_AES_128/256_CBC_SHA
        0x000a,          # TLS_RSA_WITH_3DES_EDE_CBC_SHA
        0x0005,          # TLS_RSA_WITH_RC4_128_SHA
    ]

    import os as _os
    client_random = _os.urandom(32)
    cs_bytes = b"".join(struct.pack(">H", cs) for cs in cipher_suites)

    # Extension: SNI (type 0)
    sni = host.encode("ascii", errors="ignore")
    sni_ext_data = (
        struct.pack(">H", len(sni) + 3)
        + bytes([0])                  # name type: host_name
        + struct.pack(">H", len(sni))
        + sni
    )
    ext_sni = struct.pack(">H", 0) + struct.pack(">H", len(sni_ext_data)) + sni_ext_data

    # Extension: supported_groups (type 10)
    groups = [0x0017, 0x0018, 0x001d]  # secp256r1, secp384r1, x25519
    sg_data = struct.pack(">H", len(groups) * 2) + b"".join(struct.pack(">H", g) for g in groups)
    ext_sg = struct.pack(">H", 10) + struct.pack(">H", len(sg_data)) + sg_data

    # Extension: ec_point_formats (type 11)
    epf_data = struct.pack(">B", 1) + bytes([0])  # uncompressed
    ext_epf = struct.pack(">H", 11) + struct.pack(">H", len(epf_data)) + epf_data

    # Extension: session_ticket (type 35) — empty, improves compatibility
    ext_st = struct.pack(">H", 35) + struct.pack(">H", 0)

    # NOTE: No supported_versions extension — forces TLS 1.2 negotiation.
    # Adding supported_versions with TLS 1.3 causes certificate_required
    # alerts on some home devices (ASUS, Synology) that use strict TLS 1.3
    # handshake validation.
    extensions = ext_sni + ext_sg + ext_epf + ext_st

    hello_body = (
        b"\x03\x03"                          # client_version: TLS 1.2
        + client_random
        + b"\x00"                            # session_id_length = 0
        + struct.pack(">H", len(cs_bytes))
        + cs_bytes
        + b"\x01\x00"                        # 1 compression method: none
        + struct.pack(">H", len(extensions))
        + extensions
    )

    hs_len = len(hello_body)
    handshake = bytes([0x01]) + struct.pack(">I", hs_len)[1:] + hello_body
    # Use TLS 1.0 (0x0301) record-layer version for max compatibility with old devices
    return bytes([0x16, 0x03, 0x01]) + struct.pack(">H", len(handshake)) + handshake


def _parse_server_hello_ja3s(data: bytes) -> Optional[Tuple[int, int, List[int]]]:
    """Parse raw TLS response bytes to extract ServerHello fields for JA3S.

    Returns:
        (tls_version, cipher_code, extension_types) or None if not found.
        tls_version: integer (e.g. 769=TLS1.0, 771=TLS1.2, 772=TLS1.3)
        cipher_code: IANA cipher suite integer
        extension_types: list of extension type integers (GREASE excluded)
    """
    offset = 0
    while offset + 5 <= len(data):
        record_type = data[offset]
        record_len = struct.unpack_from(">H", data, offset + 3)[0]
        offset += 5

        if offset + record_len > len(data):
            break

        if record_type == 0x16:  # Handshake
            hs_offset = offset
            hs_end = offset + record_len

            while hs_offset + 4 <= hs_end:
                hs_type = data[hs_offset]
                hs_len = struct.unpack_from(">I", b"\x00" + data[hs_offset + 1: hs_offset + 4])[0]
                hs_offset += 4

                if hs_type == 2:  # ServerHello
                    sh = data[hs_offset: hs_offset + hs_len]
                    if len(sh) < 35:
                        return None

                    # sh[0:2] = server version
                    version = struct.unpack_from(">H", sh, 0)[0]
                    # sh[2:34] = server random (skip)
                    session_id_len = sh[34]
                    pos = 35 + session_id_len

                    if pos + 3 > len(sh):
                        return None

                    cipher_code = struct.unpack_from(">H", sh, pos)[0]
                    pos += 3  # cipher(2) + compression(1)

                    extension_types: List[int] = []
                    if pos + 2 <= len(sh):
                        exts_len = struct.unpack_from(">H", sh, pos)[0]
                        pos += 2
                        ext_end = pos + exts_len

                        while pos + 4 <= ext_end and pos + 4 <= len(sh):
                            ext_type = struct.unpack_from(">H", sh, pos)[0]
                            ext_data_len = struct.unpack_from(">H", sh, pos + 2)[0]

                            # Check supported_versions extension (type 43)
                            # In TLS 1.3, this overrides the version field
                            if ext_type == 43 and pos + 4 + ext_data_len <= len(sh):
                                sv_data = sh[pos + 4: pos + 4 + ext_data_len]
                                if len(sv_data) >= 2:
                                    actual_version = struct.unpack_from(">H", sv_data, 0)[0]
                                    if actual_version in (0x0304, 0x0303, 0x0302, 0x0301):
                                        version = actual_version

                            if ext_type not in _GREASE_VALUES:
                                extension_types.append(ext_type)

                            pos += 4 + ext_data_len

                    return version, cipher_code, extension_types

                hs_offset += hs_len

        elif record_type == 0x15:  # Alert — server rejected us
            break

        offset += record_len

    return None


def _compute_ja3s(version: int, cipher: int, extensions: List[int]) -> str:
    """Compute JA3S = MD5(SSLVersion,Cipher,Extensions)."""
    ext_str = "-".join(str(e) for e in extensions)
    ja3s_str = f"{version},{cipher},{ext_str}"
    return hashlib.md5(ja3s_str.encode()).hexdigest()


def _load_ja3_signatures() -> Dict[str, Dict]:
    """Load JA3/JA3S signatures from cache.

    Returns:
        dict mapping md5_hash -> {"App": name, "Desc": description}
        Empty dict if file not found or malformed.
    """
    if not _JA3_DB_PATH.exists():
        return {}
    try:
        with open(_JA3_DB_PATH, encoding="utf-8") as f:
            raw = json.load(f)
        # Handle list format: [{"md5": "...", "App": "...", "Desc": "..."}, ...]
        if isinstance(raw, list):
            return {
                entry["md5"]: {"App": entry.get("App", ""), "Desc": entry.get("Desc", "")}
                for entry in raw
                if isinstance(entry, dict) and "md5" in entry
            }
        # Handle dict format: {"hash": {"App": "...", "Desc": "..."}, ...}
        if isinstance(raw, dict):
            return {
                k: v if isinstance(v, dict) else {"App": str(v), "Desc": ""}
                for k, v in raw.items()
            }
    except Exception as e:
        logger.debug(f"Failed to load JA3 signatures: {e}")
    return {}


def _get_ja3s(host: str, port: int, timeout: float) -> Optional[Tuple[str, Optional[str], Optional[str]]]:
    """Perform a raw TLS handshake and compute JA3S fingerprint.

    Returns:
        (ja3s_hash, matched_app, matched_desc) or None on failure.
        matched_app / matched_desc are None if no database match.
    """
    try:
        client_hello = _build_client_hello(host)
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(client_hello)

        response = b""
        # Read until we have a ServerHello or an alert
        for _ in range(20):
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            # Check if we have a complete ServerHello
            result = _parse_server_hello_ja3s(response)
            if result is not None:
                break
        sock.close()

    except Exception as e:
        logger.debug(f"JA3S raw TLS failed {host}:{port}: {e}")
        return None

    result = _parse_server_hello_ja3s(response)
    if result is None:
        return None

    version, cipher_code, ext_types = result
    ja3s_hash = _compute_ja3s(version, cipher_code, ext_types)
    logger.debug(f"JA3S {host}:{port}: {ja3s_hash} (v={version:#x}, c={cipher_code:#x}, exts={ext_types})")

    # Database lookup
    sigs = _load_ja3_signatures()
    if not sigs:
        logger.debug("JA3 database not found — run --update-cache to download")

    match = sigs.get(ja3s_hash)
    if match:
        return ja3s_hash, match.get("App"), match.get("Desc")

    return ja3s_hash, None, None


# ---------------------------------------------------------------------------
# Findings generation
# ---------------------------------------------------------------------------

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

    # ---- Certificate signature algorithm ----
    if cert.signature_algorithm:
        alg_lower = cert.signature_algorithm.lower()
        if "md5" in alg_lower:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title=f"TLS certificate signed with MD5 on port {port}",
                host=host, port=port, protocol="https",
                category="SSL/TLS",
                description=(
                    f"Certificate on port {port} uses MD5 as its signature algorithm. "
                    f"MD5 is cryptographically broken and certificates signed with it "
                    f"can be forged."
                ),
                explanation=(
                    "MD5 collision attacks allow an attacker to create a forged certificate "
                    "with the same MD5 hash as a legitimate one. This completely undermines "
                    "the certificate's integrity guarantee."
                ),
                recommendation=(
                    "Replace this certificate immediately with one signed using "
                    "SHA-256 or SHA-384. Update device firmware."
                ),
                evidence=f"Signature algorithm: {cert.signature_algorithm}",
                confidence=Confidence.CONFIRMED,
                tags=["ssl", "certificate", "md5", "weak-signature"],
            ))
        elif "sha1" in alg_lower:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title=f"TLS certificate signed with SHA-1 on port {port}",
                host=host, port=port, protocol="https",
                category="SSL/TLS",
                description=(
                    f"Certificate on port {port} uses SHA-1 as its signature algorithm. "
                    f"SHA-1 is deprecated and browsers have removed support for it."
                ),
                explanation=(
                    "SHA-1 is deprecated for certificate signing. While a practical attack "
                    "is expensive, SHA-1 signed certificates are rejected by modern browsers "
                    "and should be replaced with SHA-256 signed certificates."
                ),
                recommendation=(
                    "Replace this certificate with one signed using SHA-256. "
                    "Update device firmware or regenerate the certificate."
                ),
                evidence=f"Signature algorithm: {cert.signature_algorithm}",
                confidence=Confidence.CONFIRMED,
                tags=["ssl", "certificate", "sha1", "weak-signature"],
            ))

    # ---- RSA public key size ----
    if cert.public_key_type == "RSA" and cert.public_key_bits is not None:
        if cert.public_key_bits < 2048:
            findings.append(Finding(
                severity=Severity.HIGH,
                title=f"TLS certificate RSA key too small ({cert.public_key_bits} bits) on port {port}",
                host=host, port=port, protocol="https",
                category="SSL/TLS",
                description=(
                    f"The TLS certificate on port {port} has an RSA public key of only "
                    f"{cert.public_key_bits} bits. Keys under 2048 bits are considered weak."
                ),
                explanation=(
                    "RSA keys smaller than 2048 bits can be factored with sufficient computing "
                    "resources. NIST deprecated 1024-bit RSA keys in 2013. "
                    "Modern minimum is 2048 bits; 4096 bits is recommended."
                ),
                recommendation=(
                    "Regenerate the TLS certificate with an RSA key of at least 2048 bits, "
                    "or switch to ECDSA P-256 which provides equivalent security with shorter keys. "
                    "Update device firmware."
                ),
                evidence=f"RSA key: {cert.public_key_bits} bits",
                confidence=Confidence.CONFIRMED,
                tags=["ssl", "certificate", "weak-key", "rsa"],
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
                severity=Severity.MEDIUM,
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
                    severity=Severity.HIGH,
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
        key_info = ""
        if cert.public_key_type and cert.public_key_bits:
            key_info = f", Key={cert.public_key_type}-{cert.public_key_bits}"
        elif cert.public_key_type:
            key_info = f", Key={cert.public_key_type}"
        findings.append(Finding(
            severity=Severity.INFO,
            title=f"TLS certificate: CN={cn}",
            host=host, port=port, protocol="https",
            category="SSL/TLS",
            description=(
                f"Port {port} TLS certificate: CN={cn}, "
                f"Issuer={issuer_org}, "
                f"Expires={expiry_str}, "
                f"Protocol={cert.tls_version or 'unknown'}"
                f"{key_info}."
            ),
            explanation="TLS certificate details for this service.",
            recommendation="No action required for this informational item.",
            evidence=f"CN={cn} | Issuer={issuer_org} | Expires={expiry_str}{key_info}",
            tags=["ssl", "info"],
        ))

    return findings


def run_ssl_checks(
    host: str,
    open_ports: List[int],
    timeout: float = 5.0,
) -> List[Finding]:
    """Run SSL/TLS checks on all SSL-relevant open ports for a host.

    For each port: inspects the certificate, checks TLS version and cipher,
    and computes a JA3S fingerprint. JA3S is matched against ja3_signatures.json
    if available (run --update-cache to download).

    Args:
        host: IP address to check.
        open_ports: List of open TCP port numbers from the scan.
        timeout: Connection timeout in seconds.

    Returns:
        List of Finding objects from all SSL checks.
    """
    all_findings: List[Finding] = []
    ssl_ports_to_check = [p for p in open_ports if p in SSL_PORTS]

    ja3_sigs_available = _JA3_DB_PATH.exists()
    if not ja3_sigs_available and ssl_ports_to_check:
        logger.debug("JA3 database not found — run --update-cache to download")

    for port in ssl_ports_to_check:
        logger.debug(f"SSL check: {host}:{port}")

        # Certificate checks
        cert = check_ssl_certificate(host, port, timeout=timeout)
        findings = generate_ssl_findings(host, port, cert)
        all_findings.extend(findings)

        # JA3S fingerprinting (only if TLS connection was successful)
        if not cert.error:
            ja3s_result = _get_ja3s(host, port, timeout)
            if ja3s_result is not None:
                ja3s_hash, matched_app, matched_desc = ja3s_result

                # Store match in module cache for netwatch.py EOL pipeline
                if matched_app:
                    _ja3s_match_cache[(host, port)] = (matched_app, matched_desc or "")

                # Build JA3S finding
                if matched_app:
                    ja3s_title = f"JA3S fingerprint identified: {matched_app}"
                    ja3s_desc = (
                        f"TLS server on port {port} matched JA3S signature: {matched_app}. "
                        f"{matched_desc or ''}"
                    )
                    ja3s_sev = Severity.INFO
                    # Flag known malicious/suspicious if description contains keywords
                    if matched_desc and any(
                        kw in matched_desc.lower()
                        for kw in ("malware", "malicious", "cobalt", "metasploit", "suspicious")
                    ):
                        ja3s_sev = Severity.HIGH
                        ja3s_title = f"JA3S fingerprint matched known malicious signature: {matched_app}"
                else:
                    ja3s_title = f"JA3S fingerprint computed on port {port}"
                    ja3s_desc = (
                        f"JA3S fingerprint computed for TLS server on port {port}. "
                        f"No match found in signature database."
                        + (" Run --update-cache to download latest signatures." if not ja3_sigs_available else "")
                    )
                    ja3s_sev = Severity.INFO

                all_findings.append(Finding(
                    severity=ja3s_sev,
                    title=ja3s_title,
                    host=host, port=port, protocol="https",
                    category="SSL/TLS",
                    description=ja3s_desc,
                    explanation=(
                        "JA3S is a server-side TLS fingerprint computed from the ServerHello: "
                        "TLS version, selected cipher suite, and extension types. "
                        "It can identify the TLS server implementation and detect known malicious configurations."
                    ),
                    recommendation=(
                        "No action required for INFO findings. "
                        "If matched as malicious/suspicious, investigate the service on this port."
                    ),
                    evidence=f"JA3S: {ja3s_hash}"
                    + (f" | Matched: {matched_app}" if matched_app else ""),
                    confidence=Confidence.CONFIRMED if matched_app else Confidence.LIKELY,
                    tags=["ssl", "ja3s", "fingerprint"],
                ))

    return all_findings
