"""
NetWatch SSH Deep Analysis Module.

Uses paramiko to perform deep SSH inspection beyond what nmap reports:
  - Precise SSH version extraction from banner
  - Weak key exchange algorithm detection
  - Weak cipher detection
  - Weak MAC algorithm detection
  - Host key type and size inspection

Findings produced:
    CRITICAL  - Extremely weak algorithms (arcfour/RC4, none cipher)
    HIGH      - Weak KEX (diffie-hellman-group1-sha1, diffie-hellman-group14-sha1)
                Weak MACs (md5, sha1 in hmac-md5, hmac-sha1)
    MEDIUM    - Weak host key (DSA, RSA < 2048 bits)
    INFO      - SSH version and host key fingerprint
"""

import logging
import socket
from typing import List, Optional, Tuple

from core.findings import Finding, Severity, Confidence

logger = logging.getLogger(__name__)

SSH_PORTS = {22, 2222, 22222}

# Weak key exchange algorithms — known broken or weak
_WEAK_KEX = {
    "diffie-hellman-group1-sha1",       # 768-bit Oakley Group 1 — broken
    "diffie-hellman-group14-sha1",      # SHA-1 — deprecated
    "diffie-hellman-group-exchange-sha1",
    "gss-group1-sha1-*",
    "gss-group14-sha1-*",
}

# Weak ciphers
_WEAK_CIPHERS = {
    "arcfour", "arcfour128", "arcfour256",  # RC4 — broken
    "3des-cbc",                              # 3DES — weak, deprecated
    "blowfish-cbc",                          # weak block size
    "cast128-cbc",
    "none",                                  # no encryption
    "des-cbc-ssh1",
}

# Weak MAC algorithms
_WEAK_MACS = {
    "hmac-md5",
    "hmac-md5-96",
    "hmac-sha1",
    "hmac-sha1-96",
    "umac-32@openssh.com",
    "none",
}


def _grab_ssh_banner(host: str, port: int, timeout: float) -> Optional[str]:
    """Grab the raw SSH identification string (first line sent by server)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(256).decode("utf-8", errors="replace").strip()
            return banner
    except Exception as e:
        logger.debug(f"SSH banner grab failed {host}:{port}: {e}")
        return None


def _get_ssh_algorithms(
    host: str, port: int, timeout: float
) -> Optional[Tuple[List[str], List[str], List[str], str, int]]:
    """
    Connect via paramiko Transport and extract negotiated/advertised algorithms.

    Returns:
        (kex_algos, ciphers, macs, host_key_type, host_key_bits) or None on failure.
    """
    try:
        import paramiko
        # Suppress paramiko's internal transport error logging — we handle errors ourselves
        logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)

        transport = paramiko.Transport((host, port))
        transport.connect()  # Don't authenticate — just complete key exchange

        security_options = transport.get_security_options()
        kex = list(security_options.kex) if security_options.kex else []
        ciphers = list(security_options.ciphers) if security_options.ciphers else []
        macs = list(security_options.digests) if security_options.digests else []

        host_key = transport.get_remote_server_key()
        host_key_type = host_key.get_name() if host_key else "unknown"
        host_key_bits = host_key.get_bits() if hasattr(host_key, "get_bits") else 0

        transport.close()
        return kex, ciphers, macs, host_key_type, host_key_bits

    except Exception as e:
        logger.debug(f"SSH algorithm enumeration failed {host}:{port}: {e}")
        return None


def check_ssh(host: str, port: int, timeout: float = 8.0) -> List[Finding]:
    """Run all SSH security checks for a single host:port.

    Args:
        host:    IP address.
        port:    SSH port number.
        timeout: Connection timeout in seconds.

    Returns:
        List of Finding objects.
    """
    findings: List[Finding] = []

    # ---- Grab banner ----
    banner = _grab_ssh_banner(host, port, timeout)
    if banner is None:
        return findings

    # Extract version info from banner (format: SSH-2.0-OpenSSH_8.9p1)
    ssh_version = banner.strip()
    software = "Unknown"
    sw_version = ""
    if "-" in ssh_version:
        parts = ssh_version.split("-", 2)
        if len(parts) >= 3:
            sw_part = parts[2].split()[0]  # e.g. "OpenSSH_8.9p1"
            if "_" in sw_part:
                sw_name, sw_version = sw_part.split("_", 1)
                software = sw_name
            else:
                software = sw_part

    findings.append(Finding(
        severity=Severity.INFO,
        title=f"SSH service detected: {software} {sw_version}".strip(),
        host=host, port=port, protocol="ssh",
        category="SSH",
        description=f"SSH server identified as: {ssh_version}",
        explanation="An SSH service was detected. SSH is generally secure but weak algorithm choices can undermine its security.",
        recommendation="Ensure SSH server is up-to-date and uses modern algorithm configurations.",
        evidence=f"Banner: {ssh_version}",
        confidence=Confidence.CONFIRMED,
        tags=["ssh", "banner"],
    ))

    # ---- SSH protocol version 1 check ----
    if "SSH-1." in banner:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            title=f"SSH protocol version 1 in use on port {port}",
            host=host, port=port, protocol="ssh",
            category="SSH",
            description="SSH-1 has known cryptographic vulnerabilities and must not be used.",
            explanation=(
                "SSH protocol version 1 has multiple well-known cryptographic flaws including "
                "man-in-the-middle attacks and session hijacking. It was deprecated in 2006."
            ),
            recommendation=(
                "Disable SSH protocol version 1 in sshd_config: set 'Protocol 2'.\n"
                "If the device does not support SSH-2, replace or update the firmware."
            ),
            evidence=f"Banner: {banner}",
            confidence=Confidence.CONFIRMED,
            tags=["ssh", "protocol-v1", "critical"],
        ))

    # ---- Algorithm enumeration via paramiko ----
    algo_result = _get_ssh_algorithms(host, port, timeout)
    if algo_result is None:
        return findings

    kex_algos, ciphers, macs, host_key_type, host_key_bits = algo_result

    # ---- Weak KEX ----
    weak_kex_found = [k for k in kex_algos if k in _WEAK_KEX]
    if weak_kex_found:
        findings.append(Finding(
            severity=Severity.HIGH,
            title=f"SSH weak key exchange algorithms supported on port {port}",
            host=host, port=port, protocol="ssh",
            category="SSH",
            description=(
                f"The SSH server supports weak key exchange algorithms: "
                f"{', '.join(weak_kex_found)}"
            ),
            explanation=(
                "Key exchange algorithms establish the shared session key. "
                "Algorithms using SHA-1 (e.g. diffie-hellman-group14-sha1) are deprecated. "
                "group1-sha1 uses 768-bit Oakley Group 1 which is considered broken."
            ),
            recommendation=(
                "In sshd_config, set:\n"
                "KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group16-sha512"
            ),
            evidence=f"Weak KEX advertised: {', '.join(weak_kex_found)}",
            confidence=Confidence.CONFIRMED,
            tags=["ssh", "kex", "weak-algorithm"],
        ))

    # ---- Weak ciphers ----
    weak_ciphers_found = [c for c in ciphers if c in _WEAK_CIPHERS]
    if weak_ciphers_found:
        sev = Severity.CRITICAL if "none" in weak_ciphers_found or "arcfour" in " ".join(weak_ciphers_found) else Severity.HIGH
        findings.append(Finding(
            severity=sev,
            title=f"SSH weak ciphers supported on port {port}",
            host=host, port=port, protocol="ssh",
            category="SSH",
            description=(
                f"The SSH server supports weak or broken ciphers: "
                f"{', '.join(weak_ciphers_found)}"
            ),
            explanation=(
                "RC4 (arcfour) is a broken stream cipher banned by RFC 7465. "
                "3DES-CBC is vulnerable to Sweet32 birthday attacks. "
                "The 'none' cipher transmits data completely unencrypted."
            ),
            recommendation=(
                "In sshd_config, set:\n"
                "Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,chacha20-poly1305@openssh.com"
            ),
            evidence=f"Weak ciphers advertised: {', '.join(weak_ciphers_found)}",
            confidence=Confidence.CONFIRMED,
            tags=["ssh", "cipher", "weak-algorithm"],
        ))

    # ---- Weak MACs ----
    weak_macs_found = [m for m in macs if m in _WEAK_MACS]
    if weak_macs_found:
        findings.append(Finding(
            severity=Severity.HIGH,
            title=f"SSH weak MAC algorithms supported on port {port}",
            host=host, port=port, protocol="ssh",
            category="SSH",
            description=(
                f"The SSH server supports weak MAC algorithms: "
                f"{', '.join(weak_macs_found)}"
            ),
            explanation=(
                "HMAC-MD5 and HMAC-SHA1 are deprecated and considered weak for "
                "integrity protection. Modern SSH should use ETM (encrypt-then-MAC) variants."
            ),
            recommendation=(
                "In sshd_config, set:\n"
                "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"
            ),
            evidence=f"Weak MACs advertised: {', '.join(weak_macs_found)}",
            confidence=Confidence.CONFIRMED,
            tags=["ssh", "mac", "weak-algorithm"],
        ))

    # ---- Weak host key ----
    if host_key_type == "ssh-dss":
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title=f"SSH DSA host key in use on port {port}",
            host=host, port=port, protocol="ssh",
            category="SSH",
            description="The SSH server uses a DSA (ssh-dss) host key. DSA is deprecated and limited to 1024 bits.",
            explanation=(
                "DSA keys are limited to 1024 bits and use SHA-1, both of which are "
                "considered weak by modern standards. OpenSSH disabled DSA keys by default since version 7.0."
            ),
            recommendation="Replace the DSA host key with an Ed25519 or RSA-4096 key.",
            evidence=f"Host key type: {host_key_type}",
            confidence=Confidence.CONFIRMED,
            tags=["ssh", "host-key", "dsa"],
        ))
    elif host_key_type == "ssh-rsa" and host_key_bits and host_key_bits < 2048:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title=f"SSH RSA host key too small ({host_key_bits} bits) on port {port}",
            host=host, port=port, protocol="ssh",
            category="SSH",
            description=f"The SSH server's RSA host key is only {host_key_bits} bits.",
            explanation=(
                "RSA keys smaller than 2048 bits are considered weak. "
                "NIST recommends a minimum of 2048 bits, with 4096 preferred."
            ),
            recommendation="Regenerate the SSH host key with at least 2048 bits: ssh-keygen -t rsa -b 4096",
            evidence=f"Host key: {host_key_type} {host_key_bits} bits",
            confidence=Confidence.CONFIRMED,
            tags=["ssh", "host-key", "rsa", "weak-key"],
        ))

    return findings


def run_ssh_checks(host: str, open_ports: List[int], timeout: float = 8.0) -> List[Finding]:
    """Run SSH checks on all SSH ports discovered for a host.

    Args:
        host:       IP address.
        open_ports: List of open TCP ports from the scan.
        timeout:    Connection timeout.

    Returns:
        List of Finding objects.
    """
    findings: List[Finding] = []
    for port in open_ports:
        if port in SSH_PORTS:
            logger.debug(f"SSH check: {host}:{port}")
            try:
                findings.extend(check_ssh(host, port, timeout))
            except Exception as e:
                logger.debug(f"SSH check error {host}:{port}: {e}")
    return findings
