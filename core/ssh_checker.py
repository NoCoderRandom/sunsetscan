"""
NetWatch SSH Deep Analysis Module.

Uses paramiko to perform deep SSH inspection beyond what nmap reports:
  - Precise SSH version extraction from banner
  - Weak key exchange algorithm detection
  - Weak cipher detection
  - Weak MAC algorithm detection
  - Host key type and size inspection

Fallback: raw socket KEXINIT inspection for devices that reject paramiko
  (e.g. Synology NAS). Sends a minimal SSH_MSG_KEXINIT and parses the
  server's response to extract algorithm lists without completing auth.

Findings produced:
    CRITICAL  - Extremely weak algorithms (arcfour/RC4, none cipher)
    HIGH      - Weak KEX (diffie-hellman-group1-sha1, diffie-hellman-group14-sha1)
                Weak MACs (md5, sha1 in hmac-md5, hmac-sha1)
    MEDIUM    - Weak host key (DSA, RSA < 2048 bits)
    LOW       - Algorithm enumeration failed (manual verification recommended)
    INFO      - SSH version and host key fingerprint
"""

import logging
import os
import socket
import struct
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
    """Grab the raw SSH identification string (first line sent by server).

    Returns:
        banner string (non-empty): SSH banner received normally
        "" (empty string):         Connection accepted but immediately closed without
                                   sending data (TCP wrappers / IP access control)
        None:                      Could not connect at all (port closed / timeout)
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(256)
            if not data:
                # Server accepted TCP connection but sent nothing before closing.
                # This is the tcpwrapped / TCP wrappers / hosts.deny pattern.
                return ""
            banner = data.decode("utf-8", errors="replace").strip()
            return banner
    except (ConnectionRefusedError, OSError) as e:
        logger.debug(f"SSH banner grab failed (connection error) {host}:{port}: {e}")
        return None
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
        logger.debug(f"SSH algorithm enumeration (paramiko) failed {host}:{port}: {e}")
        return None


def _get_ssh_algorithms_raw(
    host: str, port: int, timeout: float
) -> Optional[Tuple[List[str], List[str], List[str]]]:
    """
    Raw socket SSH KEXINIT inspection — fallback when paramiko is rejected.

    Sends an SSH identification string + minimal SSH_MSG_KEXINIT, then parses
    the server's SSH_MSG_KEXINIT to extract algorithm lists. Works on devices
    that reject unknown SSH clients mid-handshake (e.g. Synology NAS) because
    the server sends its KEXINIT before deciding to reject the client.

    Returns:
        (kex_algos, ciphers_s2c, macs_s2c) or None on failure.
        Note: host key type/bits are unavailable via this method.
    """

    def _encode_namelist(names: List[str]) -> bytes:
        s = ",".join(names).encode("ascii")
        return struct.pack(">I", len(s)) + s

    def _parse_namelist(data: bytes, offset: int) -> Tuple[List[str], int]:
        if offset + 4 > len(data):
            return [], offset
        length = struct.unpack_from(">I", data, offset)[0]
        offset += 4
        if length == 0:
            return [], offset
        if offset + length > len(data):
            return [], offset
        names_str = data[offset: offset + length].decode("ascii", errors="replace")
        names = [n.strip() for n in names_str.split(",") if n.strip()]
        return names, offset + length

    # Build our SSH_MSG_KEXINIT payload
    cookie = os.urandom(16)
    payload = (
        bytes([20])                                                           # SSH_MSG_KEXINIT
        + cookie
        + _encode_namelist(["curve25519-sha256", "diffie-hellman-group14-sha256"])  # kex
        + _encode_namelist(["ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519"])       # host key
        + _encode_namelist(["aes128-ctr", "aes256-ctr"])                            # enc c→s
        + _encode_namelist(["aes128-ctr", "aes256-ctr"])                            # enc s→c
        + _encode_namelist(["hmac-sha2-256"])                                       # mac c→s
        + _encode_namelist(["hmac-sha2-256"])                                       # mac s→c
        + _encode_namelist(["none"])                                                # compress c→s
        + _encode_namelist(["none"])                                                # compress s→c
        + _encode_namelist([])                                                      # lang c→s
        + _encode_namelist([])                                                      # lang s→c
        + bytes([0])                                                                # first_kex_packet_follows
        + struct.pack(">I", 0)                                                      # reserved
    )

    # SSH binary packet framing:
    # packet = packet_length(4) + padding_length(1) + payload + padding
    # packet_length = 1 + len(payload) + padding_length
    # padding must be at least 4 bytes and make total a multiple of 8
    block_size = 8
    raw_inner_len = 1 + len(payload)  # padding_length byte + payload
    padding_len = block_size - (raw_inner_len % block_size)
    if padding_len < 4:
        padding_len += block_size
    packet_len_val = 1 + len(payload) + padding_len
    packet = (
        struct.pack(">I", packet_len_val)
        + bytes([padding_len])
        + payload
        + os.urandom(padding_len)
    )

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            # Read server banner (terminated by \n)
            banner_data = b""
            while b"\n" not in banner_data and len(banner_data) < 512:
                chunk = sock.recv(64)
                if not chunk:
                    return None
                banner_data += chunk

            # Send our banner
            sock.sendall(b"SSH-2.0-NetWatch_1.0\r\n")

            # Send our KEXINIT
            sock.sendall(packet)

            # Read server's KEXINIT packet
            # SSH binary packet: 4-byte length header, then (length) bytes of body
            header = b""
            while len(header) < 4:
                chunk = sock.recv(4 - len(header))
                if not chunk:
                    return None
                header += chunk

            pkt_len = struct.unpack(">I", header)[0]
            if pkt_len < 2 or pkt_len > 65536:
                return None

            body = b""
            while len(body) < pkt_len:
                chunk = sock.recv(min(4096, pkt_len - len(body)))
                if not chunk:
                    return None
                body += chunk

            # body layout: [padding_len(1)][msg_type(1)][...]
            if len(body) < 2:
                return None

            msg_type = body[1]
            if msg_type != 20:  # SSH_MSG_KEXINIT
                logger.debug(f"SSH raw: expected KEXINIT (20), got msg_type={msg_type}")
                return None

            # After padding_len(1) + msg_type(1) + cookie(16) = 18 bytes
            # Come the 10 name-lists in this order:
            # 0: kex_algorithms
            # 1: server_host_key_algorithms
            # 2: encryption_algorithms_client_to_server
            # 3: encryption_algorithms_server_to_client  ← server preference
            # 4: mac_algorithms_client_to_server
            # 5: mac_algorithms_server_to_client          ← server preference
            # 6: compression_algorithms_client_to_server
            # 7: compression_algorithms_server_to_client
            # 8: languages_client_to_server
            # 9: languages_server_to_client
            offset = 18
            name_lists = []
            for _ in range(10):
                names, offset = _parse_namelist(body, offset)
                name_lists.append(names)

            if len(name_lists) < 6:
                return None

            kex = name_lists[0]
            ciphers = name_lists[3]   # server_to_client = server's offered ciphers
            macs = name_lists[5]      # server_to_client = server's offered MACs

            logger.debug(
                f"SSH raw KEXINIT {host}:{port}: "
                f"{len(kex)} KEX, {len(ciphers)} ciphers, {len(macs)} MACs"
            )
            return kex, ciphers, macs

    except Exception as e:
        logger.debug(f"SSH raw KEXINIT fallback failed {host}:{port}: {e}")
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

    # None = could not connect (port closed, timeout)
    if banner is None:
        return findings

    # "" = connection accepted but server sent nothing (TCP wrappers / access control)
    if banner == "":
        findings.append(Finding(
            severity=Severity.INFO,
            title=f"SSH port {port} open — banner not returned (access restricted from scanner IP)",
            host=host, port=port, protocol="ssh",
            category="SSH",
            description=(
                f"SSH port {port} accepted the TCP connection but did not send an SSH "
                f"identification string before closing. This indicates IP-based access control "
                f"(TCP wrappers or firewall rules) is blocking inspection from the scanner's IP."
            ),
            explanation=(
                "SSH servers using TCP wrappers (libwrap / hosts.allow / hosts.deny) or "
                "host-based firewall rules will accept the TCP handshake but immediately close "
                "the connection without sending their banner if the source IP is not permitted. "
                "The SSH service exists and is running, but cannot be inspected from this host."
            ),
            recommendation=(
                "Manually verify SSH algorithm configuration from a permitted IP:\n"
                "  ssh-audit <host>  (install via pip install ssh-audit)\n"
                "Ensure the SSH server uses modern algorithms and has SSHv1 disabled."
            ),
            evidence=f"Port {port}/tcp open, TCP connection accepted, no SSH banner received",
            confidence=Confidence.LIKELY,
            tags=["ssh", "banner", "access-restricted"],
        ))
        return findings

    # ---- Extract version info from banner (format: SSH-2.0-OpenSSH_8.9p1) ----
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
    if "SSH-1." in ssh_version:
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
            evidence=f"Banner: {ssh_version}",
            confidence=Confidence.CONFIRMED,
            tags=["ssh", "protocol-v1", "critical"],
        ))

    # ---- Algorithm enumeration — paramiko first, raw KEXINIT fallback ----
    algo_result = _get_ssh_algorithms(host, port, timeout)
    host_key_type = "unknown"
    host_key_bits = 0

    if algo_result is not None:
        kex_algos, ciphers, macs, host_key_type, host_key_bits = algo_result
    else:
        logger.debug(f"Paramiko enumeration failed for {host}:{port}, trying raw KEXINIT")
        raw_result = _get_ssh_algorithms_raw(host, port, timeout)
        if raw_result is not None:
            kex_algos, ciphers, macs = raw_result
        else:
            # Both methods failed — still report banner, add LOW advisory
            findings.append(Finding(
                severity=Severity.LOW,
                title=f"SSH algorithm enumeration failed on port {port} — manual verification recommended",
                host=host, port=port, protocol="ssh",
                category="SSH",
                description=(
                    f"SSH service detected on port {port} but algorithm enumeration failed. "
                    f"The server may use non-standard client restrictions or a custom SSH stack."
                ),
                explanation=(
                    "SSH algorithm enumeration identifies weak or outdated cryptographic settings. "
                    "Both paramiko and raw socket KEXINIT methods were attempted. "
                    "When enumeration fails, the cryptographic posture cannot be fully assessed."
                ),
                recommendation=(
                    "Manually verify SSH configuration:\n"
                    "  ssh -Q kex <host>\n"
                    "  ssh-audit <host>  (install via pip install ssh-audit)\n"
                    "Ensure the server uses modern algorithms and has SSHv1 disabled."
                ),
                evidence=(
                    f"Banner: {ssh_version}; "
                    f"Paramiko: connection rejected; "
                    f"Raw KEXINIT: no valid response"
                ),
                confidence=Confidence.CONFIRMED,
                tags=["ssh", "enumeration-failed"],
            ))
            return findings

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

    # ---- Weak host key (only available from paramiko) ----
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
