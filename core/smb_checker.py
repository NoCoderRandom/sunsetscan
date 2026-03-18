"""
NetWatch SMB Security Checker.

Deep SMB/CIFS analysis using impacket:
  - SMBv1 protocol detection (CRITICAL — EternalBlue attack surface)
  - Windows version extraction via SMB negotiation → EOL check
  - SMB signing status (HIGH if disabled on non-DC)
  - Anonymous/guest share enumeration (HIGH if accessible)
  - MS17-010 EternalBlue vulnerability probe (CRITICAL)
  - NTLM information disclosure (OS/domain via NTLM challenge)

Uses impacket for low-level SMB protocol access.

Findings produced:
    CRITICAL  - SMBv1 enabled (EternalBlue attack surface)
    CRITICAL  - MS17-010 EternalBlue vulnerability confirmed
    HIGH      - Anonymous/guest share access allowed
    HIGH      - SMB signing disabled
    MEDIUM    - NTLM authentication information disclosure
    INFO      - Windows version and domain name extracted
"""

import logging
import socket
from typing import List, Optional, Tuple

from core.findings import Finding, Severity, Confidence

logger = logging.getLogger(__name__)

SMB_PORT = 445
SMB_TIMEOUT = 5  # seconds

# Default shares that are expected — only flag non-default ones as guest-accessible
_DEFAULT_SHARE_NAMES = {'IPC$', 'ADMIN$', 'C$', 'D$', 'E$', 'PRINT$'}


def _check_smb_connection(host: str, port: int = SMB_PORT, timeout: float = SMB_TIMEOUT):
    """Test if SMB port is reachable. Returns True/False."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def _get_smb_info(host: str, timeout: float = SMB_TIMEOUT) -> Optional[dict]:
    """Connect via impacket and negotiate SMB, returning protocol info.

    Returns a dict with keys:
        smb_version: int (1 or 2 or 3)
        dialect: str  (e.g. "SMB2_DIALECT_002")
        signing: bool
        os_version: str (e.g. "Windows 10 Pro 19041")
        server_name: str
        domain: str
        smb1_supported: bool
    Returns None on connection failure.
    """
    try:
        from impacket.smbconnection import SMBConnection
        from impacket import smb as impacket_smb

        conn = SMBConnection(host, host, sess_port=SMB_PORT, timeout=timeout)
        info = {}

        # After connect(), negotiate info is available
        try:
            # Try to get server OS info
            info['server_name'] = conn.getServerName() or ""
            info['domain'] = conn.getServerDomain() or ""
            info['os_version'] = conn.getServerOS() or ""
            info['dialect'] = conn.getDialect()
            info['signing'] = conn.isSigningRequired()
            # Determine SMB version from dialect
            dialect = info['dialect']
            if dialect in (0x0300, 0x0302, 0x0311):
                info['smb_version'] = 3
            elif dialect in (0x0200, 0x0202, 0x0210):
                info['smb_version'] = 2
            else:
                info['smb_version'] = 1
            info['smb1_supported'] = (info['smb_version'] == 1)
        except Exception:
            info.setdefault('server_name', "")
            info.setdefault('domain', "")
            info.setdefault('os_version', "")
            info.setdefault('dialect', 0)
            info.setdefault('signing', True)
            info.setdefault('smb_version', 2)
            info.setdefault('smb1_supported', False)

        conn.close()
        return info

    except ImportError:
        logger.warning("impacket not installed — SMB deep analysis unavailable")
        return None
    except Exception as e:
        logger.debug(f"SMB connect failed {host}: {e}")
        # Try raw SMB1 negotiate to detect SMBv1
        smb1_result = _probe_smb1(host, timeout)
        if smb1_result is not None:
            return smb1_result
        return None


def _probe_smb1(host: str, timeout: float = SMB_TIMEOUT) -> Optional[dict]:
    """Send a raw SMBv1 Negotiate Protocol Request to detect if SMBv1 is enabled.

    Returns partial info dict if SMBv1 responds, None otherwise.
    """
    # SMBv1 Negotiate Protocol Request bytes
    # NetBIOS session + SMB header + Negotiate command
    negotiate_pkt = (
        b'\x00\x00\x00\x2f'          # NetBIOS length (47 bytes follow)
        b'\xffSMB'                   # SMB magic
        b'\x72'                      # Command: Negotiate Protocol
        b'\x00\x00\x00\x00'         # NT Status
        b'\x18'                      # Flags
        b'\x01\x28'                  # Flags2
        b'\x00\x00'                  # PID high
        b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Security signature
        b'\x00\x00'                  # Reserved
        b'\xff\xff'                  # TID
        b'\x00\x00'                  # PID
        b'\x00\x00'                  # UID
        b'\x00\x00'                  # MID
        # Negotiate body
        b'\x00'                      # Word count
        b'\x0c\x00'                  # Byte count (12)
        b'\x02NT LM 0.12\x00'       # Dialect: NT LM 0.12 (SMBv1)
    )
    try:
        s = socket.create_connection((host, SMB_PORT), timeout=timeout)
        s.sendall(negotiate_pkt)
        response = s.recv(256)
        s.close()
        # If we get an SMB response header back (starts with \xffSMB), SMBv1 responded
        if len(response) >= 8 and response[4:8] == b'\xffSMB':
            logger.debug(f"SMBv1 probe: {host} responded to SMBv1 Negotiate")
            return {
                'smb_version': 1,
                'smb1_supported': True,
                'dialect': 0,
                'signing': True,
                'os_version': '',
                'server_name': '',
                'domain': '',
            }
    except Exception as e:
        logger.debug(f"SMBv1 raw probe failed {host}: {e}")
    return None


def _check_ms17_010(host: str, timeout: float = SMB_TIMEOUT) -> bool:
    """Check if host is vulnerable to MS17-010 (EternalBlue).

    Sends the specific SMB transaction request used to detect the vulnerability.
    Returns True if the host appears vulnerable.
    This is a detection probe only — does NOT exploit.
    """
    try:
        # Establish SMBv1 session and send MS17-010 detection request
        # The specific probe: TRANSACTION2 request with invalid setup count
        # A vulnerable Windows host returns ERROR_SUCCESS on this malformed request
        sock = socket.create_connection((host, SMB_PORT), timeout=timeout)

        # Step 1: Send SMBv1 Negotiate
        negotiate = (
            b'\x00\x00\x00\x2f\xffSMB\x72'
            b'\x00\x00\x00\x00\x18\x01\x28'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\xff\xff\x00\x00\x00\x00'
            b'\x00\x00\x00\x0c\x00'
            b'\x02NT LM 0.12\x00'
        )
        sock.sendall(negotiate)
        resp1 = sock.recv(1024)

        if len(resp1) < 36 or resp1[4:8] != b'\xffSMB':
            sock.close()
            return False

        # Step 2: Session Setup (anonymous)
        setup = (
            b'\x00\x00\x00\x63\xffSMB\x73'
            b'\x00\x00\x00\x00\x18\x07\xc0'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\xff\xff\x00\x00\x00\x00'
            b'\x00\x0d\xff\x00\x00\x00\xff\xff'
            b'\x02\x00\x01\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x26\x00'
            b'\x00\x40\x00\x60\x20\x06\x06\x2b'
            b'\x06\x01\x05\x05\x02\xa0\x16\x30'
            b'\x14\xa0\x12\x30\x10\x30\x0e\x06'
            b'\x0a\x2b\x06\x01\x04\x01\x82\x37'
            b'\x02\x02\x0a\x00\x00\x00\x00\x00'
            b'\x09\x01\x20\x00\x57\x69\x6e\x64'
            b'\x6f\x77\x73\x20\x32\x30\x30\x30'
            b'\x20\x32\x31\x39\x35\x00'
        )
        sock.sendall(setup)
        resp2 = sock.recv(1024)

        if len(resp2) < 36 or resp2[4:8] != b'\xffSMB':
            sock.close()
            return False

        # Extract UID from session setup response
        uid = resp2[32:34]

        # Step 3: Tree Connect to IPC$
        tree_pkt = (
            b'\x00\x00\x00\x47\xffSMB\x75'
            b'\x00\x00\x00\x00\x18\x07\xc0'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00' + uid +
            b'\x00\x00'
            b'\x04\xff\x00\x00\x00\x00\x01\x00'
            b'\x1a\x00' +
            b'\\\\' + host.encode() + b'\\IPC$\x00' +
            b'?????\x00'
        )
        sock.sendall(tree_pkt)
        resp3 = sock.recv(1024)

        if len(resp3) < 36:
            sock.close()
            return False

        # Extract TID
        tid = resp3[28:30]

        # Step 4: Send the MS17-010 detection TRANSACTION2 probe
        # This specific request triggers the bug path in vulnerable Windows
        trans2_probe = (
            b'\x00\x00\x00\x4f\xffSMB\x32'
            b'\x00\x00\x00\x00\x18\x07\xc0'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00' + tid + uid +
            b'\x00\x00'
            b'\x0f\x00\x00\x00\x00\x01\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x4e\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x0e\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
        )
        sock.sendall(trans2_probe)
        resp4 = sock.recv(1024)
        sock.close()

        # Vulnerable hosts return STATUS_SUCCESS (0x00000000) on this probe
        # Patched hosts return STATUS_INVALID_PARAMETER or similar error
        if len(resp4) >= 13 and resp4[4:8] == b'\xffSMB':
            nt_status = int.from_bytes(resp4[9:13], 'little')
            # 0x00000000 = STATUS_SUCCESS (vulnerable)
            # 0x00010002 = STATUS_INVALID_PARAMETER (patched)
            if nt_status == 0x00000000:
                logger.info(f"MS17-010: {host} appears vulnerable (STATUS_SUCCESS on probe)")
                return True

    except Exception as e:
        logger.debug(f"MS17-010 probe failed {host}: {e}")

    return False


def _enum_shares_anonymous(host: str, timeout: float = SMB_TIMEOUT) -> List[str]:
    """Try to enumerate shares with anonymous/guest access.

    Returns list of share names accessible without credentials.
    """
    shares = []
    try:
        from impacket.smbconnection import SMBConnection

        conn = SMBConnection(host, host, sess_port=SMB_PORT, timeout=timeout)
        # Anonymous login (empty username/password)
        conn.login('', '')
        raw_shares = conn.listShares()
        for share in raw_shares:
            name = share['shi1_netname'][:-1] if share['shi1_netname'].endswith('\x00') else share['shi1_netname']
            shares.append(name)
        conn.close()
    except Exception as e:
        logger.debug(f"Anonymous share enum failed {host}: {e}")
    return shares


def check_smb(host: str, port: int = SMB_PORT, timeout: float = SMB_TIMEOUT) -> List[Finding]:
    """Run SMB security checks for a single host.

    Args:
        host:    IP address.
        port:    SMB port (default 445).
        timeout: Connection timeout.

    Returns:
        List of Finding objects.
    """
    findings: List[Finding] = []

    if not _check_smb_connection(host, port, timeout):
        return findings

    # ---- Get SMB protocol info ----
    smb_info = _get_smb_info(host, timeout)

    if smb_info is None:
        # Could not connect at all — not an SMB host
        return findings

    # ---- SMBv1 detection ----
    if smb_info.get('smb1_supported') or smb_info.get('smb_version') == 1:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            title=f"SMBv1 protocol enabled on {host}",
            host=host, port=port, protocol="tcp",
            category="SMB",
            description=(
                f"SMBv1 (Server Message Block version 1) is enabled on {host}:{port}. "
                "SMBv1 is a 30-year-old protocol with numerous known critical vulnerabilities "
                "and was the attack vector for the WannaCry and NotPetya ransomware outbreaks."
            ),
            explanation=(
                "SMBv1 has no security features by modern standards — no encryption, "
                "no integrity checking, and it enables the EternalBlue exploit (MS17-010) "
                "used by WannaCry ransomware in 2017. It should be disabled on all modern "
                "systems as SMBv2 and v3 provide the same functionality with proper security."
            ),
            recommendation=(
                "1. Disable SMBv1 immediately:\n"
                "   PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false\n"
                "   Registry: Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters "
                "\\SMB1 = 0\n"
                "2. Apply all Windows security updates (MS17-010 patch if not yet applied).\n"
                "3. Block TCP 445 at network perimeter firewall to prevent external exposure.\n"
                "4. Consider upgrading to Windows 10/11 or Windows Server 2019+."
            ),
            evidence=f"SMB dialect negotiation returned version 1 response on port {port}",
            confidence=Confidence.CONFIRMED,
            tags=["smb", "smbv1", "eternalblue", "wannacry"],
        ))

    # ---- Windows version + EOL info ----
    os_version = smb_info.get('os_version', '')
    server_name = smb_info.get('server_name', '')
    domain = smb_info.get('domain', '')
    if os_version:
        findings.append(Finding(
            severity=Severity.INFO,
            title=f"Windows version detected via SMB: {os_version}",
            host=host, port=port, protocol="tcp",
            category="SMB",
            description=(
                f"SMB negotiation revealed the host operating system:\n"
                f"  OS:          {os_version}\n"
                f"  Server name: {server_name}\n"
                f"  Domain:      {domain}\n"
                "This information was provided without authentication (NTLM info disclosure)."
            ),
            explanation=(
                "SMB protocol reveals the server OS version during negotiation. "
                "This is an information disclosure that helps attackers identify vulnerable "
                "or end-of-life Windows versions to target with appropriate exploits."
            ),
            recommendation=(
                "Check if the detected Windows version is still supported by Microsoft. "
                "Older versions (Windows 7, Server 2008, Server 2012) have reached EOL "
                "and should be upgraded. "
                "Consider blocking NTLM info disclosure with registry settings if OS "
                "version exposure is a concern."
            ),
            evidence=f"SMB OS string: {os_version} | Server: {server_name} | Domain: {domain}",
            confidence=Confidence.CONFIRMED,
            tags=["smb", "ntlm", "info-disclosure", "windows-version"],
        ))

    # ---- SMB signing ----
    if not smb_info.get('signing', True):
        findings.append(Finding(
            severity=Severity.HIGH,
            title=f"SMB signing disabled on {host}",
            host=host, port=port, protocol="tcp",
            category="SMB",
            description=(
                f"SMB message signing is not required on {host}:{port}. "
                "Without signing, SMB traffic can be intercepted and modified by "
                "man-in-the-middle attackers."
            ),
            explanation=(
                "SMB signing ensures that each SMB message is digitally signed by both "
                "sender and receiver, preventing relay and tampering attacks. "
                "Without signing, NTLM relay attacks (pass-the-hash, relay attacks) "
                "can escalate a captured SMB session to full domain compromise. "
                "This is the attack vector used by tools like Responder/ntlmrelayx."
            ),
            recommendation=(
                "1. Enable SMB signing on all Windows servers:\n"
                "   Group Policy: Computer Configuration > Windows Settings > Security "
                "Settings > Local Policies > Security Options > "
                "'Microsoft network server: Digitally sign communications (always)' = Enabled\n"
                "2. Domain controllers enforce signing by default — check if this was disabled.\n"
                "3. Enable SMB signing on clients as well to prevent relay attacks."
            ),
            evidence=f"SMB negotiate response: signing_required=False on port {port}",
            confidence=Confidence.CONFIRMED,
            tags=["smb", "signing", "relay-attack", "ntlm"],
        ))

    # ---- Anonymous share enumeration ----
    anon_shares = _enum_shares_anonymous(host, timeout)
    # Filter out normal default shares (IPC$, ADMIN$, C$ are expected)
    guest_shares = [s for s in anon_shares if s.upper() not in _DEFAULT_SHARE_NAMES]
    if guest_shares:
        findings.append(Finding(
            severity=Severity.HIGH,
            title=f"Anonymous/guest SMB share access: {', '.join(guest_shares[:5])}",
            host=host, port=port, protocol="tcp",
            category="SMB",
            description=(
                f"The following SMB shares on {host} are accessible without authentication "
                f"(anonymous or guest access):\n"
                + '\n'.join(f"  - {s}" for s in guest_shares)
            ),
            explanation=(
                "Publicly accessible file shares allow any network user to read (and possibly "
                "write) files without needing a username or password. This can expose sensitive "
                "data, configuration files, or provide a foothold for lateral movement "
                "within the network."
            ),
            recommendation=(
                "1. Review each share listed above and remove anonymous/guest permissions.\n"
                "2. On Windows: Right-click share > Properties > Permissions — remove 'Everyone' "
                "and 'Guest' accounts.\n"
                "3. Disable the Guest account if not needed: "
                "net user guest /active:no\n"
                "4. Set registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"
                "\\RestrictNullSessAccess = 1"
            ),
            evidence=f"Anonymous login succeeded; accessible shares: {', '.join(guest_shares)}",
            confidence=Confidence.CONFIRMED,
            tags=["smb", "guest-access", "share-enumeration", "anonymous"],
        ))
    elif anon_shares:
        # Could enumerate shares (IPC$ accessible) — info-level disclosure
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title=f"SMB share enumeration possible (anonymous IPC$ access) on {host}",
            host=host, port=port, protocol="tcp",
            category="SMB",
            description=(
                f"Anonymous connection to IPC$ share succeeded on {host}. "
                f"Shares visible: {', '.join(anon_shares[:10])}. "
                "No non-default shares are guest-accessible."
            ),
            explanation=(
                "IPC$ (inter-process communication) share access via null session allows "
                "unauthenticated users to enumerate share names, and in older configurations, "
                "user accounts and group memberships. While less severe than guest file share "
                "access, it represents an information disclosure."
            ),
            recommendation=(
                "Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"
                "\\RestrictNullSessAccess = 1 to prevent null session IPC$ access."
            ),
            evidence=f"Anonymous IPC$ connection successful; shares: {', '.join(anon_shares[:5])}",
            confidence=Confidence.CONFIRMED,
            tags=["smb", "null-session", "info-disclosure"],
        ))

    # ---- MS17-010 EternalBlue check (only if SMBv1 is enabled) ----
    if smb_info.get('smb1_supported') or smb_info.get('smb_version') == 1:
        try:
            if _check_ms17_010(host, timeout):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title=f"MS17-010 EternalBlue vulnerability confirmed on {host}",
                    host=host, port=port, protocol="tcp",
                    category="CVE",
                    description=(
                        f"Host {host} responded to the MS17-010 detection probe in a way "
                        "consistent with a vulnerable, unpatched Windows system. "
                        "MS17-010 is the vulnerability exploited by WannaCry ransomware "
                        "and NotPetya in 2017."
                    ),
                    explanation=(
                        "CVE-2017-0144 (MS17-010, EternalBlue) is a critical SMBv1 vulnerability "
                        "in Windows that allows remote code execution without authentication. "
                        "It was developed by the NSA as a cyberweapon, leaked by Shadow Brokers, "
                        "and used in the WannaCry (2017) and NotPetya (2017) global ransomware "
                        "attacks that caused billions of dollars in damages. "
                        "Any machine with SMBv1 enabled and port 445 accessible is at risk."
                    ),
                    recommendation=(
                        "1. Apply Microsoft security update MS17-010 IMMEDIATELY:\n"
                        "   https://support.microsoft.com/en-us/topic/ms17-010-security-update\n"
                        "2. Disable SMBv1 (Set-SmbServerConfiguration -EnableSMB1Protocol $false).\n"
                        "3. Block TCP 445 at network perimeter.\n"
                        "4. If patching is not possible, isolate this host from the network.\n"
                        "5. Check for signs of compromise (unusual processes, lateral movement)."
                    ),
                    evidence=f"MS17-010 probe returned STATUS_SUCCESS on port {port}",
                    confidence=Confidence.LIKELY,
                    cve_ids=["CVE-2017-0144", "CVE-2017-0145"],
                    cvss_score=9.3,
                    tags=["smb", "ms17-010", "eternalblue", "rce", "wannacry", "cve"],
                ))
        except Exception as e:
            logger.debug(f"MS17-010 check failed {host}: {e}")

    return findings


def run_smb_checks(host: str, open_ports: List[int], timeout: float = SMB_TIMEOUT) -> List[Finding]:
    """Run SMB checks if port 445 or 139 is open.

    Args:
        host:       IP address.
        open_ports: Open TCP ports from nmap scan.
        timeout:    Connection timeout.

    Returns:
        List of Finding objects.
    """
    findings: List[Finding] = []

    smb_ports = [p for p in open_ports if p in (445, 139)]
    if not smb_ports:
        return findings

    logger.debug(f"SMB check: {host} (ports {smb_ports})")
    try:
        findings.extend(check_smb(host, port=SMB_PORT, timeout=timeout))
    except Exception as e:
        logger.debug(f"SMB check error {host}: {e}")

    return findings
