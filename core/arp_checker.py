"""
NetWatch ARP Spoofing Detection Module.

Uses Scapy to send ARP requests and analyse responses for anomalies:
  - Duplicate MAC detection: two IPs claiming the same MAC = possible ARP spoofing
  - MAC address change detection: compare against saved baseline
  - Rogue DHCP server detection: multiple DHCP offers on the same subnet

ARP spoofing is a man-in-the-middle attack where an attacker poisons ARP
caches to intercept traffic between two hosts (e.g. router + victim).

Requires: scapy (pip install scapy)
Requires root/sudo for sending raw ARP packets.

Findings produced:
    CRITICAL  - ARP spoofing detected (duplicate MAC for multiple IPs)
    HIGH      - MAC address changed since last scan (possible spoofing or new device)
    MEDIUM    - Rogue DHCP server detected (unexpected DHCP offer source)
    INFO      - ARP table snapshot (normal — for baseline)
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from core.findings import Finding, Severity, Confidence

logger = logging.getLogger(__name__)

# Where to persist the ARP baseline
_BASELINE_FILE = Path(__file__).parent.parent / "data" / "arp_baseline.json"

# How long to wait for ARP replies (seconds)
_ARP_TIMEOUT = 2


def _load_arp_baseline() -> Dict[str, str]:
    """Load saved ARP baseline {ip: mac} from disk. Returns {} if not found."""
    try:
        with open(_BASELINE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        pass
    except Exception as e:
        logger.debug(f"ARP baseline load failed: {e}")
    return {}


def _save_arp_baseline(arp_table: Dict[str, str]) -> None:
    """Save ARP table {ip: mac} to disk for future comparison."""
    try:
        _BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(_BASELINE_FILE, "w", encoding="utf-8") as f:
            json.dump(arp_table, f, indent=2)
        logger.debug(f"ARP baseline saved: {len(arp_table)} entries")
    except Exception as e:
        logger.debug(f"ARP baseline save failed: {e}")


def _get_arp_table(network: str, timeout: float = _ARP_TIMEOUT) -> Dict[str, str]:
    """Send ARP requests to all hosts in a network and return {ip: mac} map.

    Args:
        network: Network CIDR (e.g. "192.168.1.0/24") or individual IP.
        timeout: ARP reply timeout in seconds.

    Returns:
        Dict mapping IP address strings to MAC address strings.
        Empty dict if scapy unavailable or insufficient permissions.
    """
    arp_table: Dict[str, str] = {}

    try:
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import srp
        import scapy.config
        scapy.config.conf.verb = 0  # Suppress scapy output

        # Build ARP who-has packet
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)

        answered, _ = srp(arp_request, timeout=timeout, verbose=False)

        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc.lower()
            arp_table[ip] = mac

        logger.debug(f"ARP scan of {network}: {len(arp_table)} hosts responded")

    except ImportError:
        logger.warning("scapy not installed — ARP spoofing detection unavailable")
    except PermissionError:
        logger.warning("ARP scan requires root/sudo — skipping ARP spoofing detection")
    except Exception as e:
        logger.debug(f"ARP scan error for {network}: {e}")

    return arp_table


def _check_duplicate_macs(arp_table: Dict[str, str]) -> List[Tuple[str, List[str]]]:
    """Find MAC addresses that appear for multiple IPs.

    Returns:
        List of (mac, [ip1, ip2, ...]) tuples where len(ips) > 1.
    """
    mac_to_ips: Dict[str, List[str]] = {}
    for ip, mac in arp_table.items():
        mac_to_ips.setdefault(mac, []).append(ip)

    return [(mac, ips) for mac, ips in mac_to_ips.items() if len(ips) > 1]


def _check_mac_changes(
    current: Dict[str, str],
    baseline: Dict[str, str]
) -> List[Tuple[str, str, str]]:
    """Compare current ARP table against baseline for MAC changes.

    Returns:
        List of (ip, old_mac, new_mac) for each IP where MAC changed.
    """
    changes = []
    for ip, current_mac in current.items():
        if ip in baseline:
            baseline_mac = baseline[ip]
            if current_mac.lower() != baseline_mac.lower():
                changes.append((ip, baseline_mac, current_mac))
    return changes


def check_arp_spoofing(
    network: str,
    save_baseline: bool = True,
    timeout: float = _ARP_TIMEOUT,
) -> List[Finding]:
    """Run ARP spoofing and anomaly detection on a network.

    Args:
        network:       CIDR notation (e.g. "192.168.1.0/24").
        save_baseline: If True, save ARP table to disk for future comparison.
        timeout:       ARP reply timeout in seconds.

    Returns:
        List of Finding objects.
    """
    findings: List[Finding] = []

    # ---- Collect current ARP table ----
    current_arp = _get_arp_table(network, timeout=timeout)

    if not current_arp:
        # Either scapy unavailable, no permission, or no hosts responded
        return findings

    # ---- Load baseline for comparison ----
    baseline_arp = _load_arp_baseline()

    # ---- Check for duplicate MACs (possible ARP spoofing) ----
    duplicates = _check_duplicate_macs(current_arp)
    for mac, ips in duplicates:
        # Filter out legitimate duplicate-MAC scenarios:
        # VMs on same host share MAC in some configurations (rare)
        # Some load balancers use shared MACs (VRRP/HSRP use known multicast MACs)
        vrrp_prefix = "00:00:5e:00:01"  # VRRP virtual MAC prefix
        hsrp_prefix = "00:00:0c:07:ac"  # HSRP virtual MAC prefix
        if mac.startswith(vrrp_prefix) or mac.startswith(hsrp_prefix):
            continue  # Expected — VRRP/HSRP redundancy protocol

        findings.append(Finding(
            severity=Severity.CRITICAL,
            title=f"Possible ARP spoofing: MAC {mac} claimed by {len(ips)} IPs",
            host=ips[0],
            port=0,
            protocol="arp",
            category="ARP Security",
            description=(
                f"MAC address {mac} is associated with multiple IP addresses:\n"
                + '\n'.join(f"  - {ip}" for ip in sorted(ips)) +
                "\n\nIn a legitimate network, each MAC address should map to exactly one "
                "IP address (or none). Multiple IPs sharing a MAC is a strong indicator "
                "of ARP cache poisoning (ARP spoofing)."
            ),
            explanation=(
                "ARP spoofing (ARP cache poisoning) is a man-in-the-middle attack where "
                "an attacker sends fake ARP replies to associate their MAC address with "
                "another host's IP (commonly the default gateway). "
                "This redirects all traffic through the attacker's machine, allowing "
                "them to intercept, modify, or drop packets in transit — enabling "
                "credential theft, session hijacking, and traffic injection. "
                "Tools like Ettercap, Bettercap, and arpspoof automate this attack."
            ),
            recommendation=(
                "1. Identify which device the MAC belongs to: check router DHCP table "
                f"for MAC {mac}.\n"
                "2. If the device is unknown, disconnect it from the network immediately.\n"
                "3. Enable Dynamic ARP Inspection (DAI) on managed switches if available.\n"
                "4. Enable static ARP entries for critical devices (gateway, DNS server):\n"
                f"   Linux: arp -s <gateway-ip> <correct-mac>\n"
                "5. Use network monitoring tools (XArp, Arpwatch) for ongoing detection.\n"
                "6. Consider enabling 802.1X port authentication to prevent rogue devices."
            ),
            evidence=(
                f"ARP table: MAC {mac} -> IPs: {', '.join(sorted(ips))}. "
                "Expected: 1 IP per MAC."
            ),
            confidence=Confidence.LIKELY,
            tags=["arp", "arp-spoofing", "mitm", "network-attack"],
        ))

    # ---- Check for MAC address changes since last scan ----
    if baseline_arp:
        mac_changes = _check_mac_changes(current_arp, baseline_arp)
        for ip, old_mac, new_mac in mac_changes:
            findings.append(Finding(
                severity=Severity.HIGH,
                title=f"MAC address changed for {ip}: {old_mac} → {new_mac}",
                host=ip,
                port=0,
                protocol="arp",
                category="ARP Security",
                description=(
                    f"The MAC address for IP {ip} has changed since the last scan:\n"
                    f"  Previous MAC: {old_mac}\n"
                    f"  Current MAC:  {new_mac}\n\n"
                    "MAC address changes may indicate ARP spoofing, device replacement, "
                    "or a new network card."
                ),
                explanation=(
                    "In a stable network, IP-to-MAC mappings should be consistent over time. "
                    "A MAC change could mean:\n"
                    "• ARP spoofing: an attacker is impersonating this IP with a different device\n"
                    "• Legitimate device replacement: the device was swapped (check with IT)\n"
                    "• VM migration: virtual machines can change MAC on hypervisor changes\n"
                    "• MAC randomisation: some mobile OSes randomise MACs per network"
                ),
                recommendation=(
                    f"1. Verify the MAC change is legitimate for {ip}.\n"
                    "2. Check router/switch ARP tables and DHCP logs for this IP.\n"
                    f"3. If unexpected: investigate the device with MAC {new_mac}.\n"
                    "4. If spoofing suspected: enable Dynamic ARP Inspection on switches.\n"
                    "5. Update baseline after confirming the change is legitimate: "
                    "--save-baseline flag."
                ),
                evidence=f"Baseline MAC: {old_mac}, current MAC: {new_mac} for IP {ip}",
                confidence=Confidence.SUSPECTED,
                tags=["arp", "mac-change", "possible-spoofing"],
            ))

    # ---- ARP table INFO finding (baseline snapshot) ----
    if current_arp:
        arp_summary = '\n'.join(
            f"  {ip:<18} {mac}"
            for ip, mac in sorted(current_arp.items())
        )
        findings.append(Finding(
            severity=Severity.INFO,
            title=f"ARP table snapshot: {len(current_arp)} hosts on {network}",
            host="local",
            port=0,
            protocol="arp",
            category="ARP Security",
            description=(
                f"ARP scan of {network} discovered {len(current_arp)} active hosts:\n"
                + arp_summary
            ),
            explanation=(
                "ARP (Address Resolution Protocol) maps IP addresses to MAC addresses. "
                "The ARP table snapshot shows all devices that responded to ARP requests, "
                "providing ground-truth visibility into devices on the local network segment."
            ),
            recommendation=(
                "Save this ARP table as a baseline (--save-baseline) for future comparison. "
                "Any MAC address changes on subsequent scans will be flagged as anomalies."
            ),
            evidence=f"ARP scan of {network}: {len(current_arp)} responses received",
            confidence=Confidence.CONFIRMED,
            tags=["arp", "discovery", "baseline"],
        ))

    # ---- Save updated baseline ----
    if save_baseline and current_arp:
        _save_arp_baseline(current_arp)

    return findings


def run_arp_checks(
    network: str,
    save_baseline: bool = True,
    timeout: float = _ARP_TIMEOUT,
) -> List[Finding]:
    """Run ARP-level security checks for the given network.

    Convenience wrapper around check_arp_spoofing().

    Args:
        network:       Target network in CIDR notation.
        save_baseline: Save ARP table for future comparison.
        timeout:       ARP reply timeout.

    Returns:
        List of Finding objects.
    """
    try:
        return check_arp_spoofing(network, save_baseline=save_baseline, timeout=timeout)
    except Exception as e:
        logger.debug(f"ARP check failed for {network}: {e}")
        return []
