"""
NetWatch Port Scanner Orchestrator.

Uses masscan for fast initial port discovery when available, then runs
nmap service detection only on discovered open ports. Falls back silently
to plain nmap when masscan is not installed.

Pipeline when masscan is available:
  1. masscan --rate <rate> -p 1-65535 <target>  → discover all open ports
  2. nmap -sV -p <discovered_ports> <target>    → service version detection
  This is dramatically faster on large networks as masscan is ~1000x faster
  at port discovery than nmap.

Fallback when masscan is NOT available:
  - Uses NetworkScanner (nmap) exactly as before
  - No error, no warning to user
  - Behaviour is identical from the caller's perspective

Rate limiting (packets per second):
  - Default: 1000 pps (safe for home networks)
  - STEALTH profile: 100 pps (reduced noise)
  - FULL profile: 1000 pps
  - Cap: 5000 pps (never exceeded regardless of profile)

Installation (optional):
  sudo apt install masscan

Exports:
  PortScanOrchestrator: Drop-in replacement for NetworkScanner
"""

import logging
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Callable, Dict, List, Optional

from config.settings import Settings, SCAN_PROFILES, MASSCAN_RATES
from core.scanner import NetworkScanner, ScanResult

logger = logging.getLogger(__name__)

_MASSCAN_MAX_RATE = 5000  # Hard cap — never exceed this


def _masscan_available() -> bool:
    """Return True if masscan binary is on PATH."""
    return shutil.which("masscan") is not None


def _run_masscan(target: str, rate: int, timeout: int = 300) -> Dict[str, List[int]]:
    """Run masscan and return discovered open ports per host.

    Args:
        target:  CIDR, IP range, or single host.
        rate:    Packets per second (capped at _MASSCAN_MAX_RATE).
        timeout: Subprocess timeout in seconds.

    Returns:
        {ip_address: [open_port, ...]} for all discovered hosts.
        Empty dict on any failure.
    """
    rate = min(rate, _MASSCAN_MAX_RATE)
    cmd = [
        "masscan",
        target,
        "--rate", str(rate),
        "-p", "1-65535",
        "-oX", "-",      # XML to stdout
        "--wait", "3",   # wait 3 s after last packet before exiting
    ]
    logger.info(f"masscan: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            text=True,
        )
        # masscan exits 0 on success; treat any output as worth parsing
        return _parse_masscan_xml(result.stdout)
    except subprocess.TimeoutExpired:
        logger.warning("masscan timed out — falling back to nmap")
        return {}
    except FileNotFoundError:
        logger.debug("masscan binary not found")
        return {}
    except Exception as e:
        logger.debug(f"masscan execution error: {e}")
        return {}


def _parse_masscan_xml(xml_str: str) -> Dict[str, List[int]]:
    """Parse masscan XML output into {host: [open_ports]}.

    Handles partial output (masscan may write an incomplete XML document
    if it exits early). Unknown parse errors are silenced.
    """
    hosts: Dict[str, List[int]] = {}
    if not xml_str or not xml_str.strip():
        return hosts

    # masscan XML may be missing the closing </nmaprun> tag
    text = xml_str.strip()
    if not text.endswith("</nmaprun>"):
        text += "\n</nmaprun>"

    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        logger.debug(f"masscan XML parse error: {e}")
        return hosts

    for host_el in root.findall("host"):
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "").strip()
        if not ip:
            continue

        ports_el = host_el.find("ports")
        if ports_el is None:
            continue

        port_list: List[int] = []
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            portid = port_el.get("portid", "")
            if portid.isdigit():
                port_list.append(int(portid))

        if port_list:
            if ip in hosts:
                hosts[ip].extend(port_list)
            else:
                hosts[ip] = port_list

    logger.info(
        f"masscan discovered {sum(len(v) for v in hosts.values())} open ports "
        f"across {len(hosts)} hosts"
    )
    return hosts


class PortScanOrchestrator:
    """Drop-in replacement for NetworkScanner that uses masscan when available.

    API is identical to NetworkScanner — callers need no changes.

    When masscan is present:
      - Uses masscan for fast port discovery across the entire target
      - Runs nmap service detection only on the discovered open ports
      - Much faster on large networks (masscan is ~1000x faster than nmap
        for raw port discovery)

    When masscan is absent:
      - Delegates directly to NetworkScanner
      - Identical behaviour, no warnings shown to user
    """

    def __init__(self, settings: Optional[Settings] = None):
        self._settings = settings or Settings()
        self._nmap = NetworkScanner(settings=self._settings)
        self._use_masscan = _masscan_available()

        if self._use_masscan:
            logger.info("masscan detected — using masscan+nmap pipeline for port discovery")

    def set_progress_callback(self, callback: Callable) -> None:
        """Forward progress callback to the underlying nmap scanner."""
        self._nmap.set_progress_callback(callback)

    def scan(
        self,
        target: str,
        profile: str = "QUICK",
        arguments: Optional[str] = None,
    ) -> ScanResult:
        """Scan target using the best available method.

        Args:
            target:    IP, CIDR, or range.
            profile:   Scan profile (QUICK, FULL, STEALTH, PING, IOT, SMB).
            arguments: Optional custom nmap arguments (overrides profile).

        Returns:
            ScanResult identical in structure to NetworkScanner.scan().
        """
        # If custom arguments provided or masscan not available, use nmap directly
        if arguments or not self._use_masscan:
            return self._nmap.scan(target, profile, arguments=arguments)

        # PING profile is host-discovery only — no ports to pass to masscan
        if profile == "PING":
            return self._nmap.scan(target, profile)

        return self._scan_masscan_nmap(target, profile)

    def _scan_masscan_nmap(self, target: str, profile: str) -> ScanResult:
        """Run masscan discovery then nmap service detection on found ports."""
        rate = MASSCAN_RATES.get(profile, MASSCAN_RATES.get("FULL", 1000))
        rate = min(rate, _MASSCAN_MAX_RATE)

        discovered = _run_masscan(target, rate)

        if not discovered:
            # masscan found nothing (or failed) — fall back to nmap
            logger.info("masscan found no open ports — falling back to nmap")
            return self._nmap.scan(target, profile)

        # Collect union of all open ports across all discovered hosts
        all_ports = set()
        for ports in discovered.values():
            all_ports.update(ports)

        if not all_ports:
            return self._nmap.scan(target, profile)

        # Build nmap arguments: use profile's base flags but replace port discovery
        # with the exact ports masscan found, and ensure -sV is included.
        base_args = SCAN_PROFILES.get(profile, SCAN_PROFILES["FULL"])

        # Remove flags that conflict with explicit port list or that masscan replaces
        skip_tokens = {"-F"}           # -F = fast scan (top 100 ports) — we specify ports
        kept = [t for t in base_args.split() if t not in skip_tokens]

        # Ensure service version detection
        if "-sV" not in kept and "-A" not in kept:
            kept.append("-sV")

        ports_str = ",".join(str(p) for p in sorted(all_ports))
        kept.extend(["-p", ports_str])

        nmap_args = " ".join(kept)
        logger.info(
            f"nmap service scan: {len(all_ports)} ports on {target} "
            f"(discovered by masscan)"
        )
        return self._nmap.scan(target, profile, arguments=nmap_args)

    # ---- Convenience methods (mirror NetworkScanner) ----

    def quick_scan(self, target: str) -> ScanResult:
        return self.scan(target, profile="QUICK")

    def full_scan(self, target: str) -> ScanResult:
        return self.scan(target, profile="FULL")

    def stealth_scan(self, target: str) -> ScanResult:
        return self.scan(target, profile="STEALTH")

    def ping_sweep(self, target: str) -> List[str]:
        result = self.scan(target, profile="PING")
        return [ip for ip, host in result.hosts.items() if host.state == "up"]
