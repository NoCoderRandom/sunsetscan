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
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple

from config.settings import Settings, SCAN_PROFILES, MASSCAN_RATES
from core.scanner import NetworkScanner, ScanResult

logger = logging.getLogger(__name__)

_MASSCAN_MAX_RATE = 5000  # Hard cap — never exceed this


def _masscan_available() -> bool:
    """Return True if masscan binary is on PATH AND we have root privileges.

    masscan requires raw socket access (root/sudo). If the binary exists
    but we're not root, every invocation would fail and waste time before
    falling back to nmap — so we check both conditions up front.
    """
    if shutil.which("masscan") is None:
        return False
    if os.geteuid() != 0:
        logger.debug("masscan found but not running as root — disabled")
        return False
    return True


def _extract_profile_ports(profile: str) -> Optional[str]:
    """Extract explicit port list from a profile's nmap arguments.

    Returns the port string (e.g. "23,80,443,...") if the profile has a
    ``-p`` flag, or None if it uses default ports (like QUICK with ``-F``).
    """
    args = SCAN_PROFILES.get(profile, "")
    m = re.search(r'-p\s+(\S+)', args)
    return m.group(1) if m else None


def _run_masscan(
    target: str,
    rate: int,
    ports: str = "1-65535",
    timeout: int = 300,
    progress_callback: Optional[Callable] = None,
) -> Dict[str, List[int]]:
    """Run masscan and return discovered open ports per host.

    Args:
        target:   CIDR, IP range, or single host.
        rate:     Packets per second (capped at _MASSCAN_MAX_RATE).
        ports:    Port specification (default all ports).
        timeout:  Subprocess timeout in seconds.
        progress_callback: Optional (msg, pct) callback for status updates.

    Returns:
        {ip_address: [open_port, ...]} for all discovered hosts.
        Empty dict on any failure.
    """
    rate = min(rate, _MASSCAN_MAX_RATE)
    cmd = [
        "masscan",
        target,
        "--rate", str(rate),
        "-p", ports,
        "-oX", "-",      # XML to stdout
        "--wait", "3",   # wait 3 s after last packet before exiting
    ]
    logger.info(f"masscan: {' '.join(cmd)}")
    if progress_callback:
        progress_callback("masscan port discovery...", 5)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            text=True,
        )
        if result.returncode != 0 and result.stderr:
            stderr_line = result.stderr.strip().splitlines()[0] if result.stderr.strip() else ""
            logger.warning(f"masscan exited {result.returncode}: {stderr_line}")
        parsed = _parse_masscan_xml(result.stdout)
        if progress_callback:
            progress_callback(
                f"masscan discovered {sum(len(v) for v in parsed.values())} ports",
                15,
            )
        return parsed
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

        return self._scan_masscan_nmap_parallel(target, profile)

    @staticmethod
    def _build_nmap_args(profile: str, ports: List[int]) -> str:
        """Build nmap arguments with masscan-discovered ports injected.

        Removes ``-F`` and any existing ``-p`` from the profile's flags,
        inserts the masscan-discovered ports, and ensures ``-sV`` is present.
        """
        base_args = SCAN_PROFILES.get(profile, SCAN_PROFILES["FULL"])

        # Tokenise, stripping -F and any existing -p <value> pair
        tokens = base_args.split()
        kept: List[str] = []
        skip_next = False
        for tok in tokens:
            if skip_next:
                skip_next = False
                continue
            if tok == "-F":
                continue
            if tok == "-p":
                skip_next = True  # drop the following port value too
                continue
            # Handle -pXXX (no space between -p and value)
            if tok.startswith("-p") and len(tok) > 2 and tok[2:3].isdigit():
                continue
            kept.append(tok)

        if "-sV" not in kept and "-A" not in kept:
            kept.append("-sV")

        ports_str = ",".join(str(p) for p in sorted(ports))
        kept.extend(["-p", ports_str])
        return " ".join(kept)

    def _scan_masscan_nmap(self, target: str, profile: str) -> ScanResult:
        """Run masscan discovery then nmap service detection on found ports."""
        rate = MASSCAN_RATES.get(profile, MASSCAN_RATES.get("FULL", 1000))
        rate = min(rate, _MASSCAN_MAX_RATE)

        # Use profile-specific ports for masscan if the profile defines them
        masscan_ports = _extract_profile_ports(profile) or "1-65535"

        discovered = _run_masscan(
            target, rate, ports=masscan_ports,
            progress_callback=self._nmap._progress_callback,
        )

        if not discovered:
            logger.info("masscan found no open ports — falling back to nmap")
            return self._nmap.scan(target, profile)

        # Collect union of all open ports across all discovered hosts
        all_ports: set = set()
        for ports in discovered.values():
            all_ports.update(ports)

        if not all_ports:
            return self._nmap.scan(target, profile)

        nmap_args = self._build_nmap_args(profile, sorted(all_ports))
        logger.info(
            f"nmap service scan: {len(all_ports)} ports on {target} "
            f"(discovered by masscan)"
        )
        return self._nmap.scan(target, profile, arguments=nmap_args)

    def _scan_masscan_nmap_parallel(self, target: str, profile: str) -> ScanResult:
        """Run masscan discovery then parallel per-host nmap service detection.

        When masscan discovers ports on multiple hosts, runs one nmap call per
        host in parallel using ThreadPoolExecutor. Each host is scanned only
        for the ports masscan found on that specific host (not the union).

        Falls back to _scan_masscan_nmap() if only one host is discovered,
        or to plain nmap if masscan finds nothing.
        """
        rate = MASSCAN_RATES.get(profile, MASSCAN_RATES.get("FULL", 2000))
        rate = min(rate, _MASSCAN_MAX_RATE)

        # Use profile-specific ports for masscan if the profile defines them
        masscan_ports = _extract_profile_ports(profile) or "1-65535"

        discovered = _run_masscan(
            target, rate, ports=masscan_ports,
            progress_callback=self._nmap._progress_callback,
        )

        if not discovered:
            logger.info("masscan found no open ports — falling back to nmap")
            return self._nmap.scan(target, profile)

        # Single host — no benefit from parallel, use existing method
        if len(discovered) <= 1:
            return self._scan_masscan_nmap(target, profile)

        def _scan_host(ip: str, ports: List[int]) -> ScanResult:
            nmap_args = self._build_nmap_args(profile, ports)
            logger.info(f"parallel nmap: {ip} — {len(ports)} ports")
            return self._nmap.scan(ip, profile, arguments=nmap_args)

        start_time = datetime.now()
        combined = ScanResult(target=target, profile=profile)
        combined.start_time = start_time
        max_workers = self._settings.nmap_parallel_hosts

        logger.info(
            f"launching parallel nmap: {len(discovered)} hosts, "
            f"max_workers={max_workers}"
        )

        if self._nmap._progress_callback:
            self._nmap._progress_callback(
                f"nmap service detection on {len(discovered)} hosts...", 20
            )

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_scan_host, ip, ports): ip
                for ip, ports in discovered.items()
            }
            done_count = 0
            for future in as_completed(futures):
                ip = futures[future]
                done_count += 1
                try:
                    result = future.result()
                    combined.hosts.update(result.hosts)
                    if self._nmap._progress_callback:
                        pct = 20 + int(80 * done_count / len(futures))
                        self._nmap._progress_callback(
                            f"nmap: {done_count}/{len(discovered)} hosts done", pct
                        )
                except Exception as e:
                    logger.warning(f"parallel nmap failed for {ip}: {e}")

        combined.end_time = datetime.now()
        combined.duration = (combined.end_time - start_time).total_seconds()
        return combined

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
