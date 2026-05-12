"""
SunsetScan Host Capability Detection.

Detects characteristics of the host running SunsetScan that should make the
scanner less aggressive:

  - Raspberry Pi / low-end ARM SBC
  - Low CPU core count or low RAM
  - Pi-hole co-located on the same machine (it IS the LAN's DNS resolver)
  - Egress interface is Wi-Fi (shared half-duplex medium)

When any of these are true, "safe mode" is recommended: lower masscan rate,
serial nmap (parallel_hosts=1), reduced worker threads, drop OS fingerprinting,
and exclude the gateway + self IP from scans.

This module performs detection only — it does NOT mutate global state. The
caller (sunsetscan.py startup) decides whether to apply the recommended
overrides when constructing Settings.
"""

import logging
import os
import socket
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class HostProfile:
    """Detected characteristics of the scanner host."""
    cpu_count: int = 0
    mem_mb: int = 0
    is_pi: bool = False
    pi_model: str = ""
    has_pihole: bool = False
    egress_iface: str = ""
    is_wireless: bool = False
    gateway_ip: str = ""
    local_ip: str = ""
    reasons: List[str] = field(default_factory=list)

    @property
    def is_low_power(self) -> bool:
        """True if hardware is small enough to warrant gentler scanning."""
        return self.is_pi or self.cpu_count <= 4 or (self.mem_mb and self.mem_mb < 2048)

    @property
    def recommend_safe_mode(self) -> bool:
        """True if any single condition warrants safe mode."""
        return self.is_low_power or self.has_pihole or self.is_wireless

    def excluded_hosts(self) -> Tuple[str, ...]:
        """IPs that should NEVER be scanned: the gateway and the host itself."""
        out = []
        if self.gateway_ip:
            out.append(self.gateway_ip)
        if self.local_ip and self.local_ip != self.gateway_ip:
            out.append(self.local_ip)
        return tuple(out)

    def describe(self) -> str:
        """Human-readable one-paragraph summary."""
        bits = []
        if self.is_pi:
            bits.append(self.pi_model or "Raspberry Pi")
        bits.append(f"{self.cpu_count} cores")
        if self.mem_mb:
            bits.append(f"{self.mem_mb} MB RAM")
        if self.has_pihole:
            bits.append("Pi-hole active")
        if self.egress_iface:
            link = "Wi-Fi" if self.is_wireless else "Ethernet"
            bits.append(f"egress {self.egress_iface} ({link})")
        return ", ".join(bits)


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def _detect_pi() -> Tuple[bool, str]:
    """Return (is_pi, model_string) by reading /proc/device-tree/model."""
    try:
        model = Path("/proc/device-tree/model").read_text(errors="ignore").strip("\x00 \n")
        if "raspberry pi" in model.lower():
            return True, model
    except Exception:
        pass
    try:
        cpuinfo = Path("/proc/cpuinfo").read_text(errors="ignore")
        for line in cpuinfo.splitlines():
            if line.lower().startswith("model") and "raspberry" in line.lower():
                return True, line.split(":", 1)[1].strip()
            if line.startswith("Hardware") and "BCM" in line:
                return True, line.split(":", 1)[1].strip()
    except Exception:
        pass
    return False, ""


def _detect_mem_mb() -> int:
    """Return total system RAM in MB, or 0 if unknown."""
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                kb = int(line.split()[1])
                return kb // 1024
    except Exception:
        pass
    return 0


def _detect_pihole() -> bool:
    """Detect a co-located Pi-hole installation."""
    if Path("/etc/pihole").is_dir():
        return True
    if Path("/usr/local/bin/pihole").exists() or Path("/usr/bin/pihole").exists():
        return True
    # Check for the FTL daemon process
    try:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                comm = (entry / "comm").read_text().strip()
            except Exception:
                continue
            if comm in ("pihole-FTL", "pihole-ftl"):
                return True
    except Exception:
        pass
    return False


def _detect_gateway() -> str:
    """Default gateway IP from `ip route show default`."""
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], timeout=3, text=True
        )
        for line in out.splitlines():
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return ""


def _detect_egress(target_ip: str = "8.8.8.8") -> Tuple[str, str]:
    """Return (egress_interface, local_ip) used to reach the LAN/Internet."""
    iface, local_ip = "", ""
    try:
        out = subprocess.check_output(
            ["ip", "-o", "route", "get", target_ip], timeout=3, text=True
        )
        # "8.8.8.8 via 192.168.1.1 dev wlan0 src 192.168.1.42 uid 1000 \    cache"
        parts = out.split()
        if "dev" in parts:
            iface = parts[parts.index("dev") + 1]
        if "src" in parts:
            local_ip = parts[parts.index("src") + 1]
    except Exception:
        pass
    if not local_ip:
        # Fallback to UDP socket trick
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                s.connect((target_ip, 80))
                local_ip = s.getsockname()[0]
        except Exception:
            pass
    return iface, local_ip


def _detect_wireless(iface: str) -> bool:
    """True if the given interface is a wireless NIC."""
    if not iface:
        return False
    if Path(f"/sys/class/net/{iface}/wireless").exists():
        return True
    if Path(f"/sys/class/net/{iface}/phy80211").exists():
        return True
    # Heuristic on common naming (wlan0, wlp3s0, wlx…)
    return iface.startswith(("wlan", "wlp", "wlx"))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_host_profile() -> HostProfile:
    """Run all host detection checks and return a HostProfile.

    Safe to call repeatedly; cheap (no network traffic generated).
    """
    profile = HostProfile()
    profile.cpu_count = os.cpu_count() or 1
    profile.mem_mb = _detect_mem_mb()
    profile.is_pi, profile.pi_model = _detect_pi()
    profile.has_pihole = _detect_pihole()
    profile.gateway_ip = _detect_gateway()
    profile.egress_iface, profile.local_ip = _detect_egress()
    profile.is_wireless = _detect_wireless(profile.egress_iface)

    if profile.is_pi:
        profile.reasons.append("Raspberry Pi hardware")
    if profile.cpu_count <= 4 and not profile.is_pi:
        profile.reasons.append(f"low CPU count ({profile.cpu_count})")
    if profile.mem_mb and profile.mem_mb < 2048:
        profile.reasons.append(f"low RAM ({profile.mem_mb} MB)")
    if profile.has_pihole:
        profile.reasons.append("Pi-hole runs on this host")
    if profile.is_wireless:
        profile.reasons.append(f"egress is wireless ({profile.egress_iface})")

    return profile


def safe_mode_overrides(profile: HostProfile) -> Dict[str, object]:
    """Return Settings field overrides to apply when safe mode is recommended.

    Conservative defaults: serial nmap, small worker pool, exclude gateway+self.
    Wi-Fi gets the strictest treatment because airtime starvation degrades the
    entire BSS, not just the scanner host.
    """
    overrides: Dict[str, object] = {
        "safe_mode": True,
        "nmap_parallel_hosts": 1,
        "scan_worker_threads": 2,
        "excluded_hosts": profile.excluded_hosts(),
        # Skip heavy TLS probes (JA3S, full cert parse) to reduce CPU/network load.
        "skip_heavy_probes": True,
        # Halve per-probe timeouts so slow hosts don't stall the scan.
        "probe_timeout_factor": 0.5,
    }
    return overrides


# Per-profile masscan rate caps applied when safe mode is active.
# These are the *maximum* rates; the per-profile entry in MASSCAN_RATES is
# clamped down to this if higher.
SAFE_MASSCAN_RATE_CAPS: Dict[str, int] = {
    "QUICK":   400,
    "FULL":    300,
    "STEALTH": 100,
    "IOT":     300,
    "SMB":     300,
}

# Even stricter caps when egress is Wi-Fi — every packet competes for airtime
# with every other LAN client.
WIFI_MASSCAN_RATE_CAPS: Dict[str, int] = {
    "QUICK":   200,
    "FULL":    150,
    "STEALTH":  75,
    "IOT":     150,
    "SMB":     150,
}


def effective_masscan_rate(
    profile_name: str,
    base_rate: int,
    safe_mode: bool,
    is_wireless: bool = False,
) -> int:
    """Return the masscan rate to actually use for a given profile.

    Outside of safe mode, returns ``base_rate`` unchanged.
    """
    if not safe_mode:
        return base_rate
    cap_table = WIFI_MASSCAN_RATE_CAPS if is_wireless else SAFE_MASSCAN_RATE_CAPS
    cap = cap_table.get(profile_name, 300)
    return min(base_rate, cap)


def downgrade_nmap_args(args: str) -> str:
    """Strip the most network-hostile flags from an nmap argument string.

    Removes:
      -O / --osscan-guess  : OS fingerprinting (sends crafted probes that
                             can wedge consumer routers)
      -A                   : aggressive (-O + -sV + -sC + traceroute)
                             — replaced with just -sV -sC
      -T4 / -T5            : aggressive timing — downgraded to -T3

    Idempotent: re-applying produces the same result.
    """
    if not args:
        return args
    out: List[str] = []
    skip_next = False
    for tok in args.split():
        if skip_next:
            skip_next = False
            continue
        if tok in ("-O", "--osscan-guess", "--osscan-limit"):
            continue
        if tok == "-A":
            # Replace -A (which implies -O) with -sV -sC
            out.extend(["-sV", "-sC"])
            continue
        if tok in ("-T4", "-T5"):
            out.append("-T3")
            continue
        out.append(tok)
    # Deduplicate the version/script flags that -A may have already added
    seen = set()
    deduped: List[str] = []
    for tok in out:
        if tok in ("-sV", "-sC") and tok in seen:
            continue
        seen.add(tok)
        deduped.append(tok)
    return " ".join(deduped)
