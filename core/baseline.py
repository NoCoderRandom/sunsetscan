"""
NetWatch Rogue Device Baseline Module.

Saves the set of known devices (MAC + IP + hostname + vendor) from a scan
as a baseline. Subsequent scans compare against this baseline to detect:

    - New/unknown devices (not in baseline) → MEDIUM finding
    - Known devices on unexpected IPs       → LOW finding
    - Previously seen devices now offline   → INFO finding

The baseline file is stored at: data/baseline.json
It is never deleted automatically — only updated when --save-baseline is used.

Usage:
    # Save current scan as baseline
    python netwatch.py --save-baseline

    # Compare any subsequent scan automatically (happens if baseline exists)
    python netwatch.py --target 192.168.1.0/24
"""

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from core.findings import Finding, Severity

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).parent.parent
BASELINE_PATH = _PROJECT_ROOT / "data" / "baseline.json"


@dataclass
class BaselineDevice:
    """A device entry in the baseline."""
    mac: str
    ip: str
    hostname: str
    vendor: str
    first_seen: str
    last_seen: str
    notes: str = ""

    @property
    def display_name(self) -> str:
        return self.hostname or self.vendor or self.mac or self.ip


@dataclass
class BaselineData:
    """The full baseline file structure."""
    created_at: str
    updated_at: str
    network: str
    devices: Dict[str, BaselineDevice] = field(default_factory=dict)
    # keys = MAC address (lowercase, no separators)


def _normalise_mac(mac: str) -> str:
    """Normalise a MAC address to lowercase hex without separators."""
    if not mac:
        return ""
    return mac.lower().replace(":", "").replace("-", "").replace(".", "")


class BaselineManager:
    """Manages the rogue device baseline file.

    Example:
        manager = BaselineManager()

        # Save current scan as baseline
        manager.save_baseline(scan_result)

        # Compare a new scan and get findings
        findings = manager.compare_scan(scan_result)
    """

    def __init__(self, baseline_path: Optional[Path] = None):
        self.baseline_path = baseline_path or BASELINE_PATH
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)

    # -------------------------------------------------------------------------
    # Load / Save
    # -------------------------------------------------------------------------

    def load(self) -> Optional[BaselineData]:
        """Load the baseline file. Returns None if it does not exist."""
        if not self.baseline_path.exists():
            return None
        try:
            with open(self.baseline_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            devices = {
                mac: BaselineDevice(**dev)
                for mac, dev in raw.get("devices", {}).items()
            }
            return BaselineData(
                created_at=raw.get("created_at", ""),
                updated_at=raw.get("updated_at", ""),
                network=raw.get("network", ""),
                devices=devices,
            )
        except (json.JSONDecodeError, KeyError, TypeError, OSError) as e:
            logger.error(f"Failed to load baseline: {e}")
            return None

    def save(self, baseline: BaselineData) -> bool:
        """Write a BaselineData object to the baseline file."""
        try:
            raw = {
                "created_at": baseline.created_at,
                "updated_at": baseline.updated_at,
                "network": baseline.network,
                "devices": {
                    mac: asdict(dev)
                    for mac, dev in baseline.devices.items()
                },
            }
            tmp = self.baseline_path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(raw, f, indent=2)
            tmp.replace(self.baseline_path)
            logger.info(f"Baseline saved to {self.baseline_path}")
            return True
        except OSError as e:
            logger.error(f"Failed to save baseline: {e}")
            return False

    def exists(self) -> bool:
        """Return True if a baseline file exists."""
        return self.baseline_path.exists()

    # -------------------------------------------------------------------------
    # Populate from scan results
    # -------------------------------------------------------------------------

    def save_baseline_from_scan(self, scan_result, network: str = "") -> int:
        """Create or update the baseline from a ScanResult.

        Args:
            scan_result: A core.scanner.ScanResult object.
            network:     Network CIDR for documentation purposes.

        Returns:
            Number of devices saved.
        """
        now = datetime.now().isoformat()
        existing = self.load()

        if existing:
            baseline = existing
            baseline.updated_at = now
            baseline.network = network or existing.network
        else:
            baseline = BaselineData(
                created_at=now,
                updated_at=now,
                network=network,
                devices={},
            )

        count = 0
        for ip, host in scan_result.hosts.items():
            if host.state != "up":
                continue
            mac_norm = _normalise_mac(host.mac)
            if not mac_norm:
                continue  # We need a MAC to track the device uniquely

            if mac_norm in baseline.devices:
                # Update existing entry
                dev = baseline.devices[mac_norm]
                dev.ip = ip
                dev.hostname = host.hostname or dev.hostname
                dev.vendor = host.vendor or dev.vendor
                dev.last_seen = now
            else:
                baseline.devices[mac_norm] = BaselineDevice(
                    mac=host.mac,
                    ip=ip,
                    hostname=host.hostname or "",
                    vendor=host.vendor or "",
                    first_seen=now,
                    last_seen=now,
                )
            count += 1

        self.save(baseline)
        return count

    # -------------------------------------------------------------------------
    # Comparison
    # -------------------------------------------------------------------------

    def compare_scan(self, scan_result) -> List[Finding]:
        """Compare a new scan result against the saved baseline.

        Returns a list of Finding objects for rogue/changed devices.
        Returns empty list if no baseline exists.
        """
        baseline = self.load()
        if baseline is None:
            return []

        findings: List[Finding] = []
        now = datetime.now().isoformat()

        # Build a lookup of what we saw in this scan
        scanned: Dict[str, Dict] = {}  # mac_norm -> {ip, hostname, vendor}
        for ip, host in scan_result.hosts.items():
            if host.state != "up":
                continue
            mac_norm = _normalise_mac(host.mac)
            if mac_norm:
                scanned[mac_norm] = {
                    "ip": ip,
                    "hostname": host.hostname or "",
                    "vendor": host.vendor or "",
                    "mac_display": host.mac,
                }

        baseline_macs = set(baseline.devices.keys())
        scanned_macs = set(scanned.keys())

        # ---- New devices (not in baseline) ----
        for mac_norm in scanned_macs - baseline_macs:
            dev = scanned[mac_norm]
            label = dev["hostname"] or dev["vendor"] or dev["mac_display"] or dev["ip"]
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title=f"Unknown device detected: {label}",
                host=dev["ip"],
                port=0,
                protocol="",
                category="Rogue Device Detection",
                description=(
                    f"A device was found on the network that is not in your saved baseline. "
                    f"MAC: {dev['mac_display']}, IP: {dev['ip']}, "
                    f"Vendor: {dev['vendor'] or 'unknown'}, "
                    f"Hostname: {dev['hostname'] or 'unknown'}."
                ),
                explanation=(
                    "This device was not present when you last saved your network baseline. "
                    "It could be a new device you recently added, a guest device, "
                    "or an unauthorised device that has joined your network."
                ),
                recommendation=(
                    "1. Check if you recognise this device (look up the MAC vendor).\n"
                    "2. If you recognise it (new phone, laptop, etc.), run "
                    "--save-baseline to update your baseline.\n"
                    "3. If you do NOT recognise it, check your router's connected "
                    "devices list and consider changing your Wi-Fi password.\n"
                    "4. Check your router settings for any unauthorised devices."
                ),
                evidence=(
                    f"MAC: {dev['mac_display']} | IP: {dev['ip']} | "
                    f"Vendor: {dev['vendor'] or 'unknown'}"
                ),
                tags=["baseline", "rogue-device"],
            ))

        # ---- Known devices on different IPs ----
        for mac_norm in scanned_macs.intersection(baseline_macs):
            baseline_dev = baseline.devices[mac_norm]
            scan_dev = scanned[mac_norm]
            if baseline_dev.ip and scan_dev["ip"] != baseline_dev.ip:
                label = baseline_dev.display_name
                findings.append(Finding(
                    severity=Severity.LOW,
                    title=f"Device IP changed: {label}",
                    host=scan_dev["ip"],
                    port=0,
                    protocol="",
                    category="Rogue Device Detection",
                    description=(
                        f"Known device {label!r} (MAC: {baseline_dev.mac}) "
                        f"was previously at {baseline_dev.ip} and is now at {scan_dev['ip']}."
                    ),
                    explanation=(
                        "A known device has a different IP address than when the baseline was saved. "
                        "This is usually caused by DHCP reassignment (normal) but could occasionally "
                        "indicate IP spoofing."
                    ),
                    recommendation=(
                        "This is usually normal (DHCP). "
                        "If you see this repeatedly for the same device, consider assigning "
                        "a static DHCP reservation for it in your router settings. "
                        "Run --save-baseline to update the baseline with the new IP."
                    ),
                    evidence=(
                        f"MAC: {baseline_dev.mac} | "
                        f"Old IP: {baseline_dev.ip} → New IP: {scan_dev['ip']}"
                    ),
                    tags=["baseline", "ip-change"],
                ))

        # ---- Devices in baseline but not seen in this scan (offline) ----
        for mac_norm in baseline_macs - scanned_macs:
            baseline_dev = baseline.devices[mac_norm]
            label = baseline_dev.display_name
            findings.append(Finding(
                severity=Severity.INFO,
                title=f"Previously seen device offline: {label}",
                host=baseline_dev.ip or "unknown",
                port=0,
                protocol="",
                category="Rogue Device Detection",
                description=(
                    f"Device {label!r} (MAC: {baseline_dev.mac}) "
                    f"was in the baseline but did not respond in this scan."
                ),
                explanation=(
                    "This device was visible when the baseline was saved but is not "
                    "responding now. It may be powered off, on a different network, "
                    "or the IP may have changed."
                ),
                recommendation=(
                    "No action required unless you expect this device to always be present. "
                    "Run --save-baseline after verifying your network is in its normal state."
                ),
                evidence=f"MAC: {baseline_dev.mac} | Last seen IP: {baseline_dev.ip}",
                tags=["baseline", "offline"],
            ))

        return findings
