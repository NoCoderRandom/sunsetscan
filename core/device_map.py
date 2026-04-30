"""
NetWatch Persistent Device Map Module.

Maintains a JSON-backed database mapping MAC addresses to device identities.
On each scan run, known devices are preloaded from disk, new data is merged,
and confidence scores are updated based on evidence consistency.

The device map survives between scan sessions, allowing NetWatch to:
    - Instantly identify previously seen devices
    - Track device history (first seen, last seen)
    - Detect new/unknown devices on the network
    - Build confidence over repeated observations

Storage: data/device_map.json

Exports:
    DeviceMap:    Class for persistent MAC → identity storage
    DeviceRecord: Dataclass for a stored device identity
"""

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).parent.parent
_DEVICE_MAP_PATH = _PROJECT_ROOT / "data" / "device_map.json"


@dataclass
class DeviceRecord:
    """Persistent identity record for a single device.

    Attributes:
        mac:           MAC address (primary key).
        vendor:        Canonical vendor name.
        model:         Device model.
        version:       Firmware / OS version.
        device_type:   Category (router, nas, printer, etc.).
        device_name:   Friendly / display name.
        confidence:    Overall confidence 0.0 - 1.0.
        sources:       Evidence sources that contributed.
        ips:           IP addresses observed for this MAC.
        hostnames:     Hostnames observed for this MAC.
        first_seen:    ISO timestamp of first observation.
        last_seen:     ISO timestamp of most recent observation.
        observation_count: How many scans this device has been seen in.
        metadata:      Additional raw metadata from parsers.
    """
    mac: str = ""
    vendor: str = ""
    model: str = ""
    version: str = ""
    device_type: str = ""
    device_name: str = ""
    confidence: float = 0.0
    sources: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    hostnames: List[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    observation_count: int = 0
    metadata: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "DeviceRecord":
        known_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in d.items() if k in known_fields}
        return cls(**filtered)


class DeviceMap:
    """Persistent MAC → identity mapping backed by a JSON file.

    Usage:
        dmap = DeviceMap()
        dmap.load()
        record = dmap.get("aa:bb:cc:dd:ee:ff")
        dmap.update("aa:bb:cc:dd:ee:ff", vendor="Synology", device_type="NAS", ...)
        dmap.save()
    """

    def __init__(self, path: Optional[Path] = None):
        self._path = path or _DEVICE_MAP_PATH
        self._records: Dict[str, DeviceRecord] = {}  # mac -> record
        self._dirty = False

    @property
    def size(self) -> int:
        return len(self._records)

    def load(self) -> int:
        """Load device map from disk.

        Returns:
            Number of records loaded.
        """
        if not self._path.exists():
            logger.debug("No device map found — starting fresh")
            return 0

        try:
            with open(self._path, "r", encoding="utf-8") as f:
                raw = json.load(f)

            if isinstance(raw, dict):
                for mac, data in raw.items():
                    if isinstance(data, dict):
                        self._records[mac.lower()] = DeviceRecord.from_dict(data)

            logger.info(f"Device map loaded: {len(self._records)} known devices")
            return len(self._records)

        except Exception as e:
            logger.warning(f"Device map load failed: {e}")
            return 0

    def save(self) -> bool:
        """Save device map to disk.

        Returns:
            True if saved successfully.
        """
        if not self._dirty:
            logger.debug("Device map unchanged; skipping save")
            return True

        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            serialized = {
                mac: record.to_dict()
                for mac, record in sorted(self._records.items())
            }
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(serialized, f, indent=2, default=str)
            self._dirty = False
            logger.debug(f"Device map saved: {len(self._records)} records")
            return True
        except Exception as e:
            logger.warning(f"Device map save failed: {e}")
            return False

    def get(self, mac: str) -> Optional[DeviceRecord]:
        """Look up a device by MAC address."""
        return self._records.get(mac.lower())

    def get_all(self) -> Dict[str, DeviceRecord]:
        """Return all device records."""
        return dict(self._records)

    def get_by_ip(self, ip: str) -> Optional[DeviceRecord]:
        """Look up a device by IP address (searches all records)."""
        for record in self._records.values():
            if ip in record.ips:
                return record
        return None

    def update(
        self,
        mac: str,
        ip: str = "",
        hostname: str = "",
        vendor: str = "",
        model: str = "",
        version: str = "",
        device_type: str = "",
        device_name: str = "",
        confidence: float = 0.0,
        sources: Optional[List[str]] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> DeviceRecord:
        """Update or create a device record.

        Merges new data with existing record. Higher-confidence data takes
        precedence. IP addresses and hostnames are accumulated. Confidence
        is boosted slightly when consistent data is observed across scans.

        Args:
            mac:         MAC address (required).
            ip:          Current IP address.
            hostname:    Observed hostname.
            vendor:      Vendor name.
            model:       Model identifier.
            version:     Version string.
            device_type: Device category.
            device_name: Friendly name.
            confidence:  Confidence for this observation.
            sources:     Evidence sources for this observation.
            metadata:    Additional raw metadata.

        Returns:
            Updated DeviceRecord.
        """
        mac = mac.lower()
        now = datetime.now().isoformat()

        record = self._records.get(mac)
        if record is None:
            record = DeviceRecord(mac=mac, first_seen=now)
            self._records[mac] = record

        record.last_seen = now
        record.observation_count += 1

        # Accumulate IPs and hostnames (deduped)
        if ip and ip not in record.ips:
            record.ips.append(ip)
        if hostname and hostname not in record.hostnames:
            record.hostnames.append(hostname)

        # Merge fields — new data wins if confidence >= existing
        if vendor and (not record.vendor or confidence >= record.confidence):
            record.vendor = vendor
        if model and (not record.model or confidence >= record.confidence):
            record.model = model
        if version and (not record.version or confidence >= record.confidence):
            record.version = version
        if device_type and (not record.device_type or confidence >= record.confidence):
            record.device_type = device_type
        if device_name and (not record.device_name or confidence >= record.confidence):
            record.device_name = device_name

        # Accumulate sources
        if sources:
            for src in sources:
                if src not in record.sources:
                    record.sources.append(src)

        # Merge metadata
        if metadata:
            record.metadata.update(metadata)

        # Update confidence with consistency bonus
        if confidence > 0:
            if record.observation_count > 1:
                # Boost confidence slightly for consistent re-observations
                consistency_bonus = min(0.05, 0.01 * record.observation_count)
                record.confidence = min(1.0, max(record.confidence, confidence) + consistency_bonus)
            else:
                record.confidence = confidence

        self._dirty = True
        return record

    def get_new_devices(self, current_macs: set) -> List[DeviceRecord]:
        """Find devices in current scan that have never been seen before.

        Args:
            current_macs: Set of MAC addresses from the current scan.

        Returns:
            List of DeviceRecord for MACs not previously in the map.
        """
        new = []
        for mac in current_macs:
            mac = mac.lower()
            record = self._records.get(mac)
            if record and record.observation_count <= 1:
                new.append(record)
        return new

    def get_missing_devices(self, current_macs: set) -> List[DeviceRecord]:
        """Find previously known devices NOT seen in the current scan.

        Args:
            current_macs: Set of MAC addresses from the current scan.

        Returns:
            List of DeviceRecord for known devices that are absent.
        """
        current_lower = {m.lower() for m in current_macs}
        return [
            record for mac, record in self._records.items()
            if mac not in current_lower
        ]
