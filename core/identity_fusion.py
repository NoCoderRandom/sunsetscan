"""
NetWatch Identity Fusion Engine.

Combines all data sources — passive sniffing, active scanning, OUI lookup,
and persistent device history — into a single unified identity per MAC
address.

Data sources fused (in priority order):
    1. Active scan results (nmap OS, port scan, banners, HTTP, TLS, SSH)
    2. Passive capture (mDNS names/services, SSDP/UPnP metadata, DHCP hostnames)
    3. OUI vendor lookup (MAC prefix → manufacturer)
    4. Persistent device map (historical observations)

Each source contributes evidence with a confidence weight. The engine
resolves conflicts using a weighted voting system and produces a final
identity with:
    - device_name:  Best available name
    - device_type:  Category (router, NAS, printer, camera, etc.)
    - vendor:       Manufacturer name
    - confidence:   Combined confidence score (0.0 - 1.0)
    - metadata:     All raw evidence for debugging

Exports:
    IdentityFusionEngine: Main fusion class
    FusedIdentity:        Dataclass for fusion output
"""

import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from core.device_identifier import DeviceIdentity
from core.device_map import DeviceMap, DeviceRecord
from core.oui_lookup import is_randomized_mac, lookup_vendor
from core.packet_parsers import ParsedPacket

logger = logging.getLogger(__name__)


@dataclass
class FusedIdentity:
    """Unified device identity after fusion.

    Attributes:
        mac:          MAC address.
        ip:           Primary IP address.
        device_name:  Best available friendly name.
        device_type:  Device category.
        vendor:       Manufacturer / vendor name.
        model:        Model identifier.
        version:      Firmware / OS version string.
        os_hint:      Operating system hint.
        confidence:   Combined confidence (0.0 - 1.0).
        sources:      All evidence sources that contributed.
        passive_data: Parsed packets from passive capture.
        active_id:    Identity from active scan engine.
        history:      Historical record from device map.
        metadata:     Merged raw metadata from all sources.
    """
    mac: str = ""
    ip: str = ""
    device_name: str = ""
    device_type: str = ""
    vendor: str = ""
    model: str = ""
    version: str = ""
    os_hint: str = ""
    confidence: float = 0.0
    sources: List[str] = field(default_factory=list)
    passive_data: List[ParsedPacket] = field(default_factory=list)
    active_id: Optional[DeviceIdentity] = None
    history: Optional[DeviceRecord] = None
    metadata: Dict[str, str] = field(default_factory=dict)

    def summary(self) -> str:
        """One-line human-readable summary."""
        parts = []
        if self.device_type:
            parts.append(self.device_type)
        if self.vendor:
            parts.append(self.vendor)
        if self.model:
            parts.append(self.model)
        if self.device_name and self.device_name not in parts:
            parts.append(f'"{self.device_name}"')
        if self.version:
            parts.append(f"v{self.version}")
        return " — ".join(parts) if parts else "Unknown Device"

    def to_dict(self) -> dict:
        return {
            "mac": self.mac,
            "ip": self.ip,
            "device_name": self.device_name,
            "device_type": self.device_type,
            "vendor": self.vendor,
            "model": self.model,
            "version": self.version,
            "os_hint": self.os_hint,
            "confidence": round(self.confidence, 3),
            "sources": self.sources,
            "metadata": self.metadata,
        }


# Source confidence weights — higher weight sources are trusted more
_SOURCE_WEIGHTS = {
    'active_scan':  1.0,    # Active scan results (nmap, banners, fingerprints)
    'mdns':         0.85,   # mDNS is very reliable for device names and services
    'ssdp':         0.75,   # SSDP/UPnP has good device metadata
    'dhcp':         0.7,    # DHCP hostname is reliable, OS hints less so
    'oui':          0.4,    # OUI gives vendor only, not device type
    'history':      0.6,    # Historical data — useful but may be stale
}


class IdentityFusionEngine:
    """Fuses passive + active + OUI + history into per-device identities.

    Usage:
        engine = IdentityFusionEngine(device_map)
        fused = engine.fuse(
            mac="aa:bb:cc:dd:ee:ff",
            ip="192.168.1.100",
            active_identity=device_id,
            passive_packets=[...],
        )
    """

    def __init__(self, device_map: Optional[DeviceMap] = None):
        self._device_map = device_map

    def fuse(
        self,
        mac: str,
        ip: str = "",
        active_identity: Optional[DeviceIdentity] = None,
        passive_packets: Optional[List[ParsedPacket]] = None,
    ) -> FusedIdentity:
        """Fuse all data sources for a single device into a unified identity.

        Args:
            mac:              MAC address.
            ip:               IP address.
            active_identity:  Identity from the active scan engine.
            passive_packets:  Parsed packets from passive capture for this device.

        Returns:
            FusedIdentity with merged data and computed confidence.
        """
        result = FusedIdentity(mac=mac.lower(), ip=ip)

        # Collect candidate values for each field
        candidates: Dict[str, List[tuple]] = {
            'vendor': [],
            'model': [],
            'version': [],
            'device_type': [],
            'device_name': [],
            'os_hint': [],
        }

        # --- Source 1: Active scan identity ---
        if active_identity and active_identity.confidence > 0:
            result.active_id = active_identity
            weight = _SOURCE_WEIGHTS['active_scan'] * active_identity.confidence

            if active_identity.vendor:
                candidates['vendor'].append((active_identity.vendor, weight))
            if active_identity.model:
                candidates['model'].append((active_identity.model, weight))
            if active_identity.version:
                candidates['version'].append((active_identity.version, weight))
            if active_identity.device_type:
                candidates['device_type'].append((active_identity.device_type, weight))

            result.sources.extend(
                f"active:{s}" for s in active_identity.sources
                if f"active:{s}" not in result.sources
            )

        # --- Source 2: Passive capture packets ---
        if passive_packets:
            result.passive_data = passive_packets
            for pkt in passive_packets:
                src_weight = _SOURCE_WEIGHTS.get(pkt.protocol, 0.5)

                if pkt.hostname:
                    candidates['device_name'].append((pkt.hostname, src_weight))
                if pkt.vendor:
                    candidates['vendor'].append((pkt.vendor, src_weight))
                if pkt.model:
                    candidates['model'].append((pkt.model, src_weight))
                if pkt.device_type:
                    candidates['device_type'].append((pkt.device_type, src_weight))
                if pkt.version:
                    candidates['version'].append((pkt.version, src_weight))
                if pkt.os_hint:
                    candidates['os_hint'].append((pkt.os_hint, src_weight))

                if pkt.protocol not in result.sources:
                    result.sources.append(pkt.protocol)

                # Merge raw fields into metadata
                for key, val in pkt.raw_fields.items():
                    result.metadata[f"{pkt.protocol}_{key}"] = val

        # --- Source 3: OUI vendor lookup ---
        # Skip entirely for randomized (locally-administered) MACs — the OUI
        # byte is RNG-generated and will produce a confident-but-wrong label.
        if mac:
            if is_randomized_mac(mac):
                result.metadata['mac_randomized'] = 'true'
                if 'oui:randomized' not in result.sources:
                    result.sources.append('oui:randomized')
            else:
                oui_vendor = lookup_vendor(mac)
                if oui_vendor:
                    candidates['vendor'].append((oui_vendor, _SOURCE_WEIGHTS['oui']))
                    if 'oui' not in result.sources:
                        result.sources.append('oui')

        # --- Source 4: Persistent device map (history) ---
        if self._device_map:
            history = self._device_map.get(mac)
            if history:
                result.history = history
                weight = _SOURCE_WEIGHTS['history']
                # Reduce weight for stale records
                if history.observation_count > 3:
                    weight = min(weight + 0.1, 0.8)

                if history.vendor:
                    candidates['vendor'].append((history.vendor, weight))
                if history.model:
                    candidates['model'].append((history.model, weight))
                if history.version:
                    candidates['version'].append((history.version, weight * 0.5))
                if history.device_type:
                    candidates['device_type'].append((history.device_type, weight))
                if history.device_name:
                    candidates['device_name'].append((history.device_name, weight))

                if 'history' not in result.sources:
                    result.sources.append('history')

        # --- Resolve each field via weighted voting ---
        result.vendor = self._resolve_field(candidates['vendor'])
        result.model = self._resolve_field(candidates['model'])
        result.version = self._resolve_field(candidates['version'])
        result.device_type = self._resolve_field(candidates['device_type'])
        result.device_name = self._resolve_field(candidates['device_name'])
        result.os_hint = self._resolve_field(candidates['os_hint'])

        # --- Compute combined confidence ---
        result.confidence = self._compute_confidence(candidates, result)

        return result

    def fuse_all(
        self,
        active_identities: Dict[str, DeviceIdentity],
        passive_packets: List[ParsedPacket],
        mac_ip_map: Dict[str, str],
    ) -> Dict[str, FusedIdentity]:
        """Fuse identities for all devices in a scan.

        Args:
            active_identities: IP → DeviceIdentity from active scan.
            passive_packets:   All parsed packets from passive capture.
            mac_ip_map:        MAC → IP mapping from ARP/scan data.

        Returns:
            MAC → FusedIdentity for all known devices.
        """
        # Build IP → MAC reverse map
        ip_to_mac = {ip: mac for mac, ip in mac_ip_map.items()}

        # Group passive packets by MAC (or IP if MAC unavailable)
        packets_by_mac: Dict[str, List[ParsedPacket]] = {}
        for pkt in passive_packets:
            mac = pkt.src_mac.lower() if pkt.src_mac else ""
            if not mac and pkt.src_ip:
                mac = ip_to_mac.get(pkt.src_ip, "")
            if mac:
                packets_by_mac.setdefault(mac, []).append(pkt)

        # Collect all MACs from all sources
        all_macs = set(mac_ip_map.keys())
        all_macs.update(packets_by_mac.keys())

        results: Dict[str, FusedIdentity] = {}

        for mac in all_macs:
            mac = mac.lower()
            ip = mac_ip_map.get(mac, "")

            # Find active identity by IP
            active_id = active_identities.get(ip) if ip else None

            # Get passive packets for this MAC
            pkt_list = packets_by_mac.get(mac, [])

            fused = self.fuse(
                mac=mac,
                ip=ip,
                active_identity=active_id,
                passive_packets=pkt_list,
            )
            results[mac] = fused

        logger.info(f"Identity fusion complete: {len(results)} devices")
        return results

    @staticmethod
    def _resolve_field(candidates: List[tuple]) -> str:
        """Resolve a field from weighted candidates via weighted voting.

        Args:
            candidates: List of (value, weight) tuples.

        Returns:
            Best value string, or "" if no candidates.
        """
        if not candidates:
            return ""

        # Group by normalized value and sum weights
        votes: Dict[str, float] = {}
        for value, weight in candidates:
            if not value:
                continue
            key = value.strip().lower()
            votes[key] = votes.get(key, 0.0) + weight

        if not votes:
            return ""

        # Return the value with highest weighted vote (preserve original case)
        best_key = max(votes, key=votes.get)

        # Find original-case version of the best value
        for value, _ in candidates:
            if value.strip().lower() == best_key:
                return value.strip()

        return ""

    @staticmethod
    def _compute_confidence(
        candidates: Dict[str, List[tuple]],
        result: FusedIdentity,
    ) -> float:
        """Compute overall confidence score.

        Based on:
            - Number of sources contributing
            - Agreement between sources
            - Specificity of identification
        """
        # Base: average of max weights across non-empty fields
        field_weights = []
        for field_name in ('vendor', 'device_type', 'model', 'device_name'):
            field_candidates = candidates.get(field_name, [])
            if field_candidates:
                max_weight = max(w for _, w in field_candidates)
                field_weights.append(max_weight)

        if not field_weights:
            return 0.0

        base = sum(field_weights) / len(field_weights)

        # Source diversity bonus: more independent sources = higher confidence
        num_sources = len(result.sources)
        diversity_bonus = min(0.15, 0.03 * num_sources)

        # Specificity bonus: having model + vendor is more specific than just vendor
        specificity = 0.0
        if result.vendor:
            specificity += 0.05
        if result.model:
            specificity += 0.05
        if result.device_name:
            specificity += 0.03
        if result.version:
            specificity += 0.02

        confidence = min(1.0, base + diversity_bonus + specificity)
        return round(confidence, 3)
