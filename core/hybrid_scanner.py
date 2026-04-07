"""
NetWatch Hybrid Scanner Orchestrator.

Coordinates the full hybrid scanning pipeline:

    1. Start passive capture (mDNS, SSDP, DHCP)
    2. Run active scans (ARP sweep, nmap, mDNS probe, UPnP, HTTP, SMB, TLS)
    3. Stop passive capture
    4. Parse captured packets
    5. Fuse passive + active + OUI + history → unified identities
    6. Update persistent device map
    7. Return fused identities for report integration

This module ties together all the new hybrid intelligence modules:
    - passive_sniffer:   Background packet capture
    - packet_parsers:    mDNS/SSDP/DHCP parsing
    - oui_lookup:        MAC vendor resolution
    - identity_fusion:   Multi-source evidence merging
    - device_map:        Persistent MAC→identity storage
    - device_identifier: Existing active scan identity engine

Exports:
    HybridScanner: Main orchestrator class
    HybridScanResult: Dataclass wrapping scan + fusion results
"""

import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from core.active_mdns import query_active_mdns
from core.device_identifier import DeviceIdentifier, DeviceIdentity
from core.device_map import DeviceMap, DeviceRecord
from core.identity_fusion import FusedIdentity, IdentityFusionEngine
from core.oui_lookup import OUIDatabase, lookup_vendor
from core.packet_parsers import ParsedPacket
from core.passive_sniffer import PassiveSniffer
from core.scanner import ScanResult

logger = logging.getLogger(__name__)


@dataclass
class HybridScanResult:
    """Combined result from the hybrid scanning pipeline.

    Attributes:
        fused_identities: MAC → FusedIdentity for all discovered devices.
        passive_packets:  All parsed packets from passive capture.
        active_identities: IP → DeviceIdentity from active engine.
        mac_ip_map:       MAC → IP mapping.
        new_devices:      Devices seen for the first time.
        missing_devices:  Previously known devices not seen this scan.
        passive_packet_count: Total raw packets captured.
        passive_parsed_count: Successfully parsed packet count.
        active_mdns_count: Number of devices that responded to active mDNS query.
    """
    fused_identities: Dict[str, FusedIdentity] = field(default_factory=dict)
    passive_packets: List[ParsedPacket] = field(default_factory=list)
    active_identities: Dict[str, DeviceIdentity] = field(default_factory=dict)
    mac_ip_map: Dict[str, str] = field(default_factory=dict)
    new_devices: List[DeviceRecord] = field(default_factory=list)
    missing_devices: List[DeviceRecord] = field(default_factory=list)
    passive_packet_count: int = 0
    passive_parsed_count: int = 0
    active_mdns_count: int = 0


class HybridScanner:
    """Orchestrates passive + active scanning into a unified pipeline.

    Usage:
        hybrid = HybridScanner()

        # Step 1: Start passive capture before active scanning
        hybrid.start_passive(interface="eth0")

        # Step 2: Run your active scans (existing NetWatch pipeline)
        # ... scanner.scan(...), run_security_checks(...) ...

        # Step 3: Stop capture and fuse all data
        result = hybrid.stop_and_fuse(scan_result, active_identities)

        # Step 4: Use fused identities in report
        for mac, identity in result.fused_identities.items():
            print(identity.summary())
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        device_map: Optional[DeviceMap] = None,
        device_identifier: Optional[DeviceIdentifier] = None,
    ):
        """Initialize the hybrid scanner.

        Args:
            interface:         Network interface for passive capture.
            device_map:        Persistent device map (loaded or new).
            device_identifier: Active scan device identifier engine.
        """
        self._interface = interface
        self._sniffer = PassiveSniffer(interface=interface)
        self._device_map = device_map or DeviceMap()
        self._device_identifier = device_identifier or DeviceIdentifier()
        self._fusion_engine = IdentityFusionEngine(self._device_map)
        self._oui_db = OUIDatabase()
        self._progress_callback: Optional[Callable[[str, float], None]] = None

    def set_progress_callback(self, callback: Callable[[str, float], None]) -> None:
        """Set a callback for progress updates: callback(message, percentage)."""
        self._progress_callback = callback

    def _progress(self, message: str, pct: float) -> None:
        if self._progress_callback:
            try:
                self._progress_callback(message, pct)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Pipeline Steps
    # ------------------------------------------------------------------

    def start_passive(self) -> bool:
        """Step 1: Start background passive capture.

        Should be called BEFORE active scanning begins, so we capture
        discovery traffic triggered by normal network activity and by
        the active probes themselves.

        Returns:
            True if capture started, False if unavailable (no root, no scapy).
        """
        self._progress("Starting passive capture...", 0)

        # Load persistent device map
        loaded = self._device_map.load()
        if loaded > 0:
            self._progress(f"Loaded {loaded} known devices from history", 5)

        started = self._sniffer.start()
        if started:
            self._progress("Passive sniffer running (mDNS, SSDP, DHCP)", 10)
        else:
            self._progress("Passive capture unavailable (requires root + scapy)", 10)

        return started

    def stop_passive(self) -> int:
        """Step 3: Stop passive capture.

        Returns:
            Number of packets captured.
        """
        count = self._sniffer.stop()
        self._progress(f"Passive capture stopped — {count} packets", 50)
        return count

    def fuse_identities(
        self,
        scan_result: ScanResult,
        active_identities: Optional[Dict[str, DeviceIdentity]] = None,
    ) -> HybridScanResult:
        """Steps 4-6: Parse packets, fuse identities, update device map.

        Args:
            scan_result:       The active scan result from NetWatch.
            active_identities: IP → DeviceIdentity from DeviceIdentifier.
                              If None, runs identification from scan_result.

        Returns:
            HybridScanResult with all fused data.
        """
        result = HybridScanResult()

        # Step 4: Parse captured packets
        self._progress("Parsing captured packets...", 55)
        parsed_packets = self._sniffer.parse_all()
        result.passive_packet_count = self._sniffer.packet_count
        result.passive_parsed_count = len(parsed_packets)

        logger.info(
            f"Passive capture: {result.passive_packet_count} raw, "
            f"{result.passive_parsed_count} parsed"
        )

        # Step 4b: Active mDNS query — deterministic, doesn't depend on the
        # passive capture window catching a re-announce. Critical for Apple
        # devices on Wi-Fi with randomized MACs whose OUI lookup lies.
        self._progress("Querying mDNS services actively...", 58)
        try:
            active_mdns_packets = query_active_mdns()
        except Exception as e:
            logger.debug(f"Active mDNS query failed: {e}")
            active_mdns_packets = []
        result.active_mdns_count = len(active_mdns_packets)
        logger.info(f"Active mDNS: {len(active_mdns_packets)} device(s) responded")

        parsed_packets = parsed_packets + active_mdns_packets
        result.passive_packets = parsed_packets

        # Build MAC → IP map from scan results
        self._progress("Building device map...", 60)
        mac_ip_map: Dict[str, str] = {}
        for ip, host in scan_result.hosts.items():
            if host.mac:
                mac_ip_map[host.mac.lower()] = ip

        # Also extract MAC→IP from passive DHCP packets
        for pkt in parsed_packets:
            if pkt.protocol == "dhcp" and pkt.src_mac and pkt.src_ip:
                mac = pkt.src_mac.lower()
                if mac not in mac_ip_map:
                    mac_ip_map[mac] = pkt.src_ip

        # Active mDNS packets arrive keyed by IP only. Backfill src_mac
        # from mac_ip_map so they participate in MAC-keyed fusion.
        ip_to_mac = {ip: mac for mac, ip in mac_ip_map.items()}
        for pkt in active_mdns_packets:
            if not pkt.src_mac and pkt.src_ip:
                mac = ip_to_mac.get(pkt.src_ip, "")
                if mac:
                    pkt.src_mac = mac

        result.mac_ip_map = mac_ip_map

        # Run active identification if not provided
        self._progress("Running device identification...", 65)
        if active_identities is None:
            active_identities = {}
            from core.findings import Finding
            for ip, host in scan_result.hosts.items():
                if host.state == "up":
                    try:
                        identity = self._device_identifier.identify(
                            ip, host, []
                        )
                        if identity.confidence > 0:
                            active_identities[ip] = identity
                    except Exception as e:
                        logger.debug(f"Active identification failed for {ip}: {e}")

        result.active_identities = active_identities

        # Step 5: Fuse all sources
        self._progress("Fusing identities from all sources...", 75)
        fused = self._fusion_engine.fuse_all(
            active_identities=active_identities,
            passive_packets=parsed_packets,
            mac_ip_map=mac_ip_map,
        )
        result.fused_identities = fused

        # Step 6: Update persistent device map
        self._progress("Updating persistent device map...", 85)
        current_macs = set()
        for mac, fused_id in fused.items():
            current_macs.add(mac)
            self._device_map.update(
                mac=mac,
                ip=fused_id.ip,
                hostname=fused_id.device_name,
                vendor=fused_id.vendor,
                model=fused_id.model,
                version=fused_id.version,
                device_type=fused_id.device_type,
                device_name=fused_id.device_name,
                confidence=fused_id.confidence,
                sources=fused_id.sources,
                metadata=fused_id.metadata,
            )

        # Detect new and missing devices
        result.new_devices = self._device_map.get_new_devices(current_macs)
        result.missing_devices = self._device_map.get_missing_devices(current_macs)

        # Save updated device map
        self._device_map.save()
        self._progress("Device map saved", 90)

        logger.info(
            f"Hybrid scan complete: {len(fused)} devices fused, "
            f"{len(result.new_devices)} new, "
            f"{len(result.missing_devices)} missing"
        )

        return result

    def stop_and_fuse(
        self,
        scan_result: ScanResult,
        active_identities: Optional[Dict[str, DeviceIdentity]] = None,
    ) -> HybridScanResult:
        """Convenience: stop capture + parse + fuse in one call.

        Args:
            scan_result:       Active scan result.
            active_identities: Optional pre-computed identities.

        Returns:
            HybridScanResult.
        """
        self.stop_passive()
        result = self.fuse_identities(scan_result, active_identities)
        self._progress("Hybrid scan pipeline complete", 100)
        return result

    @property
    def device_map(self) -> DeviceMap:
        """Access the persistent device map."""
        return self._device_map

    @property
    def sniffer(self) -> PassiveSniffer:
        """Access the passive sniffer."""
        return self._sniffer

    def get_fused_identity_for_ip(
        self,
        ip: str,
        hybrid_result: HybridScanResult,
    ) -> Optional[FusedIdentity]:
        """Look up a fused identity by IP address.

        Args:
            ip:            IP address to look up.
            hybrid_result: Result from stop_and_fuse().

        Returns:
            FusedIdentity if found, None otherwise.
        """
        # Find MAC for this IP
        for mac, fused_ip in hybrid_result.mac_ip_map.items():
            if fused_ip == ip:
                return hybrid_result.fused_identities.get(mac)

        # Fallback: search by IP in fused identities
        for fused in hybrid_result.fused_identities.values():
            if fused.ip == ip:
                return fused

        return None
