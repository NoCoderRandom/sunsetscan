"""
NetWatch Core Module.

This package contains the core network scanning functionality including:
- scanner: nmap-based network scanning
- banner_grabber: raw socket banner grabbing
- http_fingerprinter: HTTP-based device fingerprinting
- nse_scanner: nmap NSE script scanner for enhanced detection
- auth_tester: Default credentials checker
- input_parser: Parse various IP range formats
- network_utils: subnet detection and IP helpers
- passive_sniffer: Background mDNS/SSDP/DHCP packet capture
- packet_parsers: Protocol-specific packet parsing
- oui_lookup: IEEE OUI MAC vendor resolution
- device_map: Persistent MAC→identity mapping
- identity_fusion: Multi-source identity fusion engine
- hybrid_scanner: Passive+active scan orchestrator
"""

from core.findings import FindingRegistry
from core.device_identifier import DeviceIdentifier
from core.identity_fusion import IdentityFusionEngine
from core.host_capability import detect_host_profile, safe_mode_overrides

__all__ = [
    "FindingRegistry",
    "DeviceIdentifier",
    "IdentityFusionEngine",
    "detect_host_profile",
    "safe_mode_overrides",
]
