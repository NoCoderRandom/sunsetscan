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
"""

from core.scanner import NetworkScanner
from core.banner_grabber import BannerGrabber
from core.http_fingerprinter import HttpFingerprinter
from core.nse_scanner import NSEScanner
from core.auth_tester import AuthTester
from core.input_parser import parse_target_input, format_target_summary
from core.network_utils import get_local_subnet, validate_cidr, expand_cidr

__all__ = [
    "NetworkScanner",
    "BannerGrabber", 
    "HttpFingerprinter",
    "NSEScanner",
    "AuthTester",
    "parse_target_input",
    "format_target_summary",
    "get_local_subnet",
    "validate_cidr",
    "expand_cidr",
]
