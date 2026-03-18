"""
NetWatch mDNS/Zeroconf Discovery Module.

Discovers devices that announce themselves via mDNS (Multicast DNS) /
Bonjour / Zeroconf — even if they don't respond to nmap port scans.

Common device types discovered:
  - Apple devices (iPhones, iPads, Macs) — _apple-mobdev2._tcp, _device-info._tcp
  - Google Chromecast, Home, Nest devices — _googlecast._tcp
  - Network printers — _ipp._tcp, _pdl-datastream._tcp, _printer._tcp
  - Smart home hubs — _hap._tcp (HomeKit), _hue._tcp
  - AirPlay speakers/screens — _airplay._tcp, _raop._tcp
  - SSH/HTTP services — _ssh._tcp, _http._tcp
  - Generic services announcing via mDNS

Devices discovered here are returned as ScanResult-compatible dicts and
also as INFO findings so they appear in the HTML report.

Exports:
    discover_mdns_devices(timeout): Returns list of DiscoveredDevice
    run_mdns_discovery(timeout): Returns List[Finding]
"""

import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from core.findings import Finding, Severity, Confidence

logger = logging.getLogger(__name__)

# mDNS service types to query
# Each tuple: (service_type, device_category, display_name)
_MDNS_SERVICE_TYPES = [
    ("_http._tcp.local.", "Web Service", "HTTP"),
    ("_https._tcp.local.", "Web Service", "HTTPS"),
    ("_ssh._tcp.local.", "Remote Access", "SSH"),
    ("_sftp-ssh._tcp.local.", "Remote Access", "SFTP"),
    ("_googlecast._tcp.local.", "Media", "Chromecast/Google Cast"),
    ("_airplay._tcp.local.", "Media", "AirPlay"),
    ("_raop._tcp.local.", "Media", "AirPlay Audio"),
    ("_apple-mobdev2._tcp.local.", "Apple Device", "Apple Mobile Device"),
    ("_device-info._tcp.local.", "Device Info", "Device Information"),
    ("_ipp._tcp.local.", "Printer", "Internet Printing Protocol"),
    ("_ipps._tcp.local.", "Printer", "Secure IPP"),
    ("_pdl-datastream._tcp.local.", "Printer", "Printer Data Stream"),
    ("_printer._tcp.local.", "Printer", "LPD Printer"),
    ("_hap._tcp.local.", "Smart Home", "HomeKit Accessory"),
    ("_hue._tcp.local.", "Smart Home", "Philips Hue Bridge"),
    ("_smb._tcp.local.", "File Share", "SMB/CIFS"),
    ("_afpovertcp._tcp.local.", "File Share", "AFP (Apple File Protocol)"),
    ("_nfs._tcp.local.", "File Share", "NFS"),
    ("_homekit._tcp.local.", "Smart Home", "HomeKit"),
    ("_matter._tcp.local.", "Smart Home", "Matter Protocol"),
    ("_miio._udp.local.", "Smart Home", "Xiaomi Mi IO"),
    ("_esphomelib._tcp.local.", "Smart Home", "ESPHome"),
    ("_nas._tcp.local.", "NAS", "Network Attached Storage"),
    ("_synology._tcp.local.", "NAS", "Synology NAS"),
    ("_nzbget._tcp.local.", "Media Server", "NZBGet"),
    ("_plex._tcp.local.", "Media Server", "Plex Media Server"),
    ("_jellyfin._tcp.local.", "Media Server", "Jellyfin"),
]

_MDNS_MULTICAST_ADDR = "224.0.0.251"
_MDNS_PORT = 5353
_QUERY_TIMEOUT = 3  # seconds per query
_DEFAULT_DISCOVERY_TIMEOUT = 8  # total discovery time


@dataclass
class DiscoveredDevice:
    """A device found via mDNS announcement."""
    ip: str
    hostname: str = ""
    service_type: str = ""
    service_name: str = ""
    device_category: str = ""
    port: int = 0
    properties: Dict[str, str] = field(default_factory=dict)


def _build_mdns_query(service_type: str) -> bytes:
    """Build a DNS-SD PTR query packet for the given service type."""
    # DNS query packet structure
    # Transaction ID: 0x0000 (mDNS uses 0)
    # Flags: 0x0000 (standard query)
    # Questions: 1
    # Answer/Auth/Additional: 0 each
    header = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'

    # Encode the service type as DNS labels
    labels = b''
    for part in service_type.rstrip('.').split('.'):
        labels += bytes([len(part)]) + part.encode()
    labels += b'\x00'  # root label

    # Type PTR (12), Class IN (1)
    query = labels + b'\x00\x0c\x00\x01'

    return header + query


def _parse_mdns_response(data: bytes, src_ip: str) -> Optional[DiscoveredDevice]:
    """Parse an mDNS response packet. Returns DiscoveredDevice or None."""
    try:
        if len(data) < 12:
            return None

        # Check this is a response (QR bit = 1)
        flags = int.from_bytes(data[2:4], 'big')
        if not (flags & 0x8000):
            return None  # Not a response

        # Look for A records (type 1) to get IP address
        # Simple scan for IP address patterns in the response
        # We extract hostname from the response name field
        hostname = ""
        port = 0
        device_ip = src_ip

        # Scan response for SRV records (type 33) to get port
        # and PTR records (type 12) to get service name
        pos = 12  # skip header

        # Skip questions
        num_questions = int.from_bytes(data[6:8], 'big')
        for _ in range(num_questions):
            # Skip name
            pos = _skip_name(data, pos)
            pos += 4  # type + class

        # Parse answers
        num_answers = int.from_bytes(data[8:10], 'big')
        for _ in range(num_answers):
            if pos >= len(data):
                break
            name_end = _skip_name(data, pos)
            if name_end + 10 > len(data):
                break
            rtype = int.from_bytes(data[name_end:name_end + 2], 'big')
            rdlen = int.from_bytes(data[name_end + 8:name_end + 10], 'big')
            rdata_start = name_end + 10
            rdata_end = rdata_start + rdlen

            if rtype == 33:  # SRV record — extract port
                if rdata_start + 6 <= len(data):
                    port = int.from_bytes(data[rdata_start + 4:rdata_start + 6], 'big')
            elif rtype == 1:  # A record — extract IP
                if rdlen == 4 and rdata_start + 4 <= len(data):
                    device_ip = '.'.join(str(b) for b in data[rdata_start:rdata_end])
            elif rtype == 16:  # TXT record — hostname hint
                if rdata_start < len(data):
                    try:
                        txt_len = data[rdata_start]
                        txt = data[rdata_start + 1:rdata_start + 1 + txt_len].decode('utf-8', errors='ignore')
                        if 'name=' in txt.lower():
                            hostname = txt.split('=', 1)[1]
                    except Exception:
                        pass

            pos = rdata_end if rdata_end > pos else pos + 1

        if not hostname:
            # Try to resolve the source IP to a hostname
            try:
                hostname = socket.gethostbyaddr(src_ip)[0]
            except Exception:
                hostname = ""

        return DiscoveredDevice(
            ip=device_ip,
            hostname=hostname,
            port=port,
        )
    except Exception as e:
        logger.debug(f"mDNS parse error from {src_ip}: {e}")
        return None


def _skip_name(data: bytes, pos: int) -> int:
    """Skip a DNS name field and return the position after it."""
    while pos < len(data):
        length = data[pos]
        if length == 0:
            return pos + 1
        if (length & 0xC0) == 0xC0:  # pointer
            return pos + 2
        pos += 1 + length
    return pos


def discover_mdns_devices(timeout: float = _DEFAULT_DISCOVERY_TIMEOUT) -> List[DiscoveredDevice]:
    """Discover devices via mDNS multicast queries.

    Sends DNS-SD PTR queries for common service types and collects responses.

    Args:
        timeout: Total discovery time in seconds.

    Returns:
        List of DiscoveredDevice objects (deduplicated by IP).
    """
    discovered: Dict[str, DiscoveredDevice] = {}  # ip -> device
    lock = threading.Lock()
    stop_event = threading.Event()

    def listen_for_responses():
        """Listen on UDP 5353 for mDNS responses."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
            sock.settimeout(0.5)
            sock.bind(('', _MDNS_PORT))

            # Join mDNS multicast group
            import struct
            mreq = struct.pack('4sL', socket.inet_aton(_MDNS_MULTICAST_ADDR), socket.INADDR_ANY)
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            except OSError:
                pass  # May fail if not root, continue anyway

            while not stop_event.is_set():
                try:
                    data, addr = sock.recvfrom(4096)
                    src_ip = addr[0]
                    device = _parse_mdns_response(data, src_ip)
                    if device and device.ip:
                        with lock:
                            if device.ip not in discovered:
                                discovered[device.ip] = device
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.debug(f"mDNS recv error: {e}")
                    break
            sock.close()
        except Exception as e:
            logger.debug(f"mDNS listener setup failed: {e}")

    def send_queries():
        """Send mDNS PTR queries for each service type."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
            sock.settimeout(1.0)

            for service_type, category, display_name in _MDNS_SERVICE_TYPES:
                if stop_event.is_set():
                    break
                try:
                    query = _build_mdns_query(service_type)
                    sock.sendto(query, (_MDNS_MULTICAST_ADDR, _MDNS_PORT))
                    time.sleep(0.1)  # Brief pause between queries
                except Exception as e:
                    logger.debug(f"mDNS query send error for {service_type}: {e}")
            sock.close()
        except Exception as e:
            logger.debug(f"mDNS sender setup failed: {e}")

    # Start listener thread
    listener = threading.Thread(target=listen_for_responses, daemon=True)
    listener.start()

    # Brief pause to let listener initialise
    time.sleep(0.3)

    # Send queries
    sender = threading.Thread(target=send_queries, daemon=True)
    sender.start()
    sender.join(timeout=min(timeout / 2, 5.0))

    # Wait for responses
    time.sleep(max(timeout - 5.0, 2.0))

    # Stop listener
    stop_event.set()
    listener.join(timeout=2.0)

    # Also try zeroconf for richer discovery
    zeroconf_devices = _discover_via_zeroconf(timeout=min(timeout, 6.0))
    for dev in zeroconf_devices:
        with lock:
            if dev.ip not in discovered:
                discovered[dev.ip] = dev
            else:
                # Merge hostname/category if richer
                existing = discovered[dev.ip]
                if dev.hostname and not existing.hostname:
                    existing.hostname = dev.hostname
                if dev.service_type and not existing.service_type:
                    existing.service_type = dev.service_type
                    existing.service_name = dev.service_name
                    existing.device_category = dev.device_category

    return list(discovered.values())


def _discover_via_zeroconf(timeout: float = 6.0) -> List[DiscoveredDevice]:
    """Use the zeroconf library for richer mDNS discovery."""
    devices: Dict[str, DiscoveredDevice] = {}

    try:
        from zeroconf import Zeroconf, ServiceBrowser, ServiceListener

        class _Listener(ServiceListener):
            def add_service(self, zc, type_, name):
                try:
                    info = zc.get_service_info(type_, name, timeout=2000)
                    if info and info.addresses:
                        import ipaddress
                        for addr_bytes in info.addresses:
                            try:
                                ip = str(ipaddress.ip_address(addr_bytes))
                                category = "Unknown"
                                for st, cat, _ in _MDNS_SERVICE_TYPES:
                                    if st.rstrip('.') == type_.rstrip('.'):
                                        category = cat
                                        break
                                dev = DiscoveredDevice(
                                    ip=ip,
                                    hostname=info.server or name,
                                    service_type=type_,
                                    service_name=name,
                                    device_category=category,
                                    port=info.port or 0,
                                )
                                if ip not in devices:
                                    devices[ip] = dev
                            except Exception:
                                pass
                except Exception as e:
                    logger.debug(f"zeroconf service info error: {e}")

            def remove_service(self, zc, type_, name):
                pass

            def update_service(self, zc, type_, name):
                pass

        zc = Zeroconf()
        listener = _Listener()
        service_types = [st for st, _, _ in _MDNS_SERVICE_TYPES]
        browser = ServiceBrowser(zc, service_types, listener)
        time.sleep(timeout)
        zc.close()

    except ImportError:
        logger.debug("zeroconf library not available — using raw mDNS fallback")
    except Exception as e:
        logger.debug(f"zeroconf discovery error: {e}")

    return list(devices.values())


def run_mdns_discovery(
    timeout: float = _DEFAULT_DISCOVERY_TIMEOUT,
    known_hosts: Optional[Set[str]] = None
) -> List[Finding]:
    """Run mDNS discovery and return findings for new/unknown devices.

    Args:
        timeout:     Discovery duration in seconds.
        known_hosts: Set of IP addresses already found by nmap (to identify NEW devices).

    Returns:
        List of Finding objects — one INFO per discovered device,
        plus MEDIUM findings for any device NOT seen in the nmap scan
        (devices that evade regular scanning).
    """
    if known_hosts is None:
        known_hosts = set()

    findings: List[Finding] = []

    logger.info(f"Starting mDNS discovery (timeout={timeout}s)")
    devices = discover_mdns_devices(timeout=timeout)

    if not devices:
        logger.info("mDNS discovery: no devices found")
        return findings

    for device in devices:
        is_new = device.ip not in known_hosts
        category = device.device_category or "Network Device"
        service_info = f" ({device.service_name})" if device.service_name else ""
        hostname_info = f" [{device.hostname}]" if device.hostname else ""

        if is_new:
            # Device only visible via mDNS — not in nmap results
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title=f"mDNS-only device discovered: {device.ip}{hostname_info}",
                host=device.ip,
                port=device.port or 5353,
                protocol="udp",
                category="mDNS Discovery",
                description=(
                    f"Device {device.ip}{hostname_info} was discovered via mDNS "
                    f"(Bonjour/Zeroconf) but was NOT detected by the nmap port scan. "
                    f"Service: {category}{service_info}. "
                    "This device is communicating on the network but evades standard scanning."
                ),
                explanation=(
                    "Some devices (Apple mobile devices, smart home hubs, IoT devices) "
                    "respond to mDNS queries even when they block or ignore TCP/UDP port scans. "
                    "Devices that evade port scanning represent a blind spot in network visibility. "
                    "They may be running outdated firmware, have security vulnerabilities, "
                    "or be rogue devices added without IT approval."
                ),
                recommendation=(
                    "1. Identify this device: check your DHCP server/router for MAC address.\n"
                    f"2. If device is unexpected, investigate: who added {device.ip} to the network?\n"
                    "3. Check device firmware version and apply available updates.\n"
                    "4. Consider network segmentation (IoT VLAN) to isolate smart home devices."
                ),
                evidence=(
                    f"mDNS response from {device.ip} | "
                    f"service_type={device.service_type} | "
                    f"hostname={device.hostname} | port={device.port}"
                ),
                confidence=Confidence.CONFIRMED,
                tags=["mdns", "discovery", "new-device", "zeroconf", category.lower().replace(' ', '-')],
            ))
        else:
            # Known device also announcing via mDNS — add INFO
            findings.append(Finding(
                severity=Severity.INFO,
                title=f"mDNS service: {category}{service_info} on {device.ip}",
                host=device.ip,
                port=device.port or 5353,
                protocol="udp",
                category="mDNS Discovery",
                description=(
                    f"Device {device.ip}{hostname_info} is advertising via mDNS: "
                    f"{category} — {device.service_type or 'unknown service type'}. "
                    f"Port: {device.port or 'unknown'}."
                ),
                explanation=(
                    "mDNS (Multicast DNS) is used by Apple Bonjour, Google Cast, and "
                    "other protocols for zero-configuration service discovery. "
                    "Devices advertising via mDNS are visible to all devices on the local network."
                ),
                recommendation=(
                    "Review whether mDNS/Bonjour should be enabled on this network. "
                    "On sensitive networks, consider disabling mDNS to prevent service enumeration. "
                    "Ensure the device is running current firmware."
                ),
                evidence=(
                    f"mDNS: {device.service_type} from {device.ip} | "
                    f"hostname={device.hostname} | port={device.port}"
                ),
                confidence=Confidence.CONFIRMED,
                tags=["mdns", "zeroconf", "bonjour", category.lower().replace(' ', '-')],
            ))

    return findings
