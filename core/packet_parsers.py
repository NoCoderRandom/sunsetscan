"""
NetWatch Packet Parsers Module.

Parses raw network packets captured by the passive sniffer into structured
device metadata. Supports three discovery protocols:

    - mDNS (Multicast DNS, UDP 5353): device names, service types, model IDs
    - SSDP/UPnP (UDP 1900): device type, manufacturer, model
    - DHCP (UDP 67/68): hostname, OS hints (options 12, 55, 60)

Each parser accepts raw packet bytes and returns a structured dict of
extracted fields. The identity fusion engine merges these into per-device
identity records.

Exports:
    parse_mdns_packet:  Parse mDNS response for device metadata
    parse_ssdp_packet:  Parse SSDP/UPnP announcement
    parse_dhcp_packet:  Parse DHCP request/reply for hostname and OS hints
    ParsedPacket:       Dataclass for parser output
"""

import logging
import re
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ParsedPacket:
    """Structured output from a packet parser.

    Attributes:
        protocol:    Protocol name (mdns, ssdp, dhcp)
        src_ip:      Source IP address
        src_mac:     Source MAC address (if available)
        hostname:    Device hostname
        device_type: Device type / category
        vendor:      Manufacturer / vendor name
        model:       Device model name
        version:     Firmware / protocol version string (e.g. rpVr=715.2)
        os_hint:     Operating system hint
        services:    List of discovered service types
        raw_fields:  Additional raw fields for debugging
    """
    protocol: str = ""
    src_ip: str = ""
    src_mac: str = ""
    hostname: str = ""
    device_type: str = ""
    vendor: str = ""
    model: str = ""
    version: str = ""
    os_hint: str = ""
    services: List[str] = field(default_factory=list)
    raw_fields: Dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# mDNS Parser
# ---------------------------------------------------------------------------

def _dns_decode_name(data: bytes, offset: int) -> tuple:
    """Decode a DNS name from packet data, handling compression pointers.

    Returns (name_string, bytes_consumed).
    """
    parts = []
    original_offset = offset
    jumped = False
    bytes_consumed = 0

    while offset < len(data):
        length = data[offset]

        if length == 0:
            if not jumped:
                bytes_consumed = offset - original_offset + 1
            break

        if (length & 0xC0) == 0xC0:
            # Compression pointer
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                bytes_consumed = offset - original_offset + 2
            jumped = True
            offset = pointer
            continue

        offset += 1
        if offset + length > len(data):
            break
        parts.append(data[offset:offset + length].decode('utf-8', errors='replace'))
        offset += length

    if not jumped:
        bytes_consumed = offset - original_offset + 1

    return '.'.join(parts), bytes_consumed


def parse_mdns_packet(data: bytes, src_ip: str, src_mac: str = "") -> Optional[ParsedPacket]:
    """Parse an mDNS packet for device identification metadata.

    Extracts:
        - Device hostname from A/AAAA record names
        - Service types from PTR records
        - Device name from TXT records (key=value pairs)
        - Model identifiers from TXT records (model=, md=)
        - Port numbers from SRV records

    Args:
        data:    Raw UDP payload (DNS message).
        src_ip:  Source IP address.
        src_mac: Source MAC address (from L2 header).

    Returns:
        ParsedPacket with extracted fields, or None if unparseable.
    """
    if len(data) < 12:
        return None

    flags = struct.unpack('!H', data[2:4])[0]
    # Accept both queries and responses — queries reveal the sender's name
    is_response = bool(flags & 0x8000)

    num_questions = struct.unpack('!H', data[4:6])[0]
    num_answers = struct.unpack('!H', data[6:8])[0]
    num_authority = struct.unpack('!H', data[8:10])[0]
    num_additional = struct.unpack('!H', data[10:12])[0]
    total_rrs = num_answers + num_authority + num_additional

    result = ParsedPacket(
        protocol="mdns",
        src_ip=src_ip,
        src_mac=src_mac,
    )

    pos = 12

    # Skip questions
    for _ in range(num_questions):
        if pos >= len(data):
            break
        name, consumed = _dns_decode_name(data, pos)
        pos += consumed
        pos += 4  # QTYPE + QCLASS
        # Question names can reveal the querier's hostname
        if name and '.local' in name.lower():
            _extract_hostname_from_name(name, result)

    # Parse resource records
    for _ in range(total_rrs):
        if pos >= len(data):
            break

        rr_name, consumed = _dns_decode_name(data, pos)
        pos += consumed

        if pos + 10 > len(data):
            break

        rr_type = struct.unpack('!H', data[pos:pos + 2])[0]
        # rr_class = struct.unpack('!H', data[pos + 2:pos + 4])[0]
        # rr_ttl = struct.unpack('!I', data[pos + 4:pos + 8])[0]
        rr_rdlen = struct.unpack('!H', data[pos + 8:pos + 10])[0]
        pos += 10
        rdata_start = pos
        rdata_end = pos + rr_rdlen

        if rdata_end > len(data):
            break

        try:
            if rr_type == 12:  # PTR — service type
                ptr_name, _ = _dns_decode_name(data, rdata_start)
                if ptr_name:
                    result.services.append(rr_name)
                    _extract_hostname_from_name(ptr_name, result)

            elif rr_type == 1:  # A record
                if rr_rdlen == 4:
                    ip = '.'.join(str(b) for b in data[rdata_start:rdata_end])
                    result.raw_fields['a_record'] = ip
                _extract_hostname_from_name(rr_name, result)

            elif rr_type == 33:  # SRV record — port + target
                if rr_rdlen >= 6:
                    port = struct.unpack('!H', data[rdata_start + 4:rdata_start + 6])[0]
                    result.raw_fields['srv_port'] = str(port)
                    target_name, _ = _dns_decode_name(data, rdata_start + 6)
                    if target_name:
                        _extract_hostname_from_name(target_name, result)

            elif rr_type == 16:  # TXT record — key=value metadata
                txt_pos = rdata_start
                while txt_pos < rdata_end:
                    txt_len = data[txt_pos]
                    txt_pos += 1
                    if txt_pos + txt_len > rdata_end:
                        break
                    txt_str = data[txt_pos:txt_pos + txt_len].decode('utf-8', errors='replace')
                    txt_pos += txt_len
                    _process_mdns_txt(txt_str, result)

        except Exception as e:
            logger.debug(f"mDNS RR parse error at pos {pos}: {e}")

        pos = rdata_end

    # Derive device type from service types
    if not result.device_type and result.services:
        result.device_type = _mdns_service_to_device_type(result.services)

    return result if (result.hostname or result.services or result.vendor) else None


def _extract_hostname_from_name(name: str, result: ParsedPacket) -> None:
    """Extract a clean hostname from a DNS name if it looks like a device name."""
    if not name:
        return
    # Strip .local suffix
    host = re.sub(r'\.local\.?$', '', name, flags=re.I)
    # Strip service type prefix (e.g., "My Device._http._tcp" -> "My Device")
    host = re.sub(r'\._[a-z0-9_-]+\._(?:tcp|udp)$', '', host, flags=re.I)
    if host and not host.startswith('_') and len(host) > 1:
        # Prefer longer, more descriptive hostnames
        if not result.hostname or len(host) > len(result.hostname):
            result.hostname = host


def _process_mdns_txt(txt: str, result: ParsedPacket) -> None:
    """Process a single mDNS TXT key=value pair for device metadata."""
    if '=' not in txt:
        return
    key, _, value = txt.partition('=')
    key = key.strip().lower()
    value = value.strip()

    if not value:
        return

    result.raw_fields[f"txt_{key}"] = value

    # Common TXT record keys used for device identification
    if key in ('fn', 'name', 'friendly_name', 'n'):
        if not result.hostname or len(value) > len(result.hostname):
            result.hostname = value
    elif key in ('md', 'model', 'mdl', 'ty', 'rpmd'):
        # 'rpmd' is the Apple Remote Pairing model field used by
        # _companion-link._tcp — e.g. rpMd=AppleTV6,2. Must be recognised
        # alongside the standard Bonjour model keys.
        result.model = value
    elif key in ('manufacturer', 'mfg', 'usb_mfg'):
        result.vendor = value
    elif key == 'os':
        result.os_hint = value
    elif key in ('rpvr',):
        # Apple Remote Pairing version string (e.g. rpVr=715.2)
        if not result.version:
            result.version = value
    elif key in ('am', 'adminurl'):
        result.raw_fields['admin_url'] = value


_MDNS_SERVICE_DEVICE_MAP = {
    '_ipp._tcp': 'Printer',
    '_ipps._tcp': 'Printer',
    '_pdl-datastream._tcp': 'Printer',
    '_printer._tcp': 'Printer',
    '_scanner._tcp': 'Scanner',
    '_googlecast._tcp': 'Media Device',
    '_airplay._tcp': 'Media Device',
    '_raop._tcp': 'Media Device',
    '_apple-mobdev2._tcp': 'Apple Mobile Device',
    '_hap._tcp': 'Smart Home Device',
    '_hue._tcp': 'Smart Light',
    '_homekit._tcp': 'Smart Home Device',
    '_matter._tcp': 'Smart Home Device',
    '_esphomelib._tcp': 'IoT Device',
    '_miio._udp': 'IoT Device',
    '_ssh._tcp': 'Server',
    '_smb._tcp': 'File Server',
    '_afpovertcp._tcp': 'File Server',
    '_nfs._tcp': 'File Server',
    '_plex._tcp': 'Media Server',
    '_jellyfin._tcp': 'Media Server',
    '_synology._tcp': 'NAS',
}


def _mdns_service_to_device_type(services: List[str]) -> str:
    """Map mDNS service types to a device type string."""
    for svc in services:
        clean = svc.rstrip('.').lower()
        for pattern, dtype in _MDNS_SERVICE_DEVICE_MAP.items():
            if pattern in clean:
                return dtype
    return ""


# ---------------------------------------------------------------------------
# SSDP / UPnP Parser
# ---------------------------------------------------------------------------

def parse_ssdp_packet(data: bytes, src_ip: str, src_mac: str = "") -> Optional[ParsedPacket]:
    """Parse an SSDP NOTIFY or M-SEARCH response for device metadata.

    Extracts:
        - Device type from NT/ST headers
        - Server software from SERVER header
        - Device description URL from LOCATION header

    Args:
        data:    Raw UDP payload.
        src_ip:  Source IP address.
        src_mac: Source MAC address.

    Returns:
        ParsedPacket with extracted fields, or None if unparseable.
    """
    try:
        text = data.decode('utf-8', errors='replace')
    except Exception:
        return None

    if not ('NOTIFY' in text[:10] or 'HTTP/' in text[:10] or 'M-SEARCH' in text[:10]):
        return None

    result = ParsedPacket(
        protocol="ssdp",
        src_ip=src_ip,
        src_mac=src_mac,
    )

    headers: Dict[str, str] = {}
    for line in text.splitlines():
        if ':' in line:
            key, _, value = line.partition(':')
            headers[key.strip().upper()] = value.strip()

    # Server header often contains OS and device info
    server = headers.get('SERVER', '')
    if server:
        result.raw_fields['server'] = server
        _parse_ssdp_server_header(server, result)

    # NT (Notification Type) or ST (Search Target)
    nt = headers.get('NT', '') or headers.get('ST', '')
    if nt:
        result.raw_fields['nt'] = nt
        if 'InternetGatewayDevice' in nt:
            result.device_type = 'Router'
        elif 'MediaRenderer' in nt:
            result.device_type = 'Media Device'
        elif 'MediaServer' in nt:
            result.device_type = 'Media Server'
        elif 'Printer' in nt:
            result.device_type = 'Printer'

    # USN (Unique Service Name) — may contain device UUID
    usn = headers.get('USN', '')
    if usn:
        result.raw_fields['usn'] = usn

    # Location header points to device description XML
    location = headers.get('LOCATION', '')
    if location:
        result.raw_fields['location'] = location

    return result if (result.vendor or result.device_type or result.hostname or server) else None


def _parse_ssdp_server_header(server: str, result: ParsedPacket) -> None:
    """Extract OS and vendor hints from the SSDP SERVER header.

    Typical format: "Linux/3.10 UPnP/1.0 IPC-Webserver/1.0"
    """
    # OS hint from first token
    os_match = re.match(r'(Linux|Windows|Darwin|FreeBSD|Android)[\s/]*([\d.]*)', server, re.I)
    if os_match:
        result.os_hint = os_match.group(0)

    # Known vendor patterns
    vendor_patterns = [
        (r'Synology', 'Synology'),
        (r'QNAP', 'QNAP'),
        (r'MiniDLNA', ''),
        (r'Plex', 'Plex'),
        (r'Roku', 'Roku'),
        (r'Samsung', 'Samsung'),
        (r'LG\b', 'LG'),
        (r'Sony', 'Sony'),
        (r'Philips', 'Philips'),
        (r'Google', 'Google'),
        (r'Apple', 'Apple'),
        (r'Sonos', 'Sonos'),
        (r'Belkin', 'Belkin'),
        (r'Netgear', 'Netgear'),
        (r'TP-Link', 'TP-Link'),
        (r'D-Link', 'D-Link'),
        (r'ASUS', 'ASUS'),
    ]
    for pattern, vendor in vendor_patterns:
        if re.search(pattern, server, re.I):
            result.vendor = vendor
            break


# ---------------------------------------------------------------------------
# DHCP Parser
# ---------------------------------------------------------------------------

# DHCP option codes we care about
_DHCP_OPT_HOSTNAME = 12       # Client hostname
_DHCP_OPT_VENDOR_CLASS = 60   # Vendor Class Identifier (OS hint)
_DHCP_OPT_PARAM_LIST = 55     # Parameter Request List (OS fingerprint)
_DHCP_OPT_MESSAGE_TYPE = 53   # DHCP message type
_DHCP_OPT_CLIENT_ID = 61      # Client identifier (may contain MAC)

# DHCP magic cookie
_DHCP_MAGIC = b'\x63\x82\x53\x63'


def parse_dhcp_packet(data: bytes, src_ip: str = "", src_mac: str = "") -> Optional[ParsedPacket]:
    """Parse a DHCP packet for hostname and OS identification hints.

    Extracts:
        - Hostname (option 12)
        - Vendor Class ID / OS hint (option 60)
        - Parameter Request List fingerprint (option 55)
        - Client MAC from DHCP header

    Args:
        data:    Raw UDP payload (BOOTP/DHCP message).
        src_ip:  Source IP address.
        src_mac: Source MAC address from L2.

    Returns:
        ParsedPacket with extracted fields, or None if unparseable.
    """
    # DHCP header is at least 236 bytes + 4-byte magic cookie
    if len(data) < 240:
        return None

    # Verify DHCP magic cookie at offset 236
    if data[236:240] != _DHCP_MAGIC:
        return None

    result = ParsedPacket(
        protocol="dhcp",
        src_ip=src_ip,
        src_mac=src_mac,
    )

    # Extract client MAC from DHCP header (bytes 28-34, 6-byte hardware address)
    chaddr = data[28:34]
    client_mac = ':'.join(f'{b:02x}' for b in chaddr)
    if client_mac != '00:00:00:00:00:00':
        result.src_mac = client_mac

    # Extract client IP (ciaddr) if present
    ciaddr = data[12:16]
    if ciaddr != b'\x00\x00\x00\x00':
        result.src_ip = '.'.join(str(b) for b in ciaddr)

    # Parse DHCP options starting after magic cookie
    pos = 240
    while pos < len(data):
        opt_code = data[pos]
        pos += 1

        if opt_code == 255:  # End
            break
        if opt_code == 0:  # Padding
            continue

        if pos >= len(data):
            break
        opt_len = data[pos]
        pos += 1

        if pos + opt_len > len(data):
            break

        opt_data = data[pos:pos + opt_len]
        pos += opt_len

        if opt_code == _DHCP_OPT_HOSTNAME:
            hostname = opt_data.decode('utf-8', errors='replace').strip('\x00')
            if hostname:
                result.hostname = hostname

        elif opt_code == _DHCP_OPT_VENDOR_CLASS:
            vendor_class = opt_data.decode('utf-8', errors='replace').strip('\x00')
            if vendor_class:
                result.raw_fields['vendor_class'] = vendor_class
                _parse_dhcp_vendor_class(vendor_class, result)

        elif opt_code == _DHCP_OPT_PARAM_LIST:
            # Parameter Request List — a fingerprint of the DHCP client
            param_list = ','.join(str(b) for b in opt_data)
            result.raw_fields['param_list'] = param_list
            _fingerprint_dhcp_params(opt_data, result)

        elif opt_code == _DHCP_OPT_MESSAGE_TYPE:
            msg_types = {1: 'DISCOVER', 2: 'OFFER', 3: 'REQUEST',
                         4: 'DECLINE', 5: 'ACK', 6: 'NAK', 7: 'RELEASE', 8: 'INFORM'}
            if opt_data:
                result.raw_fields['dhcp_type'] = msg_types.get(opt_data[0], str(opt_data[0]))

    return result if (result.hostname or result.os_hint or result.vendor) else None


def _parse_dhcp_vendor_class(vendor_class: str, result: ParsedPacket) -> None:
    """Parse DHCP option 60 (Vendor Class ID) for OS and device hints.

    Common values:
        - "MSFT 5.0" → Windows
        - "android-dhcp-*" → Android
        - "dhcpcd-*" → Linux
        - "udhcp*" → Embedded Linux / BusyBox
    """
    vc = vendor_class.lower()

    if 'msft' in vc:
        result.os_hint = 'Windows'
    elif 'android' in vc:
        result.os_hint = 'Android'
        result.device_type = 'Mobile Device'
    elif vc.startswith('dhcpcd'):
        result.os_hint = 'Linux'
    elif 'udhcp' in vc:
        result.os_hint = 'Embedded Linux'
        result.device_type = 'Embedded Device'
    elif 'apple' in vc or vc.startswith('1.0'):
        result.os_hint = 'Apple/macOS'
    elif 'cisco' in vc:
        result.vendor = 'Cisco'
        result.device_type = 'Network Device'
    elif 'aruba' in vc:
        result.vendor = 'Aruba'
        result.device_type = 'Access Point'


# Known DHCP parameter request list fingerprints (option 55).
# These are well-known fingerprints from fingerbank.org and dhcp.org.
_DHCP_PARAM_FINGERPRINTS = [
    # (param_set_as_tuple, os_hint, device_type)
    ((1, 3, 6, 15, 26, 28, 51, 58, 59), 'Windows', ''),
    ((1, 3, 6, 15, 44, 46, 47, 57), 'Windows XP', ''),
    ((1, 121, 3, 6, 15, 114, 119, 252), 'macOS', ''),
    ((1, 3, 6, 15, 119, 252), 'macOS', ''),
    ((1, 3, 6, 28), 'Linux', ''),
    ((1, 3, 6, 12, 15, 26, 28), 'Linux', ''),
    ((1, 3, 6, 12, 15, 28, 42), 'Embedded Linux', 'IoT Device'),
]


def _fingerprint_dhcp_params(params: bytes, result: ParsedPacket) -> None:
    """Fingerprint OS from DHCP option 55 parameter request list."""
    param_tuple = tuple(sorted(params))

    for known_params, os_hint, device_type in _DHCP_PARAM_FINGERPRINTS:
        if param_tuple == tuple(sorted(known_params)):
            if not result.os_hint:
                result.os_hint = os_hint
            if device_type and not result.device_type:
                result.device_type = device_type
            return

    # Heuristic: short param lists often indicate embedded devices
    if len(params) <= 4 and not result.os_hint:
        result.os_hint = 'Embedded'
        if not result.device_type:
            result.device_type = 'Embedded Device'
