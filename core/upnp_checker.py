"""
NetWatch UPnP Exposure Checker.

Discovers UPnP-enabled devices on the local network using SSDP
(Simple Service Discovery Protocol) multicast and analyses the risk.

All checks are passive read-only operations. No network configuration
is modified. The SSDP M-SEARCH is the same packet that any UPnP client
(Windows, media players, etc.) sends constantly.

Checks performed:
    1. SSDP M-SEARCH broadcast on 239.255.255.250:1900
    2. Parse device description XML to identify the device and capabilities
    3. Check for WAN-side port mapping (IGD/WANIPConnection service)

Findings produced:
    HIGH    - Internet Gateway Device (IGD) with WAN port mapping capability
              (attacker could open inbound ports through your router)
    MEDIUM  - UPnP-enabled device found (UPnP is a known attack vector)
    INFO    - UPnP device enumeration (device type, friendly name)
"""

import logging
import re
import socket
import struct
from typing import Dict, List, Optional
from xml.etree import ElementTree

import requests
import urllib3

from core.findings import Finding, Severity

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
SSDP_MX = 2           # Max wait seconds for responses
SSDP_TIMEOUT = 3.0    # Socket timeout
HTTP_TIMEOUT = 5.0    # Timeout for description XML fetch

# SSDP M-SEARCH message targeting all UPnP root devices
SSDP_REQUEST = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    f"MX: {SSDP_MX}\r\n"
    "ST: upnp:rootdevice\r\n"
    "\r\n"
).encode("utf-8")

# UPnP services that indicate WAN-side port mapping capability
IGD_SERVICES = {
    "urn:schemas-upnp-org:service:WANIPConnection",
    "urn:schemas-upnp-org:service:WANPPPConnection",
    "urn:schemas-upnp-org:device:InternetGatewayDevice",
}


def _send_ssdp_discover(timeout: float = SSDP_TIMEOUT) -> List[Dict[str, str]]:
    """Send an SSDP M-SEARCH and collect all responses.

    Returns a list of parsed SSDP response dicts, each with at minimum
    a 'location' key pointing to the device description XML URL.
    """
    devices: List[Dict[str, str]] = []
    seen_locations: set = set()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)

        # Enable multicast
        sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_MULTICAST_TTL,
            struct.pack("b", 1),  # TTL=1 (LAN only)
        )

        sock.sendto(SSDP_REQUEST, (SSDP_ADDR, SSDP_PORT))

        while True:
            try:
                data, addr = sock.recvfrom(1024)
                text = data.decode("utf-8", errors="ignore")
                device = _parse_ssdp_response(text, addr[0])
                location = device.get("location", "")
                if location and location not in seen_locations:
                    seen_locations.add(location)
                    devices.append(device)
            except socket.timeout:
                break
            except Exception as e:
                logger.debug(f"SSDP receive error: {e}")
                break

    except (socket.error, OSError) as e:
        logger.debug(f"SSDP socket error: {e}")
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return devices


def _parse_ssdp_response(text: str, source_ip: str) -> Dict[str, str]:
    """Parse an SSDP HTTP response into a dict of headers."""
    result: Dict[str, str] = {"_source_ip": source_ip}
    for line in text.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            result[key.strip().lower()] = value.strip()
    return result


def _fetch_device_description(location: str) -> Optional[Dict]:
    """Fetch and parse the UPnP device description XML.

    Returns a dict with: friendly_name, device_type, manufacturer, services.
    Returns None if the fetch or parse fails.
    """
    try:
        resp = requests.get(location, timeout=HTTP_TIMEOUT, verify=False)
        resp.raise_for_status()
    except requests.RequestException as e:
        logger.debug(f"UPnP description fetch failed {location}: {e}")
        return None

    try:
        root = ElementTree.fromstring(resp.content)
        ns = {"upnp": "urn:schemas-upnp-org:device-1-0"}

        def find(tag: str) -> str:
            el = root.find(f".//upnp:{tag}", ns)
            if el is None:
                el = root.find(f".//{tag}")  # Try without namespace
            return el.text.strip() if el is not None and el.text else ""

        # Collect all service types
        service_types: List[str] = []
        for el in root.iter():
            if el.tag.endswith("serviceType") and el.text:
                service_types.append(el.text.strip())

        return {
            "friendly_name": find("friendlyName"),
            "device_type": find("deviceType"),
            "manufacturer": find("manufacturer"),
            "model": find("modelName"),
            "services": service_types,
        }

    except ElementTree.ParseError as e:
        logger.debug(f"UPnP XML parse failed: {e}")
        return None


def run_upnp_checks(timeout: float = SSDP_TIMEOUT) -> List[Finding]:
    """Discover UPnP devices via SSDP and assess their risk.

    Args:
        timeout: How long to wait for SSDP responses (seconds).

    Returns:
        List of Finding objects.
    """
    findings: List[Finding] = []

    logger.debug("Sending SSDP M-SEARCH for UPnP devices...")
    raw_devices = _send_ssdp_discover(timeout=timeout)

    if not raw_devices:
        findings.append(Finding(
            severity=Severity.INFO,
            title="No UPnP devices responded to SSDP discovery",
            host="local",
            port=1900,
            protocol="udp",
            category="UPnP",
            description="No UPnP root devices responded within the scan window.",
            explanation=(
                "No UPnP devices were found on the network. This is generally good. "
                "UPnP is a known attack surface that has been used in large-scale "
                "denial-of-service attacks."
            ),
            recommendation="No action required.",
            tags=["upnp", "ok"],
        ))
        return findings

    for device_resp in raw_devices:
        source_ip = device_resp.get("_source_ip", "unknown")
        location = device_resp.get("location", "")
        usn = device_resp.get("usn", "")
        server = device_resp.get("server", "")

        # Try to get device description XML
        description: Optional[Dict] = None
        if location:
            description = _fetch_device_description(location)

        friendly_name = ""
        device_type = ""
        manufacturer = ""
        services: List[str] = []
        is_igd = False

        if description:
            friendly_name = description.get("friendly_name", "")
            device_type = description.get("device_type", "")
            manufacturer = description.get("manufacturer", "")
            services = description.get("services", [])

            # Check if it's an Internet Gateway Device (router)
            is_igd = any(
                igd_svc in svc or svc in igd_svc
                for igd_svc in IGD_SERVICES
                for svc in ([device_type] + services)
            )

        display_name = (
            friendly_name
            or f"UPnP Device at {source_ip}"
        )
        info_str = (
            f"Device: {friendly_name!r}, "
            f"Type: {device_type!r}, "
            f"Manufacturer: {manufacturer!r}, "
            f"Server: {server!r}, "
            f"Services: {len(services)}"
        )

        # ---- INFO: device found ----
        findings.append(Finding(
            severity=Severity.INFO,
            title=f"UPnP device found: {display_name}",
            host=source_ip,
            port=1900,
            protocol="udp",
            category="UPnP",
            description=info_str,
            explanation=(
                f"A UPnP-enabled device was discovered on the network at {source_ip}."
            ),
            recommendation="See related UPnP findings for risk assessment.",
            evidence=f"SSDP Location: {location} | USN: {usn}",
            tags=["upnp", "info"],
        ))

        # ---- HIGH: IGD with port mapping capability ----
        if is_igd:
            findings.append(Finding(
                severity=Severity.HIGH,
                title=f"UPnP Internet Gateway Device (router) found at {source_ip}",
                host=source_ip,
                port=1900,
                protocol="udp",
                category="UPnP",
                description=(
                    f"Device {display_name!r} at {source_ip} exposes UPnP Internet Gateway Device (IGD) "
                    f"services including WAN port mapping. "
                    f"Services detected: {', '.join(services[:5])}."
                ),
                explanation=(
                    "Your router is advertising UPnP Internet Gateway Device (IGD) services. "
                    "This means any device on your network (including malware) can automatically "
                    "open inbound ports in your router's firewall — without any password or confirmation. "
                    "This capability has been exploited in attacks like Mirai and various IoT botnets. "
                    "In 2018, attackers used UPnP IGD to proxy traffic through 65,000+ routers worldwide."
                ),
                recommendation=(
                    "1. Log into your router's admin panel.\n"
                    "2. Find the UPnP settings (usually under Advanced > UPnP or NAT).\n"
                    "3. Disable UPnP entirely unless you have a specific need for it.\n"
                    "4. After disabling, test that streaming services, games, and VoIP "
                    "still work — most will not require UPnP.\n"
                    "5. If some application specifically requires UPnP, create static "
                    "port forwarding rules manually instead."
                ),
                evidence=f"IGD services: {', '.join(s for s in services if any(igd in s for igd in ['WAN', 'Gateway']))}",
                tags=["upnp", "igd", "port-mapping"],
            ))
        else:
            # ---- MEDIUM: general UPnP device ----
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title=f"UPnP-enabled device at {source_ip}: {display_name}",
                host=source_ip,
                port=1900,
                protocol="udp",
                category="UPnP",
                description=(
                    f"{display_name!r} at {source_ip} is broadcasting UPnP availability. "
                    f"Manufacturer: {manufacturer!r}."
                ),
                explanation=(
                    "UPnP (Universal Plug and Play) allows devices to automatically "
                    "announce and discover services on the network. While convenient, "
                    "UPnP has a history of security vulnerabilities and is a common "
                    "attack target. Having UPnP-enabled devices increases the attack "
                    "surface of your network."
                ),
                recommendation=(
                    "1. Check if this device actually needs UPnP to function.\n"
                    "2. If possible, disable UPnP in the device's settings.\n"
                    "3. Ensure the device has the latest firmware installed.\n"
                    "4. Keep this device on a separate IoT network segment if possible."
                ),
                evidence=f"SSDP response from {source_ip} | {info_str}",
                tags=["upnp", "medium"],
            ))

    return findings
