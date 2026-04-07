"""
NetWatch Active mDNS Query Module.

Actively queries the local network for mDNS services using the zeroconf
library, producing ``ParsedPacket`` objects that feed directly into the
existing identity fusion pipeline. This complements the passive sniffer:

    - Passive capture (``passive_sniffer``) listens for whatever devices
      happen to announce during the scan window — a lottery, since mDNS
      re-announces happen every ~20 min to several hours.
    - Active query (this module) sends multicast PTR queries for known
      service types and collects responses in a bounded 2-5 s window.
      Every Bonjour-speaking device on the segment replies deterministically.

The two sources are fused under the same ``'mdns'`` protocol tag in
``identity_fusion``, so active results get the same weight as passive ones
but arrive reliably. This is the key to identifying Apple devices with
randomized MACs (Apple TV, HomePod, iPhone) whose OUI lookup lies.

Service types queried (keyed on what's most diagnostic for device identity):

    Apple AirPlay / AppleTV / HomePod:
        _airplay._tcp       - AirPlay 2 (TXT ``model`` gives exact SKU)
        _raop._tcp          - AirPlay audio (Remote Audio Output Protocol)
        _companion-link._tcp - Apple Companion protocol (HomePod, AppleTV)
        _mediaremotetv._tcp - Apple TV Remote app
        _touch-able._tcp    - older iTunes/AppleTV remote
        _sleep-proxy._udp   - Bonjour Sleep Proxy (AppleTV, Time Capsule)
        _device-info._tcp   - Generic Apple device metadata
        _apple-mobdev2._tcp - Apple mobile devices (iPhone, iPad)
        _homekit._tcp / _hap._tcp - HomeKit accessories

    Google / Cast:
        _googlecast._tcp    - Chromecast, Google Home, Nest

    Media / Streaming:
        _spotify-connect._tcp - Spotify Connect speakers

    Printers:
        _ipp._tcp / _ipps._tcp / _printer._tcp / _pdl-datastream._tcp

    Storage / File Shares:
        _smb._tcp / _afpovertcp._tcp / _nfs._tcp

    Media Servers:
        _plex._tcp / _jellyfin._tcp

Exports:
    query_active_mdns(timeout): Run active query and return parsed packets
"""

from __future__ import annotations

import ipaddress
import logging
import shlex
import shutil
import subprocess
from typing import Dict, List, Optional

from core.packet_parsers import (
    ParsedPacket,
    _mdns_service_to_device_type,
    _process_mdns_txt,
)

logger = logging.getLogger(__name__)


# Service types worth actively querying. Ordered by identity value: Apple
# services first because they rarely leak via passive capture (randomized
# MAC devices that don't announce often).
_ACTIVE_SERVICE_TYPES: List[str] = [
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_companion-link._tcp.local.",
    "_mediaremotetv._tcp.local.",
    "_touch-able._tcp.local.",
    "_sleep-proxy._udp.local.",
    "_device-info._tcp.local.",
    "_apple-mobdev2._tcp.local.",
    "_homekit._tcp.local.",
    "_hap._tcp.local.",
    "_googlecast._tcp.local.",
    "_spotify-connect._tcp.local.",
    "_ipp._tcp.local.",
    "_ipps._tcp.local.",
    "_printer._tcp.local.",
    "_pdl-datastream._tcp.local.",
    "_smb._tcp.local.",
    "_afpovertcp._tcp.local.",
    "_plex._tcp.local.",
    "_jellyfin._tcp.local.",
    "_esphomelib._tcp.local.",
    "_miio._udp.local.",
    "_hue._tcp.local.",
    "_matter._tcp.local.",
]

DEFAULT_QUERY_TIMEOUT = 4.0


# ---------------------------------------------------------------------------
# AppleTV / HomePod model identifier mapping
# ---------------------------------------------------------------------------
# Apple embeds a "model" TXT record with their internal device identifier
# (e.g. J305AP, AppleTV14,1). Translating these to marketing names gives
# us model-level identity without needing any other signal.

_APPLE_MODEL_MAP = {
    # Apple TV
    "AppleTV5,3":  ("Apple TV HD",            "Media Device"),
    "AppleTV6,2":  ("Apple TV 4K (1st gen)",  "Media Device"),
    "AppleTV11,1": ("Apple TV 4K (2nd gen)",  "Media Device"),
    "AppleTV14,1": ("Apple TV 4K (3rd gen)",  "Media Device"),
    # HomePod
    "AudioAccessory1,1": ("HomePod (1st gen)", "Smart Speaker"),
    "AudioAccessory1,2": ("HomePod (1st gen)", "Smart Speaker"),
    "AudioAccessory5,1": ("HomePod mini",      "Smart Speaker"),
    "AudioAccessory6,1": ("HomePod (2nd gen)", "Smart Speaker"),
    # iPhone / iPad generic
    "iPhone":      ("iPhone",  "Mobile Device"),
    "iPad":        ("iPad",    "Tablet"),
    "MacBookPro":  ("MacBook Pro", "Laptop"),
    "MacBookAir":  ("MacBook Air", "Laptop"),
    "Macmini":     ("Mac mini",    "Desktop"),
    "iMac":        ("iMac",        "Desktop"),
}


def _apple_model_to_pretty(raw_model: str) -> Optional[tuple]:
    """Map a raw Apple ``model=`` TXT value to (pretty_name, device_type).

    Handles exact matches and prefix matches (e.g. ``iPhone15,2`` → iPhone).
    """
    if not raw_model:
        return None
    # Exact match first
    if raw_model in _APPLE_MODEL_MAP:
        return _APPLE_MODEL_MAP[raw_model]
    # Prefix match for family names
    for family in ("iPhone", "iPad", "MacBookPro", "MacBookAir", "Macmini", "iMac"):
        if raw_model.startswith(family):
            return _APPLE_MODEL_MAP[family]
    # AppleTV / AudioAccessory families with unknown revision → generic label
    if raw_model.startswith("AppleTV"):
        return ("Apple TV", "Media Device")
    if raw_model.startswith("AudioAccessory"):
        return ("HomePod", "Smart Speaker")
    return None


def _service_is_apple(service_type: str) -> bool:
    """Return True if the service type is Apple-specific."""
    apple_prefixes = (
        "_airplay", "_raop", "_companion-link", "_mediaremotetv",
        "_touch-able", "_sleep-proxy", "_device-info", "_apple-mobdev2",
        "_homekit", "_hap",
    )
    return any(p in service_type for p in apple_prefixes)


def _decode_txt_properties(properties: dict) -> List[str]:
    """Decode zeroconf's bytes-keyed properties dict into "key=value" strings."""
    out: List[str] = []
    for k, v in (properties or {}).items():
        try:
            key = k.decode("utf-8", errors="replace") if isinstance(k, bytes) else str(k)
            if v is None:
                continue
            if isinstance(v, bytes):
                val = v.decode("utf-8", errors="replace")
            else:
                val = str(v)
            if key:
                out.append(f"{key}={val}")
        except Exception:
            continue
    return out


def _finalize_apple_identity(pkt: ParsedPacket, service_clean: str) -> None:
    """Apply Apple model translation + vendor stamping to a ParsedPacket.

    Checks for Apple ``model=`` / ``rpMd=`` TXT values, translates them to
    marketing names, and stamps ``vendor="Apple"`` whenever the service
    type is Apple-exclusive. Used by both the avahi-browse path and the
    zeroconf fallback so the identification logic stays in one place.
    """
    raw_model = (
        pkt.raw_fields.get("txt_rpmd", "")
        or pkt.raw_fields.get("txt_model", "")
        or pkt.model
    )
    mapped = _apple_model_to_pretty(raw_model)
    if mapped:
        pretty, dtype = mapped
        pkt.model = pretty
        if not pkt.device_type:
            pkt.device_type = dtype
        if not pkt.vendor:
            pkt.vendor = "Apple"
    elif _service_is_apple(service_clean) and not pkt.vendor:
        # Apple-only service type → vendor is Apple even without a model
        # TXT record (e.g. devices on older tvOS that only publish hints
        # under the Remote Pairing protocol).
        pkt.vendor = "Apple"
        if not pkt.device_type:
            pkt.device_type = _mdns_service_to_device_type([service_clean])

    if not pkt.device_type and pkt.services:
        pkt.device_type = _mdns_service_to_device_type(pkt.services)


def _query_via_avahi(timeout: float) -> List[ParsedPacket]:
    """Query mDNS via the system ``avahi-browse`` utility.

    When ``avahi-daemon`` is running (standard on Raspberry Pi OS, Debian,
    Ubuntu, most Linux desktops) it owns UDP 5353 and maintains a complete
    mDNS cache that is already populated by the time NetWatch starts. This
    path is far more reliable than the python ``zeroconf`` library on such
    hosts because:

      - avahi's cache already contains every recently-announced record, so
        there is no window to miss.
      - There is no SO_REUSEPORT race with the avahi daemon.
      - avahi handles Bonjour Sleep Proxy forwarding transparently, so
        sleeping AppleTVs etc. still show up.

    Uses ``avahi-browse -artp --terminate --no-db-lookup`` to dump and
    resolve every service type in one parsable pass, then parses the
    semicolon-delimited output into ``ParsedPacket`` objects.

    Returns an empty list if avahi-browse is not installed or errors out.
    """
    if not shutil.which("avahi-browse"):
        return []

    try:
        proc = subprocess.run(
            ["avahi-browse", "-a", "-r", "-t", "-p", "--no-db-lookup"],
            capture_output=True,
            text=True,
            timeout=max(timeout, 5.0),
        )
    except subprocess.TimeoutExpired:
        logger.debug("avahi-browse timed out")
        return []
    except Exception as e:
        logger.debug(f"avahi-browse failed: {e}")
        return []

    if proc.returncode != 0 and not proc.stdout:
        logger.debug(f"avahi-browse exited {proc.returncode}: {proc.stderr.strip()}")
        return []

    packets_by_ip: Dict[str, ParsedPacket] = {}

    for line in proc.stdout.splitlines():
        # Resolved record lines start with '='. New/removed announcements
        # use '+'/'-' and don't include TXT/port data, so skip them.
        if not line.startswith("="):
            continue

        # Parsable format: =;iface;proto;name;type;domain;hostname;addr;port;txt
        parts = line.split(";")
        if len(parts) < 9:
            continue

        proto = parts[2]
        if proto != "IPv4":
            # IPv6 records just duplicate v4 ones on dual-stack devices.
            continue

        friendly_name = parts[3]
        service_type = parts[4]  # e.g. "_companion-link._tcp"
        hostname_raw = parts[6]
        ip = parts[7]
        txt_field = parts[9] if len(parts) > 9 else ""

        if not ip:
            continue

        pkt = packets_by_ip.get(ip)
        if pkt is None:
            pkt = ParsedPacket(protocol="mdns", src_ip=ip)
            packets_by_ip[ip] = pkt

        service_clean = service_type.rstrip(".")
        if service_clean and service_clean not in pkt.services:
            pkt.services.append(service_clean)

        # Prefer the resolved hostname (e.g. "Sovrum.local") over the raw
        # service instance name. Strip trailing dots and ".local" suffix.
        hostname = (hostname_raw or "").rstrip(".")
        if hostname.endswith(".local"):
            hostname = hostname[:-len(".local")]
        if hostname and (not pkt.hostname or len(hostname) > len(pkt.hostname)):
            pkt.hostname = hostname
        elif friendly_name and not pkt.hostname:
            pkt.hostname = friendly_name

        # TXT field format: "key1=val1" "key2=val2" "key3=val3" ...
        if txt_field:
            try:
                for kv in shlex.split(txt_field):
                    _process_mdns_txt(kv, pkt)
            except ValueError:
                # Malformed quoting — fall back to space split.
                for kv in txt_field.split():
                    _process_mdns_txt(kv.strip('"'), pkt)

        _finalize_apple_identity(pkt, service_clean)

    return list(packets_by_ip.values())


def query_active_mdns(timeout: float = DEFAULT_QUERY_TIMEOUT) -> List[ParsedPacket]:
    """Actively query mDNS for device metadata and return ParsedPacket list.

    Two-path strategy:

      1. ``avahi-browse`` (preferred) — uses the system mDNS cache. On any
         Linux host running ``avahi-daemon`` this is the only path that
         sees records from devices behind Bonjour Sleep Proxy (sleeping
         AppleTVs, Time Capsules, etc.) and avoids the SO_REUSEPORT race
         between our zeroconf instance and avahi.
      2. ``zeroconf`` library (fallback) — used on macOS and any Linux
         host where avahi isn't installed. Sends its own multicast PTR
         queries for every service type in ``_ACTIVE_SERVICE_TYPES``.

    Args:
        timeout: Discovery window in seconds. 4 s is enough to let all
                 devices on a typical home/SMB LAN reply.

    Returns:
        List of ParsedPacket (may be empty if neither path is usable).
    """
    # Preferred: piggyback on avahi-daemon's cache.
    avahi_results = _query_via_avahi(timeout)
    if avahi_results:
        logger.info(f"Active mDNS (avahi): {len(avahi_results)} device(s)")
        return avahi_results

    try:
        from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
    except ImportError:
        logger.debug("zeroconf not installed — active mDNS query skipped")
        return []

    packets_by_ip: dict = {}  # ip → ParsedPacket (merged across services)

    class _Listener(ServiceListener):
        def add_service(self, zc, type_, name):
            try:
                info = zc.get_service_info(type_, name, timeout=1500)
            except Exception as e:
                logger.debug(f"zeroconf get_service_info failed for {name}: {e}")
                return
            if not info or not info.addresses:
                return

            service_clean = type_.rstrip(".")

            for addr_bytes in info.addresses:
                try:
                    ip = str(ipaddress.ip_address(addr_bytes))
                except Exception:
                    continue

                pkt = packets_by_ip.get(ip)
                if pkt is None:
                    pkt = ParsedPacket(protocol="mdns", src_ip=ip)
                    packets_by_ip[ip] = pkt

                # Accumulate service type
                if service_clean not in pkt.services:
                    pkt.services.append(service_clean)

                # Hostname (server name, e.g. "AppleTV-Sovrum.local.")
                if info.server:
                    server = info.server.rstrip(".")
                    if server and (not pkt.hostname or len(server) > len(pkt.hostname)):
                        pkt.hostname = server

                # Friendly service name ("Sovrum._airplay._tcp.local.")
                friendly = name.split(".")[0] if name else ""
                if friendly and not pkt.hostname:
                    pkt.hostname = friendly

                # Process TXT properties through the existing mDNS TXT handler
                # so vendor/model/os_hint extraction stays in one place.
                for txt_kv in _decode_txt_properties(info.properties):
                    _process_mdns_txt(txt_kv, pkt)

                _finalize_apple_identity(pkt, service_clean)
                pkt.raw_fields[f"service_{service_clean}"] = name

        def update_service(self, zc, type_, name):
            self.add_service(zc, type_, name)

        def remove_service(self, zc, type_, name):
            pass

    zc = None
    try:
        zc = Zeroconf()
        listener = _Listener()
        ServiceBrowser(zc, _ACTIVE_SERVICE_TYPES, listener)
        import time
        time.sleep(max(timeout, 1.0))
    except OSError as e:
        logger.debug(f"zeroconf could not bind (another mDNS listener?): {e}")
    except Exception as e:
        logger.debug(f"active mDNS query error: {e}")
    finally:
        if zc is not None:
            try:
                zc.close()
            except Exception:
                pass

    results = list(packets_by_ip.values())
    logger.info(f"Active mDNS query: {len(results)} device(s) responded")
    return results
