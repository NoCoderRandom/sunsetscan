"""
SunsetScan Passive Sniffer Module.

Runs a background packet capture using scapy to collect discovery protocol
traffic that devices broadcast on the local network. Captures only:

    - mDNS   (UDP 5353)  — device names, services, model info
    - SSDP   (UDP 1900)  — UPnP announcements
    - DHCP   (UDP 67/68) — hostnames, OS hints

The sniffer runs in a background thread and stores captured packets in
memory. It is started before active scanning begins and stopped when
scanning completes.

No traffic is injected — this is purely passive listening.

Requires: scapy (pip install scapy)
Requires root/sudo for raw socket capture.

Exports:
    PassiveSniffer: Main sniffer class with start/stop/get_packets
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from core.packet_parsers import (
    ParsedPacket,
    parse_dhcp_packet,
    parse_mdns_packet,
    parse_ssdp_packet,
)

logger = logging.getLogger(__name__)

# BPF filter for the three protocols we care about
_BPF_FILTER = "udp port 5353 or udp port 1900 or udp port 67 or udp port 68"


@dataclass
class CapturedPacket:
    """A single captured packet with metadata.

    Attributes:
        timestamp:   Capture time (Unix epoch).
        src_ip:      Source IP address.
        src_mac:     Source MAC address.
        dst_ip:      Destination IP address.
        protocol:    Detected protocol (mdns, ssdp, dhcp).
        src_port:    Source UDP port.
        dst_port:    Destination UDP port.
        raw_payload: Raw UDP payload bytes.
        parsed:      Parsed packet metadata (filled by parse step).
    """
    timestamp: float = 0.0
    src_ip: str = ""
    src_mac: str = ""
    dst_ip: str = ""
    protocol: str = ""
    src_port: int = 0
    dst_port: int = 0
    raw_payload: bytes = b""
    parsed: Optional[ParsedPacket] = None


class PassiveSniffer:
    """Background packet sniffer for network discovery protocols.

    Usage:
        sniffer = PassiveSniffer(interface="eth0")
        sniffer.start()
        # ... run active scans ...
        sniffer.stop()
        packets = sniffer.get_packets()
        parsed = sniffer.parse_all()
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: str = _BPF_FILTER,
        max_packets: int = 10000,
    ):
        """Initialize the passive sniffer.

        Args:
            interface:   Network interface to sniff on (None = auto-detect).
            bpf_filter:  BPF filter string for packet capture.
            max_packets: Maximum packets to store before dropping oldest.
        """
        self._interface = interface
        self._bpf_filter = bpf_filter
        self._max_packets = max_packets
        self._packets: List[CapturedPacket] = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._started = False
        self._packet_count = 0
        self._scapy_available = False

    @property
    def is_running(self) -> bool:
        return self._started and not self._stop_event.is_set()

    @property
    def packet_count(self) -> int:
        return self._packet_count

    def start(self) -> bool:
        """Start background packet capture.

        Returns:
            True if capture started successfully, False otherwise.
        """
        if self._started:
            logger.warning("Passive sniffer already running")
            return True

        # Verify scapy is available
        try:
            from scapy.all import sniff as scapy_sniff, conf as scapy_conf
            self._scapy_available = True
        except ImportError:
            logger.warning("scapy not installed — passive sniffing disabled")
            return False
        except PermissionError:
            logger.warning("Passive sniffer requires raw socket access — capture disabled")
            return False
        except OSError as e:
            logger.warning("Passive sniffer unavailable — capture disabled: %s", e)
            return False

        self._stop_event.clear()
        self._packets.clear()
        self._packet_count = 0

        self._thread = threading.Thread(
            target=self._capture_loop,
            daemon=True,
            name="sunsetscan-passive-sniffer",
        )
        self._thread.start()
        self._started = True

        # Brief pause to let capture initialize
        time.sleep(0.5)
        logger.info(
            f"Passive sniffer started on {self._interface or 'default interface'} "
            f"(filter: {self._bpf_filter})"
        )
        return True

    def stop(self) -> int:
        """Stop the background capture.

        Returns:
            Number of packets captured.
        """
        if not self._started:
            return 0

        self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

        self._started = False
        count = self._packet_count
        logger.info(f"Passive sniffer stopped — {count} packets captured")
        return count

    def get_packets(self) -> List[CapturedPacket]:
        """Return all captured packets (thread-safe copy)."""
        with self._lock:
            return list(self._packets)

    def parse_all(self) -> List[ParsedPacket]:
        """Parse all captured packets and return structured metadata.

        Returns:
            List of ParsedPacket objects (one per successfully parsed packet).
        """
        parsed: List[ParsedPacket] = []

        with self._lock:
            packets = list(self._packets)

        for pkt in packets:
            result = self._parse_packet(pkt)
            if result:
                pkt.parsed = result
                parsed.append(result)

        logger.info(f"Parsed {len(parsed)}/{len(packets)} captured packets")
        return parsed

    def get_parsed_by_protocol(self) -> Dict[str, List[ParsedPacket]]:
        """Parse all packets and group by protocol.

        Returns:
            Dict mapping protocol name to list of ParsedPacket.
        """
        grouped: Dict[str, List[ParsedPacket]] = {
            'mdns': [],
            'ssdp': [],
            'dhcp': [],
        }

        for pkt in self.parse_all():
            if pkt.protocol in grouped:
                grouped[pkt.protocol].append(pkt)

        return grouped

    def _capture_loop(self) -> None:
        """Main capture loop running in background thread."""
        try:
            from scapy.all import sniff as scapy_sniff
            import scapy.config
            scapy.config.conf.verb = 0

            # Build sniff kwargs
            kwargs = {
                'filter': self._bpf_filter,
                'prn': self._process_scapy_packet,
                'store': False,  # Don't store in scapy's memory
                'stop_filter': lambda pkt: self._stop_event.is_set(),
            }

            if self._interface:
                kwargs['iface'] = self._interface

            # Scapy sniff blocks until stop_filter returns True or timeout
            # Use a short timeout loop so we can check the stop event
            while not self._stop_event.is_set():
                try:
                    scapy_sniff(timeout=2, **kwargs)
                except Exception as e:
                    if not self._stop_event.is_set():
                        logger.debug(f"Scapy sniff iteration error: {e}")
                    break

        except PermissionError:
            logger.warning("Passive sniffer requires root/sudo — capture disabled")
        except Exception as e:
            logger.debug(f"Passive sniffer error: {e}")

    def _process_scapy_packet(self, scapy_pkt) -> None:
        """Callback for each captured scapy packet."""
        try:
            from scapy.layers.inet import IP, UDP
            from scapy.layers.l2 import Ether

            if not scapy_pkt.haslayer(UDP):
                return

            udp = scapy_pkt[UDP]
            sport = udp.sport
            dport = udp.dport

            # Classify protocol by port
            protocol = ""
            if sport == 5353 or dport == 5353:
                protocol = "mdns"
            elif sport == 1900 or dport == 1900:
                protocol = "ssdp"
            elif sport in (67, 68) or dport in (67, 68):
                protocol = "dhcp"
            else:
                return

            # Extract addresses
            src_ip = scapy_pkt[IP].src if scapy_pkt.haslayer(IP) else ""
            dst_ip = scapy_pkt[IP].dst if scapy_pkt.haslayer(IP) else ""
            src_mac = scapy_pkt[Ether].src if scapy_pkt.haslayer(Ether) else ""

            # Extract raw UDP payload
            raw_payload = bytes(udp.payload)

            captured = CapturedPacket(
                timestamp=float(scapy_pkt.time) if hasattr(scapy_pkt, 'time') else time.time(),
                src_ip=src_ip,
                src_mac=src_mac,
                dst_ip=dst_ip,
                protocol=protocol,
                src_port=sport,
                dst_port=dport,
                raw_payload=raw_payload,
            )

            with self._lock:
                if len(self._packets) >= self._max_packets:
                    self._packets.pop(0)
                self._packets.append(captured)
                self._packet_count += 1

        except Exception as e:
            logger.debug(f"Packet processing error: {e}")

    @staticmethod
    def _parse_packet(pkt: CapturedPacket) -> Optional[ParsedPacket]:
        """Parse a captured packet based on its protocol."""
        if not pkt.raw_payload:
            return None

        if pkt.protocol == "mdns":
            return parse_mdns_packet(pkt.raw_payload, pkt.src_ip, pkt.src_mac)
        elif pkt.protocol == "ssdp":
            return parse_ssdp_packet(pkt.raw_payload, pkt.src_ip, pkt.src_mac)
        elif pkt.protocol == "dhcp":
            return parse_dhcp_packet(pkt.raw_payload, pkt.src_ip, pkt.src_mac)

        return None
