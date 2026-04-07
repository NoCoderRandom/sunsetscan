"""
NetWatch Instant Scan Module.

Ultra-fast Fing-style network discovery. Uses only lightweight protocols:
  - ARP sweep (host + MAC discovery)
  - OUI vendor lookup (MAC → manufacturer)
  - Passive mDNS/SSDP/DHCP sniffing (short burst, ~1 second)

No port scanning, no OS fingerprinting, no Nmap, no report generation.
Results are printed to the terminal in real time as devices are found.

Requires: scapy (pip install scapy)
Requires root/sudo for ARP and passive capture.

Exports:
    run_instant_scan: Main entry point
"""

import logging
import time
from typing import Dict, List, Optional

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

from core.network_utils import get_local_subnet, is_local_subnet
from core.oui_lookup import lookup_vendor
from core.passive_sniffer import PassiveSniffer
from core.packet_parsers import ParsedPacket

logger = logging.getLogger(__name__)

# How long to passively sniff for mDNS/SSDP/DHCP (seconds)
_SNIFF_DURATION = 1.0

# ARP timeout (seconds)
_ARP_TIMEOUT = 2


def _arp_sweep(network: str, timeout: float = _ARP_TIMEOUT) -> Dict[str, str]:
    """Send ARP requests and return {ip: mac} for all responding hosts.

    Does NOT save a baseline — Instant Scan is read-only.
    """
    try:
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import srp
        import scapy.config
        scapy.config.conf.verb = 0

        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
        answered, _ = srp(arp_request, timeout=timeout, verbose=False)

        table: Dict[str, str] = {}
        for _, received in answered:
            table[received.psrc] = received.hwsrc.lower()
        return table

    except ImportError:
        logger.warning("scapy not installed — ARP sweep unavailable")
    except PermissionError:
        logger.warning("ARP sweep requires root/sudo")
    except Exception as e:
        logger.debug(f"ARP sweep error: {e}")
    return {}


def _guess_device_type(vendor: str, hostname: str, metadata: dict) -> str:
    """Best-effort device type guess from vendor + hostname + passive metadata."""
    combined = f"{vendor} {hostname} {metadata.get('device_type', '')}".lower()

    if any(k in combined for k in ("apple", "iphone", "ipad", "macbook", "airpods")):
        return "Apple Device"
    if any(k in combined for k in ("samsung", "galaxy")):
        return "Samsung Device"
    if any(k in combined for k in ("google", "chromecast", "nest")):
        return "Google Device"
    if any(k in combined for k in ("amazon", "echo", "kindle", "fire")):
        return "Amazon Device"
    if any(k in combined for k in ("sonos",)):
        return "Sonos Speaker"
    if any(k in combined for k in ("roku",)):
        return "Roku Streaming"
    if any(k in combined for k in ("ring",)):
        return "Ring Camera"
    if any(k in combined for k in ("philips", "hue")):
        return "Philips Hue"
    if any(k in combined for k in ("synology",)):
        return "Synology NAS"
    if any(k in combined for k in ("qnap",)):
        return "QNAP NAS"
    if any(k in combined for k in ("raspberry", "raspberrypi")):
        return "Raspberry Pi"
    if any(k in combined for k in ("printer", "canon", "epson", "brother", "hp inc")):
        return "Printer"
    if any(k in combined for k in ("camera", "hikvision", "dahua", "reolink", "wyze")):
        return "IP Camera"
    if any(k in combined for k in ("router", "gateway", "ubiquiti", "mikrotik", "netgear",
                                    "tp-link", "asus", "linksys", "cisco", "arris")):
        return "Router/AP"
    if any(k in combined for k in ("switch", "unifi")):
        return "Network Switch"
    if any(k in combined for k in ("television", "tv", "lg electronics", "vizio", "tcl")):
        return "Smart TV"
    if any(k in combined for k in ("xbox",)):
        return "Xbox"
    if any(k in combined for k in ("playstation", "sony")):
        return "PlayStation"
    if any(k in combined for k in ("nintendo",)):
        return "Nintendo"
    if any(k in combined for k in ("intel", "dell", "lenovo", "hewlett")):
        return "PC/Laptop"
    if any(k in combined for k in ("android", "oneplus", "xiaomi", "huawei", "oppo")):
        return "Android Device"
    if any(k in combined for k in ("espressif", "tuya", "shelly")):
        return "IoT Device"

    if metadata.get("device_type"):
        return metadata["device_type"]
    return ""


def _build_table(devices: list) -> Table:
    """Build a Rich Table for the current device list."""
    table = Table(
        title="Instant Scan — Live Results",
        show_lines=False,
        expand=True,
        title_style="bold cyan",
    )
    table.add_column("IP Address", style="bold white", min_width=15)
    table.add_column("MAC Address", style="dim", min_width=17)
    table.add_column("Vendor", style="yellow", min_width=14)
    table.add_column("Hostname", style="green", min_width=14)
    table.add_column("mDNS/SSDP", style="cyan", min_width=14)
    table.add_column("Type", style="bold magenta", min_width=12)

    for d in devices:
        table.add_row(
            d["ip"],
            d["mac"],
            d["vendor"],
            d["hostname"],
            d["metadata_str"],
            d["device_type"],
        )
    return table


def run_instant_scan(target: Optional[str] = None) -> int:
    """Run an ultra-fast Instant Scan and print results live.

    Instant Scan is L2-only (ARP + passive sniff). Because ARP broadcasts
    cannot cross routers, the scan can only ever cover the local subnet.
    The ``target`` parameter is therefore advisory:

      - ``None`` (the normal case)  → auto-detect the local subnet.
      - A target on the local subnet → used as-is.
      - A target on a different subnet → warn the user and fall back to
        the auto-detected local subnet, since scanning it via ARP is
        physically impossible.

    Args:
        target: Optional CIDR. Ignored if it does not match the local L2.

    Returns:
        Exit code (0 = success).
    """
    console = Console()

    # ---- Determine target (always end up on the local subnet) ----
    auto_detected = False

    if target and is_local_subnet(target) is False:
        # Explicitly off-subnet — warn and fall back. (None = undetermined,
        # so we leave the user-supplied target alone to avoid spurious noise.)
        console.print(
            f"[yellow]Warning:[/yellow] {target} is not on this host's local "
            f"subnet. ARP cannot cross routers, so Instant Scan will use the "
            f"auto-detected local network instead."
        )
        target = None  # Force auto-detect path below

    if not target:
        target = get_local_subnet()
        auto_detected = True
        if not target:
            console.print(
                "[red]Could not detect local subnet. "
                "Check that this host has an active network interface.[/red]"
            )
            return 1

    source = "auto-detected" if auto_detected else "user-supplied"
    console.print(f"\n[bold cyan]Instant Scan[/bold cyan]  [dim]target: {target} ({source})[/dim]")
    console.print("[dim]ARP sweep + passive sniff — no port scanning[/dim]\n")

    # ---- Start passive sniffer (mDNS / SSDP / DHCP) ----
    sniffer = PassiveSniffer()
    sniffer_ok = sniffer.start()

    # ---- ARP sweep ----
    console.print("[cyan]Sending ARP requests...[/cyan]")
    start_time = time.time()
    arp_table = _arp_sweep(target)
    arp_elapsed = time.time() - start_time

    if not arp_table:
        console.print("[yellow]No hosts responded to ARP sweep.[/yellow]")
        console.print("[dim]Make sure you are running as root/sudo.[/dim]")
        sniffer.stop()
        return 1

    console.print(f"[green]Found {len(arp_table)} hosts[/green] [dim]({arp_elapsed:.1f}s)[/dim]\n")

    # ---- Let passive sniffer collect a bit more ----
    if sniffer_ok:
        remaining = _SNIFF_DURATION - arp_elapsed
        if remaining > 0:
            time.sleep(remaining)
        sniffer.stop()
        parsed_packets = sniffer.parse_all()
    else:
        parsed_packets = []

    # ---- Index passive metadata by IP ----
    passive_by_ip: Dict[str, dict] = {}
    for pkt in parsed_packets:
        ip = pkt.src_ip
        if not ip:
            continue
        if ip not in passive_by_ip:
            passive_by_ip[ip] = {
                "hostname": "",
                "device_type": "",
                "vendor": "",
                "model": "",
                "services": [],
                "protocol_hits": [],
            }
        entry = passive_by_ip[ip]
        if pkt.hostname and not entry["hostname"]:
            entry["hostname"] = pkt.hostname
        if pkt.device_type and not entry["device_type"]:
            entry["device_type"] = pkt.device_type
        if pkt.vendor and not entry["vendor"]:
            entry["vendor"] = pkt.vendor
        if pkt.model and not entry["model"]:
            entry["model"] = pkt.model
        if pkt.services:
            entry["services"].extend(pkt.services)
        if pkt.protocol and pkt.protocol not in entry["protocol_hits"]:
            entry["protocol_hits"].append(pkt.protocol)

    # ---- Build device list ----
    devices = []
    for ip in sorted(arp_table.keys(), key=lambda x: tuple(int(p) for p in x.split("."))):
        mac = arp_table[ip]
        vendor = lookup_vendor(mac)
        passive = passive_by_ip.get(ip, {})

        hostname = passive.get("hostname", "")
        metadata_parts = []
        if passive.get("model"):
            metadata_parts.append(passive["model"])
        if passive.get("services"):
            # Show first two unique services
            svcs = list(dict.fromkeys(passive["services"]))[:2]
            metadata_parts.extend(svcs)
        if passive.get("protocol_hits"):
            metadata_parts.append("/".join(passive["protocol_hits"]))
        metadata_str = ", ".join(metadata_parts) if metadata_parts else ""

        device_type = _guess_device_type(vendor, hostname, passive)

        devices.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor or "Unknown",
            "hostname": hostname,
            "metadata_str": metadata_str,
            "device_type": device_type,
        })

    # ---- Print final table ----
    console.print(_build_table(devices))

    elapsed = time.time() - start_time
    console.print(
        f"\n[bold green]Done.[/bold green]  "
        f"{len(devices)} devices found in {elapsed:.1f}s  "
        f"[dim](no report saved)[/dim]\n"
    )
    return 0
