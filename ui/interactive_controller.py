"""
NetWatch Interactive Controller Module.

This module provides the main interactive mode for NetWatch,
allowing users to perform network discovery and then select
specific actions on discovered hosts.

Exports:
    InteractiveController: Main controller for interactive mode
    DiscoveredHost: Data class for storing discovered host info

Example:
    from ui.interactive_controller import InteractiveController
    controller = InteractiveController()
    controller.run()
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

from config.settings import Settings, SCAN_PROFILES
from core.input_parser import parse_target_input, format_target_summary, get_local_subnet_suggestion
from core.scanner import NetworkScanner, ScanResult, HostInfo
from core.nse_scanner import NSEScanner
from core.auth_tester import AuthTester
from core.banner_grabber import BannerGrabber
from core.scan_history import ScanHistory
from eol.checker import EOLChecker
from eol.cache import CacheManager
from ui.display import Display
from ui.export import ReportExporter

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredHost:
    """Information about a discovered host.
    
    Attributes:
        ip: IP address
        hostname: Resolved hostname
        status: up/down
        open_ports: List of open port numbers
        services: Detected services by port
        device_type: Detected device type/manufacturer
        os_guess: Operating system guess
        last_seen: When host was last discovered
        detailed_scan: Results from detailed scan
    """
    ip: str
    hostname: str = ""
    status: str = "unknown"
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    device_type: str = ""
    os_guess: str = ""
    last_seen: datetime = field(default_factory=datetime.now)
    detailed_scan: Optional[ScanResult] = None
    eol_results: Dict[int, Any] = field(default_factory=dict)


class InteractiveController:
    """Interactive mode controller for NetWatch.
    
    Manages the interactive workflow:
    1. Get target range from user
    2. Perform discovery scan
    3. Show discovered hosts
    4. Let user select actions on specific hosts
    
    Attributes:
        settings: Application settings
        console: Rich console for output
        display: Display handler
        discovered_hosts: Dictionary of discovered hosts by IP
        current_target: Current target range being scanned
        scanner: Network scanner
        nse_scanner: NSE scanner (optional)
        auth_tester: Auth tester (optional)
        banner_grabber: Banner grabber
        eol_checker: EOL checker
        
    Example:
        controller = InteractiveController()
        controller.run()
    """
    
    def __init__(self, settings: Optional[Settings] = None):
        """Initialize interactive controller.
        
        Args:
            settings: Application settings
        """
        self.settings = settings or Settings()
        self.console = Console()
        self.display = Display(settings=self.settings, console=self.console)
        
        # Storage
        self.discovered_hosts: Dict[str, DiscoveredHost] = {}
        self.current_target: str = ""
        self.scan_history: List[Dict] = []
        self._last_scan_result: Optional[ScanResult] = None
        
        # Components
        self.scanner = NetworkScanner(settings=self.settings)
        self.nse_scanner: Optional[NSEScanner] = None
        self.auth_tester: Optional[AuthTester] = None
        self.banner_grabber = BannerGrabber(settings=self.settings)
        self.eol_checker = EOLChecker(settings=self.settings)
        
        logger.debug("InteractiveController initialized")
    
    def run(self) -> int:
        """Run the interactive mode main loop.
        
        Returns:
            Exit code (0 for success)
        """
        self.show_welcome()
        
        # Get initial target
        if not self.get_target_from_user():
            return 1
        
        # Perform initial discovery
        if not self.discovery_scan():
            return 1
        
        # Main menu loop
        while True:
            choice = self.show_main_menu()

            if choice == "0":
                self.console.print("\nGoodbye!")
                return 0
            elif choice == "1":
                self.host_operations_menu()
            elif choice == "2":
                self.bulk_operations_menu()
            elif choice == "3":
                self.run_full_assessment()
            elif choice == "4":
                self.network_menu()
            elif choice == "5":
                self.results_menu()
            elif choice == "6":
                self.modules_menu()
            elif choice == "7":
                self.settings_menu()
            elif choice == "8":
                self._run_device_inventory()
    
    def show_welcome(self) -> None:
        """Display welcome message."""
        self.console.print(f"\n{'='*70}")
        self.console.print(f"  NetWatch Interactive Mode v{self.settings.version}")
        self.console.print(f"{'='*70}\n")
        self.console.print("Discover your network and analyze devices interactively.\n")
    
    def get_target_from_user(self) -> bool:
        """Get target range from user.
        
        Returns:
            True if valid target entered
        """
        suggestion = get_local_subnet_suggestion()
        
        self.console.print("Enter target IP range. Supported formats:")
        self.console.print("  - CIDR:     192.168.1.0/24")
        self.console.print("  - Wildcard: 192.168.1.*")
        self.console.print("  - Range:    192.168.1.1-100")
        self.console.print("  - List:     192.168.1.1,5,10")
        self.console.print("  - Hostname: router.local")
        self.console.print()
        
        while True:
            target = Prompt.ask("Target range", default=suggestion)
            
            if not target:
                continue
            
            targets = parse_target_input(target)
            
            if not targets:
                self.console.print("[red]Invalid target format. Please try again.[/red]")
                continue
            
            summary = format_target_summary(targets)
            self.console.print(f"[green]Parsed as: {summary}[/green]")
            
            if Confirm.ask("Proceed with this target?", default=True):
                self.current_target = target
                return True
    
    def discovery_scan(self) -> bool:
        """Perform initial discovery scan (PING).
        
        Returns:
            True if scan completed
        """
        self.console.print(f"\n[bold blue]Performing discovery scan on {self.current_target}...[/bold blue]")
        
        try:
            targets = parse_target_input(self.current_target)
            
            for target in targets:
                result = self.scanner.ping_sweep(target)
                
                for ip in result:
                    self.discovered_hosts[ip] = DiscoveredHost(
                        ip=ip,
                        status="up",
                        last_seen=datetime.now()
                    )
            
            if self.discovered_hosts:
                self.console.print(f"[green]Found {len(self.discovered_hosts)} active hosts[/green]\n")
                self.show_discovered_hosts()
            else:
                self.console.print("[yellow]No active hosts found.[/yellow]")
                if Confirm.ask("Try a different target range?"):
                    return self.get_target_from_user() and self.discovery_scan()
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Discovery scan failed: {e}")
            self.console.print(f"[red]Scan failed: {e}[/red]")
            return False
    
    def show_discovered_hosts(self) -> None:
        """Display table of discovered hosts."""
        if not self.discovered_hosts:
            self.console.print("[yellow]No hosts discovered yet.[/yellow]")
            return
        
        table = Table(title="Discovered Hosts")
        table.add_column("#", justify="right", style="cyan")
        table.add_column("IP Address", style="bold")
        table.add_column("Hostname")
        table.add_column("Status", style="green")
        table.add_column("Ports", justify="right")
        table.add_column("Device Type")
        
        for idx, (ip, host) in enumerate(sorted(self.discovered_hosts.items()), 1):
            ports_str = str(len(host.open_ports)) if host.open_ports else "-"
            device = host.device_type or "-"
            
            table.add_row(
                str(idx),
                ip,
                host.hostname or "-",
                host.status,
                ports_str,
                device
            )
        
        self.console.print(table)
        self.console.print()
    
    def select_hosts(self, allow_multiple: bool = True) -> List[str]:
        """Let user select host(s) from discovered list.
        
        Args:
            allow_multiple: Allow selecting multiple hosts
            
        Returns:
            List of selected IP addresses
        """
        if not self.discovered_hosts:
            self.console.print("[yellow]No hosts available. Run discovery scan first.[/yellow]")
            return []
        
        self.show_discovered_hosts()
        
        if allow_multiple:
            self.console.print("Select hosts by number (comma-separated) or 'all':")
        else:
            self.console.print("Select host by number:")
        
        ips = sorted(self.discovered_hosts.keys())
        
        selection = Prompt.ask("Selection")
        
        if not selection:
            return []
        
        if selection.lower() == "all":
            return ips
        
        selected = []
        for item in selection.split(","):
            item = item.strip()
            try:
                idx = int(item) - 1
                if 0 <= idx < len(ips):
                    selected.append(ips[idx])
                else:
                    self.console.print(f"[red]Invalid selection: {item}[/red]")
            except ValueError:
                # Might be an IP address directly
                if item in self.discovered_hosts:
                    selected.append(item)
                else:
                    self.console.print(f"[red]Invalid selection: {item}[/red]")
        
        return selected
    
    def show_main_menu(self) -> str:
        """Display main menu and get user choice.

        Returns:
            Menu choice string
        """
        self.console.print(f"\n[bold cyan]Main Menu[/bold cyan]")
        self.console.print(f"Current target: {self.current_target}")
        self.console.print(f"Discovered hosts: {len(self.discovered_hosts)}\n")

        menu = """
[1] Host Operations      - Scan/analyze specific hosts
[2] Bulk Operations      - Actions on all discovered hosts
[3] Full Assessment      - Complete security audit + HTML report
[4] Network Menu         - Rescan, change target, discover
[5] Results & History    - View, export, compare results
[6] Modules & Data       - Download data modules, update cache
[7] Settings             - Configure scan options
[8] Device Inventory     - Identify all devices on the network
[0] Exit                 - Quit NetWatch
        """

        self.console.print(menu)

        return Prompt.ask(
            "Select option",
            choices=["0", "1", "2", "3", "4", "5", "6", "7", "8"],
            default="1"
        )
    
    def host_operations_menu(self) -> None:
        """Display and handle host operations menu."""
        self.console.print("\n[bold]Host Operations[/bold]")
        
        ips = self.select_hosts(allow_multiple=False)
        if not ips:
            return
        
        ip = ips[0]
        host = self.discovered_hosts[ip]
        
        self.console.print(f"\nSelected: {ip}")
        if host.hostname:
            self.console.print(f"Hostname: {host.hostname}")
        
        menu = """
[1] Quick port scan      - Scan common ports
[2] Deep scan            - Full scan with OS detection
[3] Grab banners         - Get service banners
[4] Check credentials    - Test default passwords
[5] Check EOL            - Check software EOL status
[6] View details         - Show all collected info
[0] Back to main menu
        """
        
        self.console.print(menu)
        
        choice = Prompt.ask(
            "Select action",
            choices=["0", "1", "2", "3", "4", "5", "6"],
            default="1"
        )
        
        if choice == "1":
            self.quick_port_scan([ip])
        elif choice == "2":
            self.deep_scan([ip])
        elif choice == "3":
            self.grab_banners([ip])
        elif choice == "4":
            self.check_credentials([ip])
        elif choice == "5":
            self.check_eol([ip])
        elif choice == "6":
            self.view_host_details(ip)
    
    def bulk_operations_menu(self) -> None:
        """Display and handle bulk operations menu."""
        self.console.print("\n[bold]Bulk Operations[/bold]")

        menu = """
[1] Quick scan all       - Quick scan on all discovered hosts
[2] Deep scan all        - Full scan with OS detect (slow)
[3] IoT scan all         - Scan IoT/smart device ports
[4] SMB scan all         - Windows shares + EternalBlue check
[5] Grab all banners     - Banner grab from all hosts
[6] Check all EOL        - EOL check on all services
[7] Check all credentials- Test for default passwords
[8] Generate report      - Create network summary report
[0] Back to main menu
        """

        self.console.print(menu)

        choice = Prompt.ask(
            "Select action",
            choices=["0", "1", "2", "3", "4", "5", "6", "7", "8"],
            default="1"
        )

        all_ips = list(self.discovered_hosts.keys())

        if choice == "1":
            self.quick_port_scan(all_ips)
        elif choice == "2":
            self.deep_scan(all_ips)
        elif choice == "3":
            self._profile_scan(all_ips, "IOT")
        elif choice == "4":
            self._profile_scan(all_ips, "SMB")
        elif choice == "5":
            self.grab_banners(all_ips)
        elif choice == "6":
            self.check_eol(all_ips)
        elif choice == "7":
            self.check_credentials(all_ips)
        elif choice == "8":
            self.generate_network_report()
    
    def network_menu(self) -> None:
        """Display and handle network menu."""
        self.console.print("\n[bold]Network Menu[/bold]")
        
        menu = """
[1] Rescan current       - Rediscover current target
[2] Quick rediscover     - Fast ping sweep
[3] Change target        - Enter new IP range
[4] Advanced discovery   - Use NSE for discovery
[0] Back to main menu
        """
        
        self.console.print(menu)
        
        choice = Prompt.ask(
            "Select action",
            choices=["0", "1", "2", "3", "4"],
            default="1"
        )
        
        if choice == "1":
            self.discovery_scan()
        elif choice == "2":
            self.quick_rediscover()
        elif choice == "3":
            if self.get_target_from_user():
                self.discovery_scan()
        elif choice == "4":
            self.advanced_discovery()
    
    def results_menu(self) -> None:
        """Display and handle results menu."""
        self.console.print("\n[bold]Results & History[/bold]")

        menu = """
[1] View discovered      - Show host list
[2] View scan history    - Show previous scans
[3] Compare scans (diff) - Diff last two scans
[4] Export to JSON       - Save as JSON file
[5] Export to HTML       - Save as HTML report
[0] Back to main menu
        """

        self.console.print(menu)

        choice = Prompt.ask(
            "Select action",
            choices=["0", "1", "2", "3", "4", "5"],
            default="1"
        )

        if choice == "1":
            self.show_discovered_hosts()
        elif choice == "2":
            self.view_scan_history()
        elif choice == "3":
            self.compare_results()
        elif choice == "4":
            self.export_results("json")
        elif choice == "5":
            self.export_results("html")
    
    def _run_device_inventory(self) -> None:
        """Run device identification on all discovered hosts."""
        if not self._last_scan_result or not self._last_scan_result.hosts:
            self.console.print(
                "[yellow]No scan results available. Run a scan first "
                "(option 1 or 3).[/yellow]"
            )
            return

        from core.device_identifier import DeviceIdentifier
        from collections import Counter

        identifier = DeviceIdentifier()
        device_identities = {}

        self.console.print("\n[bold blue]Identifying devices...[/bold blue]")
        for ip, host_info in self._last_scan_result.hosts.items():
            if host_info.state != "up":
                continue
            try:
                identity = identifier.identify_preliminary(ip, host_info)
                if identity.confidence > 0:
                    device_identities[ip] = identity
            except Exception as e:
                logger.debug(f"Device identification failed for {ip}: {e}")

        self.display.show_device_inventory(device_identities)

        # Print summary line
        if device_identities:
            type_counts = Counter(
                (i.device_type or "Unknown") for i in device_identities.values()
            )
            parts = [f"{c} {t}" for t, c in type_counts.most_common()]
            self.console.print(
                f"\n[bold]{len(device_identities)}/{len(self._last_scan_result.hosts)} "
                f"hosts identified ({', '.join(parts)})[/bold]"
            )

    def settings_menu(self) -> None:
        """Display and handle settings menu."""
        self.console.print("\n[bold]Settings[/bold]")
        
        menu = f"""
Current Settings:
  NSE Scripts: {'Enabled' if self.nse_scanner else 'Disabled'}
  Auth Testing: {'Enabled' if self.auth_tester and self.auth_tester.enabled else 'Disabled'}
  Timeout: {self.settings.banner_timeout}s

[1] Toggle NSE scripts   - {'Disable' if self.nse_scanner else 'Enable'}
[2] Toggle auth testing  - {'Disable' if self.auth_tester and self.auth_tester.enabled else 'Enable'}
[3] Change timeout       - Banner grab timeout
[0] Back to main menu
        """
        
        self.console.print(menu)
        
        choice = Prompt.ask(
            "Select setting",
            choices=["0", "1", "2", "3"],
            default="0"
        )
        
        if choice == "1":
            if self.nse_scanner:
                self.nse_scanner = None
                self.console.print("[yellow]NSE scripts disabled[/yellow]")
            else:
                self.nse_scanner = NSEScanner(settings=self.settings)
                self.console.print("[green]NSE scripts enabled[/green]")
        elif choice == "2":
            if self.auth_tester and self.auth_tester.enabled:
                self.auth_tester = AuthTester(settings=self.settings, enabled=False)
                self.console.print("[yellow]Auth testing disabled[/yellow]")
            else:
                self.auth_tester = AuthTester(settings=self.settings, enabled=True)
                self.console.print("[green]Auth testing enabled[/green]")
                self.console.print("[red]WARNING: Only test devices you own![/red]")
        elif choice == "3":
            timeout = Prompt.ask("Enter timeout (seconds)", default="3")
            try:
                self.settings.banner_timeout = int(timeout)
                self.console.print(f"[green]Timeout set to {timeout}s[/green]")
            except ValueError:
                self.console.print("[red]Invalid timeout value[/red]")
    
    # Action implementations
    def quick_port_scan(self, ips: List[str]) -> None:
        """Perform quick port scan on hosts.
        
        Args:
            ips: List of IP addresses to scan
        """
        self.console.print(f"\n[blue]Quick scanning {len(ips)} host(s)...[/blue]")
        
        total_ports = 0
        for ip in ips:
            try:
                result = self.scanner.quick_scan(ip)
                
                if ip in result.hosts:
                    host_data = result.hosts[ip]
                    disc_host = self.discovered_hosts.get(ip)
                    if disc_host:
                        disc_host.open_ports = list(host_data.ports.keys())
                        disc_host.hostname = host_data.hostname
                        disc_host.services = {
                            p.port: p.service for p in host_data.ports.values()
                        }
                    total_ports += len(host_data.ports)
                
                self.console.print(f"[green]{ip}: Found {len(host_data.ports)} open ports[/green]")
                
            except Exception as e:
                self.console.print(f"[red]{ip}: Scan failed - {e}[/red]")
        
        # Show summary
        self.console.print(f"\n[bold]Scan Summary:[/bold] {total_ports} total open ports found on {len(ips)} hosts")
        self.console.print()
        self.show_discovered_hosts()
    
    def deep_scan(self, ips: List[str]) -> None:
        """Perform deep scan on hosts.
        
        Args:
            ips: List of IP addresses to scan
        """
        self.console.print(f"\n[blue]Deep scanning {len(ips)} host(s)...[/blue]")
        self.console.print("[dim]This may take a few minutes per host...[/dim]\n")
        
        for ip in ips:
            try:
                result = self.scanner.full_scan(ip)
                
                if ip in result.hosts:
                    host_data = result.hosts[ip]
                    disc_host = self.discovered_hosts.get(ip)
                    if disc_host:
                        disc_host.detailed_scan = result
                        disc_host.open_ports = list(host_data.ports.keys())
                        disc_host.hostname = host_data.hostname
                        disc_host.os_guess = host_data.os_guess
                        disc_host.services = {
                            p.port: p.service for p in host_data.ports.values()
                        }
                
                # Run NSE if enabled
                if self.nse_scanner:
                    self.console.print(f"[dim]Running NSE scripts on {ip}...[/dim]")
                    nse_result = self.nse_scanner.scan_host(ip)
                    if nse_result.os_guesses:
                        disc_host.os_guess = nse_result.os_guesses[0]
                    # Extract device type from NSE results
                    for script_name, results in nse_result.nse_results.items():
                        for nse_result_item in results:
                            if script_name == "http-server-header" and nse_result_item.output:
                                server = nse_result_item.output.strip()
                                if "/" in server:
                                    name = server.split("/")[0]
                                    if not disc_host.device_type:
                                        disc_host.device_type = name
                
                self.console.print(f"[green]{ip}: Deep scan complete - Found {len(host_data.ports)} ports[/green]")
                
            except Exception as e:
                self.console.print(f"[red]{ip}: Scan failed - {e}[/red]")
        
        # Show summary
        self.console.print(f"\n[bold]Deep Scan Complete[/bold]")
        self.show_discovered_hosts()
    
    def grab_banners(self, ips: List[str]) -> None:
        """Grab banners from hosts.
        
        Args:
            ips: List of IP addresses
        """
        self.console.print(f"\n[blue]Grabbing banners from {len(ips)} host(s)...[/blue]")
        
        devices_found = []
        for ip in ips:
            disc_host = self.discovered_hosts.get(ip)
            if not disc_host or not disc_host.open_ports:
                self.console.print(f"[yellow]{ip}: No ports to scan[/yellow]")
                continue
            
            try:
                banners = self.banner_grabber.grab_banners(ip, disc_host.open_ports)
                
                for port, banner in banners.items():
                    if banner.parsed_name:
                        disc_host.services[port] = banner.parsed_name
                    if banner.http_fingerprint and banner.http_fingerprint.device_type:
                        disc_host.device_type = banner.http_fingerprint.device_type
                        if banner.http_fingerprint.device_type not in devices_found:
                            devices_found.append(banner.http_fingerprint.device_type)
                
                self.console.print(f"[green]{ip}: Banners grabbed[/green]")
                
            except Exception as e:
                self.console.print(f"[red]{ip}: Failed - {e}[/red]")
        
        # Show summary
        if devices_found:
            self.console.print(f"\n[bold]Devices Identified:[/bold] {', '.join(devices_found)}")
        self.show_discovered_hosts()
    
    def check_credentials(self, ips: List[str]) -> None:
        """Check default credentials on hosts.
        
        Args:
            ips: List of IP addresses
        """
        if not self.auth_tester:
            self.console.print("[red]Auth tester not initialized. Enable in Settings.[/red]")
            return
        
        if not self.auth_tester.enabled:
            self.console.print("[red]Auth testing is disabled. Enable in Settings first.[/red]")
            return
        
        self.console.print(f"\n[yellow]WARNING: Only testing devices you own![/yellow]")
        self.console.print(f"[blue]Checking credentials on {len(ips)} host(s)...[/blue]\n")
        
        vulnerable_found = False
        
        for ip in ips:
            disc_host = self.discovered_hosts.get(ip)
            if not disc_host or not disc_host.open_ports:
                continue
            
            # Get device type if known
            device_type = disc_host.device_type or None
            
            # Check all services
            auth_results = self.auth_tester.check_all_services(
                ip, disc_host.open_ports, device_type
            )
            
            if auth_results:
                # Check for successful logins
                for port, results in auth_results.items():
                    for result in results:
                        if result.success:
                            self.console.print(f"[red]CRITICAL: {ip}:{port} - Default credentials work![/red]")
                            self.console.print(f"[red]  Username: {result.username}[/red]")
                            self.console.print(f"[red]  Password: {result.password}[/red]")
                            vulnerable_found = True
                            break
                    if vulnerable_found:
                        break
                
                if not vulnerable_found:
                    self.console.print(f"[green]{ip}: No default credentials found[/green]")
            else:
                self.console.print(f"[dim]{ip}: No testable services[/dim]")
        
        if not vulnerable_found:
            self.console.print("\n[green]No default credentials detected on tested hosts.[/green]")
        else:
            self.console.print("\n[yellow]Recommendation: Change default passwords immediately![/yellow]")
    
    def check_eol(self, ips: List[str]) -> None:
        """Check EOL status on hosts.
        
        Args:
            ips: List of IP addresses
        """
        self.console.print(f"\n[blue]Checking EOL status for {len(ips)} host(s)...[/blue]")
        
        total_services = 0
        for ip in ips:
            disc_host = self.discovered_hosts.get(ip)
            if not disc_host:
                continue
            
            for port, service in disc_host.services.items():
                try:
                    eol_status = self.eol_checker.check_version(service, "")
                    disc_host.eol_results[port] = eol_status
                    total_services += 1
                except Exception as e:
                    logger.debug(f"EOL check failed for {ip}:{port}: {e}")
            
            self.console.print(f"[green]{ip}: EOL check complete[/green]")
        
        # Show results summary
        self.show_eol_summary(ips)
    
    def show_eol_summary(self, ips: List[str]) -> None:
        """Display EOL check results summary.
        
        Args:
            ips: List of IPs that were checked
        """
        self.console.print(f"\n[bold]EOL Check Results Summary[/bold]\n")
        
        # Collect all EOL results
        all_results = []
        for ip in ips:
            host = self.discovered_hosts.get(ip)
            if not host:
                continue
            for port, eol in host.eol_results.items():
                service = host.services.get(port, "unknown")
                all_results.append({
                    'ip': ip,
                    'port': port,
                    'service': service,
                    'status': eol.level.value if eol else 'Unknown',
                    'eol_date': eol.eol_date.strftime('%Y-%m-%d') if eol and eol.eol_date else '-',
                    'days': eol.days_remaining if eol else None
                })
        
        if not all_results:
            self.console.print("[yellow]No EOL data collected. Services may not be recognized.[/yellow]")
            return
        
        # Create summary table
        table = Table(title=f"EOL Status for {len(all_results)} Services")
        table.add_column("IP Address", style="cyan")
        table.add_column("Port", justify="right")
        table.add_column("Service")
        table.add_column("Status", style="bold")
        table.add_column("EOL Date")
        table.add_column("Days")
        
        # Count by status
        status_counts = {'CRITICAL': 0, 'WARNING': 0, 'OK': 0, 'UNKNOWN': 0}
        
        for result in all_results:
            status = result['status']
            status_counts[status] = status_counts.get(status, 0) + 1
            
            # Color code status
            status_display = status
            if status == 'CRITICAL':
                status_display = f"[red]{status}[/red]"
            elif status == 'WARNING':
                status_display = f"[yellow]{status}[/yellow]"
            elif status == 'OK':
                status_display = f"[green]{status}[/green]"
            
            days_str = str(result['days']) if result['days'] is not None else '-'
            
            table.add_row(
                result['ip'],
                str(result['port']),
                result['service'],
                status_display,
                result['eol_date'],
                days_str
            )
        
        self.console.print(table)
        
        # Show summary counts
        self.console.print(f"\n[bold]Summary:[/bold]")
        self.console.print(f"  [red]CRITICAL: {status_counts.get('CRITICAL', 0)}[/red] - EOL reached, update immediately!")
        self.console.print(f"  [yellow]WARNING:  {status_counts.get('WARNING', 0)}[/yellow] - EOL approaching within 180 days")
        self.console.print(f"  [green]OK:       {status_counts.get('OK', 0)}[/green] - Supported")
        self.console.print(f"  UNKNOWN:  {status_counts.get('UNKNOWN', 0)} - Could not determine status")
    
    def view_host_details(self, ip: str) -> None:
        """View detailed information about a host.
        
        Args:
            ip: IP address to view
        """
        host = self.discovered_hosts.get(ip)
        if not host:
            self.console.print("[red]Host not found[/red]")
            return
        
        self.console.print(f"\n[bold]Host Details: {ip}[/bold]\n")
        
        info = f"""
IP Address:     {ip}
Hostname:       {host.hostname or 'Unknown'}
Status:         {host.status}
Device Type:    {host.device_type or 'Unknown'}
OS Guess:       {host.os_guess or 'Unknown'}
Last Seen:      {host.last_seen.strftime('%Y-%m-%d %H:%M:%S')}

Open Ports:     {len(host.open_ports)}
        """
        
        self.console.print(Panel(info, title=f"Host: {ip}"))
        
        if host.open_ports:
            table = Table(title="Services")
            table.add_column("Port")
            table.add_column("Service")
            table.add_column("EOL Status")
            
            for port in host.open_ports:
                service = host.services.get(port, "unknown")
                eol = host.eol_results.get(port)
                eol_status = eol.level.value if eol else "Unknown"
                
                table.add_row(str(port), service, eol_status)
            
            self.console.print(table)
    
    def quick_rediscover(self) -> None:
        """Quickly rediscover hosts with ping sweep."""
        self.console.print("\n[blue]Quick rediscovery...[/blue]")
        
        # Mark all as unknown first
        for host in self.discovered_hosts.values():
            host.status = "unknown"
        
        # Run ping sweep
        targets = parse_target_input(self.current_target)
        for target in targets:
            result = self.scanner.ping_sweep(target)
            
            for ip in result:
                if ip in self.discovered_hosts:
                    self.discovered_hosts[ip].status = "up"
                    self.discovered_hosts[ip].last_seen = datetime.now()
                else:
                    self.discovered_hosts[ip] = DiscoveredHost(
                        ip=ip,
                        status="up",
                        last_seen=datetime.now()
                    )
        
        up_count = sum(1 for h in self.discovered_hosts.values() if h.status == "up")
        self.console.print(f"[green]{up_count} hosts are up[/green]")
    
    def advanced_discovery(self) -> None:
        """Use NSE for advanced discovery."""
        if not self.nse_scanner:
            self.console.print("[red]NSE scanner not enabled. Enable in Settings.[/red]")
            return
        
        self.console.print("\n[blue]Running advanced discovery with NSE...[/blue]")
        # Implementation would go here
        self.console.print("[yellow]Advanced discovery not yet implemented[/yellow]")
    
    def generate_network_report(self) -> None:
        """Generate a summary report of the network."""
        self.console.print("\n[bold]Network Summary Report[/bold]\n")
        
        total = len(self.discovered_hosts)
        with_ports = sum(1 for h in self.discovered_hosts.values() if h.open_ports)
        with_devices = sum(1 for h in self.discovered_hosts.values() if h.device_type)
        
        # Count EOL status
        eol_counts = {"Supported": 0, "Approaching EOL": 0, "End of Life": 0, "Unknown": 0}
        for host in self.discovered_hosts.values():
            for port, eol in host.eol_results.items():
                if eol.level.value == "Supported":
                    eol_counts["Supported"] += 1
                elif eol.level.value == "Approaching EOL":
                    eol_counts["Approaching EOL"] += 1
                elif eol.level.value == "End of Life":
                    eol_counts["End of Life"] += 1
                else:
                    eol_counts["Unknown"] += 1
        
        report = f"""
Total Hosts Discovered:     {total}
Hosts with Open Ports:      {with_ports}
Hosts with Device ID:       {with_devices}

EOL Status Summary:
  Supported:                {eol_counts['Supported']}
  Approaching EOL:          {eol_counts['Approaching EOL']}
  End of Life:              {eol_counts['End of Life']}
  Unknown:                  {eol_counts['Unknown']}

Device Types Found:
        """
        
        self.console.print(report)
        
        # Count device types
        device_counts = {}
        for host in self.discovered_hosts.values():
            if host.device_type:
                device_counts[host.device_type] = device_counts.get(host.device_type, 0) + 1
        
        if device_counts:
            for device, count in sorted(device_counts.items()):
                self.console.print(f"  {device}: {count}")
        else:
            self.console.print("  [dim]No device types identified yet[/dim]")
    
    def view_scan_history(self) -> None:
        """View scan history."""
        history = ScanHistory()
        rows = history.history_table()
        if not rows:
            self.console.print("[yellow]No scan history found. Run a scan first.[/yellow]")
            return
        self.console.print(f"\n[bold]Scan History[/bold] ({len(rows)} scans)\n")
        self.console.print(
            f"{'Timestamp':<18} {'Target':<22} {'Profile':<8} "
            f"{'Hosts':<6} {'C':>4} {'H':>4} {'M':>4} {'L':>4}"
        )
        self.console.print("-" * 75)
        for r in rows:
            self.console.print(
                f"{r['timestamp']:<18} {r['target']:<22} {r['profile']:<8} "
                f"{r['hosts']:<6} {r['critical']:>4} {r['high']:>4} "
                f"{r['medium']:>4} {r['low']:>4}"
            )

    def export_results(self, format_type: str) -> None:
        """Export results to file.

        Args:
            format_type: 'json' or 'html'
        """
        if not self._last_scan_result:
            self.console.print("[yellow]No scan results to export. Run a scan first.[/yellow]")
            return

        try:
            exporter = ReportExporter(settings=self.settings)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"netwatch_export_{timestamp}.{format_type}"

            if format_type == "html":
                exporter.export_html(
                    scan_result=self._last_scan_result,
                    filename=filename,
                )
            else:
                exporter.export_json(
                    scan_result=self._last_scan_result,
                    filename=filename,
                )
            self.console.print(f"[green]Exported to: {filename}[/green]")
        except Exception as e:
            self.console.print(f"[red]Export failed: {e}[/red]")

    def compare_results(self) -> None:
        """Compare last two scans."""
        history = ScanHistory()
        diff = history.diff_last_two()
        if diff is None:
            self.console.print("[yellow]Need at least two scans for a diff.[/yellow]")
            return
        self.console.print(f"\n[bold]Diff:[/bold] {diff.older_ts[:19]}  ->  {diff.newer_ts[:19]}")
        self.console.print("-" * 60)
        for line in diff.summary_lines():
            self.console.print(f"  {line}")

    def _profile_scan(self, ips: List[str], profile: str) -> None:
        """Run a scan with a specific profile on hosts."""
        self.console.print(f"\n[blue]{profile} scanning {len(ips)} host(s)...[/blue]")
        for ip in ips:
            try:
                result = self.scanner.scan(ip, profile=profile)
                if ip in result.hosts:
                    host_data = result.hosts[ip]
                    disc_host = self.discovered_hosts.get(ip)
                    if disc_host:
                        disc_host.open_ports = list(host_data.ports.keys())
                        disc_host.hostname = host_data.hostname
                        disc_host.services = {
                            p.port: p.service for p in host_data.ports.values()
                        }
                self.console.print(f"[green]{ip}: {profile} scan complete[/green]")
            except Exception as e:
                self.console.print(f"[red]{ip}: Scan failed - {e}[/red]")
        self.show_discovered_hosts()

    def run_full_assessment(self) -> None:
        """Run full assessment on current target."""
        if not self.current_target:
            self.console.print("[red]No target set. Use Network Menu to set a target.[/red]")
            return
        self.console.print(f"\n[bold]Running Full Assessment on {self.current_target}...[/bold]")
        self.console.print("[dim]This runs all scan phases + security checks + HTML export.[/dim]\n")

        try:
            import argparse
            args = argparse.Namespace(
                target=self.current_target, profile="QUICK", verbose=False,
                no_color=False, nse=True, check_defaults=True, interactive=False,
                full_assessment=True, setup=False, update_cache=False,
                save_baseline=False, cache_status=False, check_version=False,
                update=False, history=False, diff=False, since=None,
                quiet=False, db="normal", modules=False, download=None,
            )
            from netwatch import NetWatch
            app = NetWatch(args)
            app.run_full_assessment(self.current_target)
            self.console.print("[green]Full assessment complete.[/green]")
        except Exception as e:
            self.console.print(f"[red]Assessment failed: {e}[/red]")
            logger.error(f"Full assessment error: {e}", exc_info=True)

    def modules_menu(self) -> None:
        """Show data modules and offer downloads."""
        self.console.print("\n[bold]Modules & Data[/bold]")
        try:
            from core.module_manager import ModuleManager
            mm = ModuleManager()

            menu = """
[1] Show module status   - List all data modules
[2] Download a module    - Download a specific module
[3] Download all modules - Download everything
[4] Update caches        - Refresh CVE/EOL data
[5] Cache status         - Show cache age and entries
[0] Back to main menu
            """
            self.console.print(menu)

            choice = Prompt.ask(
                "Select action",
                choices=["0", "1", "2", "3", "4", "5"],
                default="1"
            )

            if choice == "1":
                mm.show_modules()
            elif choice == "2":
                name = Prompt.ask("Module name")
                mm.download(name)
            elif choice == "3":
                mm.download_all()
            elif choice == "4":
                from core.cache_manager import UnifiedCacheManager
                cache = UnifiedCacheManager()
                cache.update_all()
                self.console.print("[green]Caches updated.[/green]")
            elif choice == "5":
                from core.update_manager import UpdateManager
                mgr = UpdateManager()
                mgr.show_cache_status()
        except Exception as e:
            self.console.print(f"[red]Error: {e}[/red]")
