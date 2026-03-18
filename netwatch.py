#!/usr/bin/env python3
"""
NetWatch - Network EOL Scanner & Security Assessment Tool.

Main entry point for the NetWatch CLI application. Provides network discovery,
banner grabbing, and End-of-Life (EOL) status checking for discovered services.

Usage:
    ./netwatch.py                    Launch interactive menu
    ./netwatch.py --target <CIDR>    Scan target directly
    ./netwatch.py --version          Show version and exit
    ./netwatch.py --help             Show help message

Author: NetWatch Team
License: MIT
Python: 3.9+
"""

import argparse
import json
import logging
import os
import sys
import signal
import platform
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

# Setup logger
logger = logging.getLogger(__name__)

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.progress import Progress

from config.settings import Settings, SCAN_DESCRIPTIONS
from core.scanner import NetworkScanner, ScanResult
from core.port_scanner import PortScanOrchestrator
from core.banner_grabber import BannerGrabber
from core.http_fingerprinter import HttpFingerprinter
from core.nse_scanner import NSEScanner
from core.auth_tester import AuthTester, AuthConfidence
from core.network_utils import get_local_subnet, validate_cidr
from core.findings import FindingRegistry, Finding, Severity
from core.cache_manager import UnifiedCacheManager
from core.cve_checker import CVEChecker, CVECacheBuilder
from core.ssl_checker import run_ssl_checks, get_last_ja3s_match
from core.web_checker import run_web_checks
from core.dns_checker import run_dns_checks
from core.upnp_checker import run_upnp_checks
from core.ftp_checker import run_ftp_checks
from core.ssh_checker import run_ssh_checks
from core.snmp_checker import run_snmp_checks, get_last_sysdescr, parse_sysdescr, SNMP_PORT
from core.smb_checker import run_smb_checks
from core.mdns_checker import run_mdns_discovery
from core.arp_checker import run_arp_checks
from core.baseline import BaselineManager
from core.risk_scorer import RiskScorer
from core.scan_history import ScanHistory
from core.update_manager import UpdateManager
from core.module_manager import ModuleManager, MODULE_REGISTRY
from eol.checker import EOLChecker, EOLStatus, EOLStatusLevel
from eol.cache import CacheManager
from ui.menu import Menu
from ui.display import Display
from ui.export import ReportExporter


def setup_logging(verbose: bool = False) -> None:
    """Configure logging for the application.
    
    Args:
        verbose: Enable debug logging if True
    """
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stderr)]
    )


def check_privileges() -> bool:
    """Check if running with root/admin privileges.
    
    Returns:
        True if running with elevated privileges
    """
    try:
        if platform.system() == 'Windows':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def signal_handler(signum, frame):
    """Handle interrupt signals gracefully."""
    print("\n\n[yellow]Scan cancelled.[/yellow]")
    sys.exit(0)


class NetWatch:
    """Main NetWatch application controller.
    
    Coordinates all components: scanning, banner grabbing, EOL checking,
    and user interface.
    
    Attributes:
        settings: Application configuration
        console: Rich console for output
        display: Display handler for formatted output
        menu: Interactive menu system
        scanner: Network scanner instance
        banner_grabber: Banner grabbing instance
        eol_checker: EOL checking instance
        cache: Cache manager for EOL data
        last_scan_result: Most recent scan results
        last_eol_data: Most recent EOL check results
    """
    
    def __init__(self, args: argparse.Namespace):
        """Initialize NetWatch application.
        
        Args:
            args: Command line arguments
        """
        self.settings = Settings()
        self.console = Console(color_system=None if args.no_color else "auto")
        self.display = Display(settings=self.settings, console=self.console, use_color=not args.no_color)
        self.menu = Menu(settings=self.settings, console=self.console)
        
        # Initialize components
        self.scanner = PortScanOrchestrator(settings=self.settings)
        self.banner_grabber = BannerGrabber(settings=self.settings)
        self.nse_scanner = NSEScanner(settings=self.settings) if args.nse else None
        self.auth_tester = AuthTester(settings=self.settings, enabled=args.check_defaults)
        self.cache = CacheManager(settings=self.settings)
        self.eol_checker = EOLChecker(cache=self.cache, settings=self.settings)
        self.exporter = ReportExporter(settings=self.settings)

        # New security modules
        self.unified_cache = UnifiedCacheManager()
        self.cve_checker = CVEChecker(self.unified_cache)
        self.baseline_manager = BaselineManager()
        self.finding_registry = FindingRegistry()
        self.risk_scorer = RiskScorer()
        self.scan_history = ScanHistory()

        # Store results for recheck/export
        self.last_scan_result: Optional[ScanResult] = None
        self.last_eol_data: Dict[str, Dict[int, EOLStatus]] = {}
        self.last_target: str = ""
        self.nse_results: Dict[str, Any] = {}
        self.auth_results: Dict[str, Any] = {}
        self.last_risk_scores: Dict = {}
        
        # CLI arguments
        self.args = args
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        
        # Check privileges
        self.has_privileges = check_privileges()
    
    def run(self) -> int:
        """Run the main application loop.
        
        Returns:
            Exit code (0 for success)
        """
        # Direct target scan mode
        if self.args.target:
            return self.direct_scan(self.args.target, self.args.profile or "QUICK")
        
        # Show banner
        self.display.show_banner()
        
        # Check privileges
        if not self.has_privileges:
            self.display.show_warning("Running without root/admin privileges - some features may be limited")
        
        # Main menu loop
        while True:
            try:
                choice = self.menu.show_main_menu()
                
                if choice == "1":
                    self.run_quick_scan()
                elif choice == "2":
                    self.run_full_scan()
                elif choice == "3":
                    self.run_stealth_scan()
                elif choice == "4":
                    self.run_custom_target()
                elif choice == "5":
                    self.recheck_eol()
                elif choice == "6":
                    self.export_report()
                elif choice == "7":
                    self.menu.show_settings()
                elif choice == "8":
                    self.menu.show_help()
                elif choice == "9":
                    self.console.print("\n[green]Goodbye![/green]")
                    return 0
                    
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Operation cancelled.[/yellow]")
            except Exception as e:
                logging.error(f"Error in main loop: {e}", exc_info=True)
                self.display.show_error(str(e))
        
        return 0
    
    def direct_scan(self, target: str, profile: str) -> int:
        """Run a direct scan without menu.
        
        Args:
            target: Target to scan
            profile: Scan profile to use
            
        Returns:
            Exit code
        """
        self.display.show_banner()
        
        if not self.has_privileges:
            self.display.show_warning("Running without root/admin privileges")
        
        # Validate target
        is_valid, error = validate_cidr(target)
        if not is_valid:
            # Try as single IP or hostname
            target = target  # Keep as-is for nmap to handle
        
        return self.perform_scan(target, profile)
    
    def run_quick_scan(self) -> None:
        """Run a quick scan."""
        target = self.get_target()
        if not target:
            return
        
        if self.menu.confirm_scan("QUICK", target):
            self.perform_scan(target, "QUICK")
    
    def run_full_scan(self) -> None:
        """Run a full comprehensive scan."""
        if not self.has_privileges:
            self.display.show_warning("Full scan works best with root/admin privileges")
        
        target = self.get_target()
        if not target:
            return
        
        if self.menu.confirm_scan("FULL", target):
            self.perform_scan(target, "FULL")
    
    def run_stealth_scan(self) -> None:
        """Run a stealth SYN scan."""
        if not self.has_privileges:
            self.display.show_error("Stealth scan requires root/admin privileges")
            return
        
        target = self.get_target()
        if not target:
            return
        
        if self.menu.confirm_scan("STEALTH", target):
            self.perform_scan(target, "STEALTH")
    
    def run_custom_target(self) -> None:
        """Run scan on custom user-specified target."""
        target = self.menu.prompt_target()
        if not target:
            return
        
        self.console.print("\n[bold]Select scan profile:[/bold]")
        self.console.print("  [1] Quick Scan")
        self.console.print("  [2] Full Scan")
        self.console.print("  [3] Stealth Scan")
        
        profile_choice = input("Choice [1]: ").strip() or "1"
        profile_map = {"1": "QUICK", "2": "FULL", "3": "STEALTH"}
        profile = profile_map.get(profile_choice, "QUICK")
        
        if self.menu.confirm_scan(profile, target):
            self.perform_scan(target, profile)
    
    def get_target(self) -> str:
        """Get scan target, using local subnet as default.
        
        Returns:
            Target string or empty string if cancelled
        """
        default_target = get_local_subnet() or self.settings.default_target
        return self.menu.prompt_target(default_target)
    
    def perform_scan(self, target: str, profile: str) -> int:
        """Execute network scan and EOL checks.
        
        Args:
            target: Target to scan
            profile: Scan profile to use
            
        Returns:
            Exit code
        """
        try:
            # Set up progress callback
            with self.display.create_progress() as progress:
                scan_task = progress.add_task(f"[cyan]Scanning {target}...", total=100)
                
                def update_progress(msg: str, pct: float):
                    progress.update(scan_task, description=f"[cyan]{msg}", completed=pct)
                
                self.scanner.set_progress_callback(update_progress)
                
                # Perform scan
                self.console.print(f"\n[bold blue]Starting {profile} scan on {target}...[/bold blue]")
                scan_result = self.scanner.scan(target, profile)
                
                progress.update(scan_task, completed=100)
            
            # Store result
            self.last_scan_result = scan_result
            self.last_target = target
            
            # Show basic results
            self.display.show_scan_info(scan_result)
            
            if not scan_result.hosts:
                self.console.print("[yellow]No hosts found.[/yellow]")
                return 0
            
            # Grab banners for services with versions
            self.grab_banners(scan_result)
            
            # Run NSE scans if enabled
            if self.nse_scanner:
                self.run_nse_scans(scan_result)
            
            # Check for default credentials if enabled
            if self.auth_tester and self.auth_tester.enabled:
                self.run_auth_tests(scan_result)
            
            # Check EOL status
            self.check_eol_status(scan_result)

            # Run new security checks (SSL, web, DNS, UPnP, CVE, baseline)
            self.run_security_checks(scan_result)

            # Show results table
            self.display.show_results_table(scan_result, self.last_eol_data)

            # Show summary
            stats = self.calculate_stats(scan_result, self.last_eol_data)
            self.display.show_summary(stats)

            # Print finding counts
            counts = self.finding_registry.counts()
            self.console.print(
                f"\n[bold]Security findings:[/bold] "
                f"[red]{counts['CRITICAL']} Critical[/red]  "
                f"[yellow]{counts['HIGH']} High[/yellow]  "
                f"[cyan]{counts['MEDIUM']} Medium[/cyan]  "
                f"[blue]{counts['LOW']} Low[/blue]  "
                f"[dim]{counts['INFO']} Info[/dim]"
            )

            # Compute risk scores
            self.last_risk_scores = self.risk_scorer.score_all(self.finding_registry)
            if self.last_risk_scores:
                self.console.print("\n[bold]Device risk scores:[/bold]")
                for ip, risk in self.last_risk_scores.items():
                    self.console.print(
                        f"  {ip:<18} {risk.score:>3}/100  {risk.label}"
                    )

            # Auto-save scan history
            if getattr(self.settings, 'auto_save_history', True):
                try:
                    self.scan_history.save(
                        scan_result, self.finding_registry, target=self.last_target
                    )
                except Exception as e:
                    logger.debug(f"History save failed: {e}")

            # Auto-save baseline if flag set
            if getattr(self.args, 'save_baseline', False):
                saved = self.baseline_manager.save_baseline_from_scan(
                    scan_result, network=self.last_target
                )
                if saved > 0:
                    self.display.show_success(f"Baseline saved: {saved} devices recorded")
                else:
                    self.display.show_warning(
                        "Baseline saved but 0 devices recorded (no MAC addresses). "
                        "Run with root/sudo for MAC address detection: sudo python3 netwatch.py --save-baseline --target ..."
                    )

            return 0
            
        except Exception as e:
            logging.error(f"Scan failed: {e}", exc_info=True)
            self.display.show_error(f"Scan failed: {e}")
            return 1
    
    def grab_banners(self, scan_result: ScanResult) -> None:
        """Grab banners from discovered services.
        
        Args:
            scan_result: Scan results containing hosts and ports
        """
        with self.display.create_progress() as progress:
            total_ports = sum(len(h.ports) for h in scan_result.hosts.values())
            banner_task = progress.add_task("[cyan]Grabbing banners...", total=total_ports)
            
            for ip, host in scan_result.hosts.items():
                if not host.ports:
                    continue
                
                open_ports = [p.port for p in host.ports.values() if p.state == 'open']
                if not open_ports:
                    continue
                
                # Grab banners concurrently
                banners = self.banner_grabber.grab_banners(ip, open_ports)
                
                # Update port info with banner data
                for port_num, banner_result in banners.items():
                    if port_num in host.ports:
                        host.ports[port_num].banner = banner_result.raw_banner
                        host.ports[port_num].http_fingerprint = banner_result.http_fingerprint
                        
                        # Update service/version from banner if detected
                        if banner_result.parsed_name:
                            host.ports[port_num].service = banner_result.parsed_name
                        if banner_result.parsed_version:
                            host.ports[port_num].version = banner_result.parsed_version
                        
                        # Log HTTP fingerprint info if found
                        if banner_result.http_fingerprint:
                            fp = banner_result.http_fingerprint
                            if fp.device_type or fp.firmware_version:
                                logger.info(f"HTTP fingerprint {ip}:{port_num}: "
                                          f"{fp.device_type} {fp.model} "
                                          f"Firmware: {fp.firmware_version}")
                
                progress.update(banner_task, advance=len(open_ports))
    
    def check_eol_status(self, scan_result: ScanResult) -> None:
        """Check EOL status for discovered services.
        
        Args:
            scan_result: Scan results
        """
        self.last_eol_data = {}
        
        with self.display.create_progress() as progress:
            total_services = sum(
                1 for h in scan_result.hosts.values() 
                for p in h.ports.values() 
                if p.service and p.service != 'unknown'
            )
            
            eol_task = progress.add_task("[cyan]Checking EOL status...", total=max(total_services, 1))
            
            for ip, host in scan_result.hosts.items():
                self.last_eol_data[ip] = {}
                
                for port_num, port in host.ports.items():
                    if not port.service or port.service == 'unknown':
                        continue

                    # Skip EOL check when no version info is available — no version
                    # means we cannot match to an EOL cycle; skip avoids false UNKNOWNs.
                    has_version = bool(port.version and port.version.strip())
                    has_banner = bool(port.banner and port.banner.strip())
                    if not has_version and not has_banner:
                        progress.update(eol_task, advance=1)
                        continue

                    # Try banner first if available
                    if has_banner:
                        eol_status = self.eol_checker.check_banner(port.banner)
                    else:
                        # Use service name and version
                        eol_status = self.eol_checker.check_version(
                            port.service,
                            port.version or ""
                        )

                    # Only store the result if we actually identified a product.
                    # product="unknown" means the banner/service gave no useful info —
                    # these are N/A, not meaningful UNKNOWN EOL results.
                    if eol_status.product and eol_status.product != "unknown":
                        self.last_eol_data[ip][port_num] = eol_status
                    progress.update(eol_task, advance=1)
    
    def run_nse_scans(self, scan_result: ScanResult) -> None:
        """Run NSE (Nmap Scripting Engine) scans on discovered hosts.
        
        Args:
            scan_result: Scan results containing hosts and ports
        """
        if not self.nse_scanner:
            return
        
        print("Running NSE enhanced detection...")
        
        for ip, host in scan_result.hosts.items():
            if not host.ports:
                continue
            
            # Get list of open ports as string
            open_ports = [str(p.port) for p in host.ports.values() if p.state == 'open']
            if not open_ports:
                continue
            
            port_string = ",".join(open_ports)
            
            try:
                # Run NSE scan
                nse_info = self.nse_scanner.scan_host(ip, ports=port_string)
                self.nse_results[ip] = nse_info
                
                # Update host info with NSE findings
                if nse_info.os_guesses:
                    host.os_guess = nse_info.os_guesses[0]
                
                # Update port info with NSE script results
                for script_name, results in nse_info.nse_results.items():
                    for nse_result in results:
                        port_num = nse_result.port
                        if port_num and port_num in host.ports:
                            # Update service info if found
                            if script_name == "http-title" and nse_result.output:
                                # Store in http_fingerprint
                                if not host.ports[port_num].http_fingerprint:
                                    from core.http_fingerprinter import HttpFingerprint
                                    host.ports[port_num].http_fingerprint = HttpFingerprint(
                                        host=ip, port=port_num
                                    )
                                host.ports[port_num].http_fingerprint.raw_html = nse_result.output
                            
                            elif script_name == "http-server-header" and nse_result.output:
                                # Update service version from server header
                                server = nse_result.output.strip()
                                if "/" in server:
                                    name, version = server.split("/", 1)
                                    host.ports[port_num].service = name.lower()
                                    host.ports[port_num].version = version.split()[0]
                
                logger.info(f"NSE scan completed for {ip}")
                
            except Exception as e:
                logger.error(f"NSE scan failed for {ip}: {e}")
    
    def run_auth_tests(self, scan_result: ScanResult) -> None:
        """Check for default credentials on discovered services.
        
        WARNING: Only runs if auth testing is explicitly enabled.
        
        Args:
            scan_result: Scan results containing hosts and ports
        """
        if not self.auth_tester or not self.auth_tester.enabled:
            return
        
        print("WARNING: Testing default credentials (only test your own devices!)")
        
        for ip, host in scan_result.hosts.items():
            if not host.ports:
                continue
            
            # Detect device type from existing data
            device_type = None
            for port in host.ports.values():
                if port.http_fingerprint and port.http_fingerprint.device_type:
                    device_type = port.http_fingerprint.device_type
                    break
                if port.service:
                    # Try to identify from service name
                    service_lower = port.service.lower()
                    for brand in ["tp-link", "asus", "netgear", "linksys", "d-link", "ubiquiti", "mikrotik"]:
                        if brand in service_lower:
                            device_type = brand.replace("-", " ").title()
                            break
            
            # Get open ports for testable services
            open_ports = [p.port for p in host.ports.values() if p.state == 'open']
            
            # Run auth tests
            auth_results = self.auth_tester.check_all_services(
                ip, open_ports, device_type
            )
            
            if auth_results:
                self.auth_results[ip] = auth_results
                
                # Generate and display report (only confirmed/likely findings)
                report = self.auth_tester.generate_report(auth_results)
                if report["vulnerable_services"]:
                    print(f"CRITICAL: {ip} has default credentials on ports: {report['vulnerable_services']}")
                if report.get("suspected_services"):
                    print(f"LOW: {ip} — possible default credentials on ports (unconfirmed): {report['suspected_services']}")
    
    def run_security_checks(self, scan_result: ScanResult) -> FindingRegistry:
        """Run all new security checks and collect findings.

        This runs after the existing scan pipeline (banners, NSE, auth tests,
        EOL checks are already done). Results are added to self.finding_registry.

        New checks:
            - SSL/TLS certificate analysis
            - Web interface security (headers, admin paths, HTTP login forms)
            - DNS hijack detection
            - UPnP exposure
            - CVE correlation for detected service versions
            - EOL results converted to findings
            - Baseline comparison (rogue device detection)
            - Insecure protocol detection (Telnet, FTP, SNMP, etc.)
            - Auth test results converted to CRITICAL findings

        Returns:
            The populated FindingRegistry.
        """
        self.finding_registry.clear()

        # --- Print cache warnings (non-blocking) ---
        for warning in self.unified_cache.stale_warnings():
            self.console.print(f"[yellow]WARNING: {warning}[/yellow]")

        with self.display.create_progress() as progress:
            task = progress.add_task("[cyan]Running security checks...", total=None)

            for ip, host in scan_result.hosts.items():
                if host.state != "up":
                    continue

                open_ports = [p.port for p in host.ports.values() if p.state == "open"]

                # ---- Insecure protocols ----
                progress.update(task, description=f"[cyan]Checking protocols: {ip}")
                self.finding_registry.add_all(
                    _check_insecure_protocols(ip, open_ports)
                )

                # ---- SSL/TLS checks (includes JA3S fingerprinting) ----
                progress.update(task, description=f"[cyan]SSL/TLS checks: {ip}")
                try:
                    ssl_findings = run_ssl_checks(
                        ip, open_ports,
                        timeout=self.settings.ssl_check_timeout,
                    )
                    self.finding_registry.add_all(ssl_findings)
                except Exception as e:
                    logger.debug(f"SSL check error for {ip}: {e}")

                # ---- JA3S match → EOL pipeline ----
                # If a JA3S signature matched a known software (e.g. "nginx 1.18.0"),
                # feed the product name and version into the EOL checker.
                try:
                    for port in open_ports:
                        ja3s_match = get_last_ja3s_match(ip, port)
                        if ja3s_match:
                            app_name, app_desc = ja3s_match
                            # Try to extract product slug and version from App string
                            # App strings can look like "nginx/1.18.0" or "Apache httpd 2.4.41"
                            parts = app_name.replace("/", " ").split()
                            if len(parts) >= 2:
                                product_slug = parts[0].lower()
                                version = parts[1]
                                eol_status = self.eol_checker.check_version(product_slug, version)
                                if ip not in self.last_eol_data:
                                    self.last_eol_data[ip] = {}
                                self.last_eol_data[ip][port] = eol_status
                                logger.info(
                                    f"JA3S→EOL: {ip}:{port} {product_slug} {version} "
                                    f"→ {eol_status.level.value}"
                                )
                except Exception as e:
                    logger.debug(f"JA3S EOL pipeline error for {ip}: {e}")

                # ---- Web interface checks ----
                progress.update(task, description=f"[cyan]Web checks: {ip}")
                try:
                    web_findings = run_web_checks(
                        ip, open_ports,
                        timeout=self.settings.web_check_timeout,
                    )
                    self.finding_registry.add_all(web_findings)
                except Exception as e:
                    logger.debug(f"Web check error for {ip}: {e}")

                # ---- FTP checks ----
                progress.update(task, description=f"[cyan]FTP checks: {ip}")
                try:
                    ftp_findings = run_ftp_checks(
                        ip, open_ports, timeout=self.settings.banner_timeout
                    )
                    self.finding_registry.add_all(ftp_findings)
                except Exception as e:
                    logger.debug(f"FTP check error for {ip}: {e}")

                # ---- SSH deep analysis ----
                progress.update(task, description=f"[cyan]SSH analysis: {ip}")
                try:
                    ssh_findings = run_ssh_checks(ip, open_ports)
                    self.finding_registry.add_all(ssh_findings)
                except Exception as e:
                    logger.debug(f"SSH check error for {ip}: {e}")

                # ---- SMB deep analysis ----
                progress.update(task, description=f"[cyan]SMB analysis: {ip}")
                try:
                    smb_findings = run_smb_checks(ip, open_ports)
                    self.finding_registry.add_all(smb_findings)
                except Exception as e:
                    logger.debug(f"SMB check error for {ip}: {e}")

                # ---- SNMP checks ----
                progress.update(task, description=f"[cyan]SNMP checks: {ip}")
                try:
                    snmp_findings = run_snmp_checks(ip, open_ports)
                    self.finding_registry.add_all(snmp_findings)
                except Exception as e:
                    logger.debug(f"SNMP check error for {ip}: {e}")

                # ---- SNMP sysDescr → EOL pipeline ----
                # If SNMP returned a sysDescr, parse it for firmware version
                # and feed directly into EOL checker (bypasses nmap version detection).
                try:
                    sysdescr = get_last_sysdescr(ip)
                    if sysdescr:
                        parsed = parse_sysdescr(sysdescr)
                        if parsed:
                            product_slug, version = parsed
                            eol_status = self.eol_checker.check_version(product_slug, version)
                            if ip not in self.last_eol_data:
                                self.last_eol_data[ip] = {}
                            self.last_eol_data[ip][SNMP_PORT] = eol_status
                            logger.info(
                                f"SNMP sysDescr EOL: {ip} {product_slug} {version} → {eol_status.level.value}"
                            )
                except Exception as e:
                    logger.debug(f"SNMP sysDescr EOL pipeline error for {ip}: {e}")

                # ---- CVE lookup for each detected service version ----
                progress.update(task, description=f"[cyan]CVE lookup: {ip}")
                for port_num, port in host.ports.items():
                    if port.service and port.version:
                        try:
                            cve_findings = self.cve_checker.check(
                                host=ip,
                                product=port.service,
                                version=port.version,
                                port=port.port,
                                protocol=port.protocol,
                            )
                            self.finding_registry.add_all(cve_findings)
                        except Exception as e:
                            logger.debug(f"CVE check error {ip}:{port_num}: {e}")

            # ---- EOL results → Findings ----
            progress.update(task, description="[cyan]Converting EOL results...")
            self.finding_registry.add_all(
                self._eol_to_findings(scan_result, self.last_eol_data)
            )

            # ---- Auth test results → CRITICAL findings ----
            progress.update(task, description="[cyan]Processing auth results...")
            self.finding_registry.add_all(
                self._auth_to_findings(self.auth_results)
            )

            # ---- DNS hijack check ----
            progress.update(task, description="[cyan]DNS security check...")
            try:
                dns_findings = run_dns_checks(local_network=self.last_target)
                self.finding_registry.add_all(dns_findings)
            except Exception as e:
                logger.debug(f"DNS check error: {e}")

            # ---- UPnP discovery ----
            progress.update(task, description="[cyan]UPnP discovery...")
            try:
                upnp_findings = run_upnp_checks(
                    timeout=self.settings.upnp_discovery_timeout
                )
                self.finding_registry.add_all(upnp_findings)
            except Exception as e:
                logger.debug(f"UPnP check error: {e}")

            # ---- mDNS/Zeroconf discovery ----
            progress.update(task, description="[cyan]mDNS discovery...")
            try:
                known_ips = set(scan_result.hosts.keys())
                mdns_findings = run_mdns_discovery(
                    timeout=self.settings.upnp_discovery_timeout * 2,
                    known_hosts=known_ips,
                )
                self.finding_registry.add_all(mdns_findings)
            except Exception as e:
                logger.debug(f"mDNS discovery error: {e}")

            # ---- ARP spoofing detection ----
            if self.last_target:
                progress.update(task, description="[cyan]ARP spoofing detection...")
                try:
                    arp_findings = run_arp_checks(
                        network=self.last_target,
                        save_baseline=True,
                        timeout=2.0,
                    )
                    self.finding_registry.add_all(arp_findings)
                except Exception as e:
                    logger.debug(f"ARP check error: {e}")

            # ---- Baseline comparison (rogue devices) ----
            if self.baseline_manager.exists():
                progress.update(task, description="[cyan]Baseline comparison...")
                try:
                    baseline_findings = self.baseline_manager.compare_scan(scan_result)
                    self.finding_registry.add_all(baseline_findings)
                except Exception as e:
                    logger.debug(f"Baseline check error: {e}")

        # Deduplicate (same host+port+title from multiple code paths)
        self.finding_registry.deduplicate()
        return self.finding_registry

    def _eol_to_findings(
        self,
        scan_result: ScanResult,
        eol_data: Dict,
    ) -> list:
        """Convert EOLStatus objects to Finding objects."""
        findings = []
        for ip, host_eol in eol_data.items():
            for port_num, eol_status in host_eol.items():
                host = scan_result.hosts.get(ip)
                port_info = host.ports.get(port_num) if host else None
                service = port_info.service if port_info else "unknown"
                version = port_info.version if port_info else ""

                if eol_status.level == EOLStatusLevel.CRITICAL:
                    sev = Severity.HIGH  # EOL = HIGH (not immediate exploit)
                    title = f"End-of-Life software: {eol_status.product} {eol_status.version}"
                    explanation = (
                        f"{eol_status.product} {eol_status.version} reached End-of-Life "
                        f"on {eol_status.eol_date.strftime('%Y-%m-%d') if eol_status.eol_date else 'an unknown date'}. "
                        "The vendor no longer releases security patches for this version. "
                        "Any new vulnerabilities discovered will remain unpatched forever."
                    )
                    recommendation = (
                        f"Upgrade {eol_status.product} to the latest supported version "
                        f"({eol_status.latest_version or 'check vendor site'}). "
                        "If this is a network device (router, NAS, printer), check the "
                        "manufacturer's website for a firmware update or replacement options."
                    )
                elif eol_status.level == EOLStatusLevel.WARNING:
                    sev = Severity.MEDIUM
                    title = (
                        f"EOL approaching: {eol_status.product} {eol_status.version} "
                        f"({eol_status.days_remaining} days)"
                    )
                    explanation = (
                        f"{eol_status.product} {eol_status.version} reaches End-of-Life "
                        f"in {eol_status.days_remaining} days. After that date, security "
                        "patches will no longer be issued by the vendor."
                    )
                    recommendation = (
                        f"Plan to upgrade {eol_status.product} to version "
                        f"{eol_status.latest_version or 'the latest'} before EOL. "
                        "Schedule the update during a maintenance window."
                    )
                else:
                    continue  # OK or UNKNOWN — not a finding

                findings.append(Finding(
                    severity=sev,
                    title=title,
                    host=ip,
                    port=port_num,
                    protocol=port_info.protocol if port_info else "tcp",
                    category="End-of-Life Software",
                    description=eol_status.message,
                    explanation=explanation,
                    recommendation=recommendation,
                    evidence=f"Product: {eol_status.product} {eol_status.version}",
                    tags=["eol", eol_status.product.lower()],
                ))
        return findings

    def _auth_to_findings(self, auth_results: Dict) -> list:
        """Convert auth test results to findings, severity based on confidence.

        CONFIRMED/LIKELY  → CRITICAL finding
        SUSPECTED         → LOW finding (manual verification note)
        FAILED            → no finding
        """
        findings = []
        for ip, port_map in auth_results.items():
            # port_map is Dict[int, List[AuthTestResult]]
            if not port_map:
                continue
            for port_num, result_list in port_map.items():
                for result in result_list:
                    if not getattr(result, "success", False):
                        continue

                    port = getattr(result, "port", port_num)
                    service = getattr(result, "service", "unknown")
                    username = getattr(result, "username", "unknown")
                    password = getattr(result, "password", "unknown")
                    confidence = getattr(result, "confidence", AuthConfidence.FAILED)
                    notes = getattr(result, "notes", "")

                    if confidence in (AuthConfidence.CONFIRMED, AuthConfidence.LIKELY):
                        severity = Severity.CRITICAL
                        title = f"Default credentials accepted: {username}/{password} on port {port}"
                        explanation = (
                            "This device still uses its factory-default username and password. "
                            "This is one of the most dangerous misconfigurations possible — "
                            "anyone on your network (or internet if the service is exposed) "
                            "can log in and take full control of this device."
                        )
                        recommendation = (
                            f"1. Log in to the device at {ip}:{port} immediately.\n"
                            "2. Navigate to Administration > Change Password (or similar).\n"
                            "3. Set a strong, unique password (12+ characters, mixed case, "
                            "numbers, and symbols).\n"
                            "4. Disable remote access if not needed.\n"
                            "5. Check for and apply any firmware updates."
                        )
                        tags = ["authentication", "default-credentials", "critical"]
                    elif confidence == AuthConfidence.SUSPECTED:
                        severity = Severity.LOW
                        title = f"Possible default credentials on port {port} — verify manually"
                        explanation = (
                            "A weak indicator suggests the login may have succeeded, but the "
                            "result is not conclusive. Manual verification is required before "
                            "treating this as a confirmed vulnerability."
                        )
                        recommendation = (
                            f"1. Manually attempt to log in to {ip}:{port} with {username}/{password}.\n"
                            "2. If login succeeds, change the password immediately.\n"
                            "3. If login fails, disregard this finding."
                        )
                        tags = ["authentication", "default-credentials", "suspected"]
                    else:
                        continue  # FAILED — no finding

                    findings.append(Finding(
                        severity=severity,
                        title=title,
                        host=ip,
                        port=port,
                        protocol="tcp",
                        category="Authentication",
                        description=(
                            f"Port {port} ({service}) may accept the default credentials "
                            f"username={username!r}. Confidence: {confidence.value}."
                        ),
                        explanation=explanation,
                        recommendation=recommendation,
                        evidence=(
                            f"Credentials tested: {username}:{password} → "
                            f"{confidence.value}. {notes}"
                        ),
                        tags=tags,
                    ))
        return findings

    def recheck_eol(self) -> None:
        """Recheck EOL status using last scan results."""
        if not self.last_scan_result:
            self.display.show_error("No previous scan results available")
            return
        
        self.console.print("[cyan]Refreshing EOL data...[/cyan]")
        
        # Clear cache to force fresh API calls
        self.cache.cleanup_expired()
        
        # Recheck EOL status
        self.check_eol_status(self.last_scan_result)
        
        # Show updated results
        self.display.show_results_table(self.last_scan_result, self.last_eol_data)
        stats = self.calculate_stats(self.last_scan_result, self.last_eol_data)
        self.display.show_summary(stats)
    
    def export_report(self) -> None:
        """Export last scan results to file."""
        if not self.last_scan_result:
            self.display.show_error("No scan results to export")
            return
        
        format_type = self.menu.prompt_export_format()
        
        # Generate default filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"netwatch_scan_{timestamp}.{format_type}"
        
        filename = self.menu.prompt_filename(default_name)
        
        # Ensure correct extension
        if not filename.endswith(f".{format_type}"):
            filename += f".{format_type}"
        
        # Export (pass findings if available)
        findings_arg = self.finding_registry if self.finding_registry.total() > 0 else None
        scan_diff = None
        try:
            scan_diff = self.scan_history.diff_last_two()
        except Exception:
            pass
        success = self.exporter.export(
            format_type,
            self.last_scan_result,
            filename,
            self.last_eol_data,
            findings=findings_arg,
            risk_scores=self.last_risk_scores or None,
            scan_diff=scan_diff,
        )
        
        if success:
            self.display.show_success(f"Report exported to {filename}")
        else:
            self.display.show_error("Failed to export report")
    
    def calculate_stats(
        self, 
        scan_result: ScanResult,
        eol_data: Dict[str, Dict[int, EOLStatus]]
    ) -> Dict[str, int]:
        """Calculate summary statistics.
        
        Args:
            scan_result: Scan results
            eol_data: EOL status data
            
        Returns:
            Dictionary of statistics
        """
        stats = {
            'total_hosts': len(scan_result.hosts),
            'hosts_up': sum(1 for h in scan_result.hosts.values() if h.state == 'up'),
            'open_ports': sum(len(h.ports) for h in scan_result.hosts.values()),
            'critical': 0,
            'warning': 0,
            'ok': 0,
            'unknown': 0,
        }
        
        for host_eol in eol_data.values():
            for eol_status in host_eol.values():
                if eol_status.level.value == 'CRITICAL':
                    stats['critical'] += 1
                elif eol_status.level.value == 'WARNING':
                    stats['warning'] += 1
                elif eol_status.level.value == 'OK':
                    stats['ok'] += 1
                elif eol_status.level.value == 'N/A':
                    pass  # Not tracked — excluded from UNKNOWN count
                else:
                    stats['unknown'] += 1
        
        return stats
    
    def run_full_assessment(self, target: str) -> int:
        """Run comprehensive security assessment on target.
        
        This performs a complete workflow:
        1. Discovery scan (ping sweep)
        2. Port scanning on discovered hosts
        3. Banner grabbing
        4. NSE enhanced detection
        5. Default credential testing
        6. EOL status checking
        7. Security analysis (SSL/TLS, SSH, DNS, UPnP, CVE, JA3S)
        8. Auto-export to HTML with timestamp
        
        Args:
            target: Target network range (e.g., "192.168.*.*")
            
        Returns:
            Exit code
        """
        from datetime import datetime
        from core.input_parser import parse_target_input
        
        # Estimate scan size and warn user
        targets = parse_target_input(target)
        estimated_hosts = 0
        for t in targets:
            if '*.' in t or '/16' in t or '/8' in t:
                estimated_hosts = 65000
                break
            elif '/24' in t or '*.' in t:
                estimated_hosts += 254
            elif '-' in t:
                estimated_hosts += 100
            else:
                estimated_hosts += 1
        
        # Show warning for large scans
        if estimated_hosts > 1000:
            self.console.print("\n" + "="*70)
            self.console.print("[bold yellow]WARNING: LARGE SCAN DETECTED[/bold yellow]")
            self.console.print(f"Target: {target}")
            self.console.print(f"Estimated hosts: ~{estimated_hosts:,}")
            self.console.print("\nThis comprehensive scan will:")
            self.console.print("  - Discover all active hosts")
            self.console.print("  - Port scan each host")
            self.console.print("  - Grab banners and identify services")
            self.console.print("  - Run NSE scripts (if enabled)")
            self.console.print("  - Test for default passwords")
            self.console.print("  - Check EOL status")
            self.console.print("  - Export results to HTML")
            self.console.print(f"\n[bold red]Estimated time: 2-6 hours[/bold red]")
            self.console.print("="*70 + "\n")
            
            # In non-interactive mode, we need to use a different approach
            # For now, we'll proceed with the scan but show prominent warnings
            self.console.print("[yellow]Proceeding with full assessment...[/yellow]\n")
        
        start_time = datetime.now()
        
        try:
            # Phase 1: Discovery
            self.console.print("[bold blue]Phase 1/6: Host Discovery[/bold blue]")
            discovery_result = self.scanner.ping_sweep(target)
            
            if not discovery_result:
                self.console.print("[yellow]No active hosts found.[/yellow]")
                return 0
            
            discovered_hosts = list(discovery_result)
            self.console.print(f"[green]Discovered {len(discovered_hosts)} active hosts[/green]\n")
            
            # Phase 2: Port Scanning
            self.console.print("[bold blue]Phase 2/6: Port Scanning[/bold blue]")
            scan_result = ScanResult(target=target, profile="FULL")
            scan_result.start_time = start_time
            
            for idx, ip in enumerate(discovered_hosts, 1):
                self.console.print(f"[dim]Scanning {ip} ({idx}/{len(discovered_hosts)})...[/dim]")
                try:
                    host_result = self.scanner.quick_scan(ip)
                    if ip in host_result.hosts:
                        scan_result.hosts[ip] = host_result.hosts[ip]
                except Exception as e:
                    logger.debug(f"Scan failed for {ip}: {e}")
            
            scan_result.end_time = datetime.now()
            self.last_scan_result = scan_result
            self.console.print(f"[green]Port scanning complete: {len(scan_result.hosts)} hosts scanned[/green]\n")
            
            # Phase 3: Banner Grabbing
            self.console.print("[bold blue]Phase 3/6: Service Banner Grabbing[/bold blue]")
            self.grab_banners(scan_result)
            self.console.print("[green]Banner grabbing complete[/green]\n")
            
            # Phase 4: NSE Scripts (if scanner available)
            if self.nse_scanner:
                self.console.print("[bold blue]Phase 4/6: NSE Enhanced Detection[/bold blue]")
                self.run_nse_scans(scan_result)
                self.console.print("[green]NSE scanning complete[/green]\n")
            else:
                self.console.print("[dim]Phase 4/6: NSE Enhanced Detection (skipped - enable with --nse)[/dim]\n")
            
            # Phase 5: Default Credentials
            if self.auth_tester and self.auth_tester.enabled:
                self.console.print("[bold blue]Phase 5/6: Default Credential Testing[/bold blue]")
                self.console.print("[yellow]WARNING: Only testing devices you own![/yellow]")
                self.run_auth_tests(scan_result)
                self.console.print("[green]Credential testing complete[/green]\n")
            else:
                self.console.print("[dim]Phase 5/6: Default Credential Testing (skipped - enable with --check-defaults)[/dim]\n")
            
            # Phase 6: EOL Check
            self.console.print("[bold blue]Phase 6/7: EOL Status Check[/bold blue]")
            self.check_eol_status(scan_result)
            self.console.print("[green]EOL checking complete[/green]\n")

            # Phase 7: Security Checks (SSL/TLS, SSH, DNS, UPnP, CVE, JA3S)
            self.console.print("[bold blue]Phase 7/7: Security Analysis[/bold blue]")
            self.run_security_checks(scan_result)
            self.console.print("[green]Security analysis complete[/green]\n")

            # Show results
            self.display.show_scan_info(scan_result)
            self.display.show_results_table(scan_result, self.last_eol_data)
            stats = self.calculate_stats(scan_result, self.last_eol_data)
            self.display.show_summary(stats)

            # Print security finding counts
            counts = self.finding_registry.counts()
            self.console.print(
                f"\n[bold]Security findings:[/bold] "
                f"[red]{counts['CRITICAL']} Critical[/red]  "
                f"[yellow]{counts['HIGH']} High[/yellow]  "
                f"[cyan]{counts['MEDIUM']} Medium[/cyan]  "
                f"[blue]{counts['LOW']} Low[/blue]  "
                f"[dim]{counts['INFO']} Info[/dim]"
            )

            # Compute and display risk scores
            self.last_risk_scores = self.risk_scorer.score_all(self.finding_registry)
            if self.last_risk_scores:
                self.console.print("\n[bold]Device risk scores:[/bold]")
                for ip, risk in self.last_risk_scores.items():
                    self.console.print(
                        f"  {ip:<18} {risk.score:>3}/100  {risk.label}"
                    )
            
            # Auto-export to HTML with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"netwatch_assessment_{timestamp}.html"
            
            self.console.print(f"\n[bold blue]Exporting report to {filename}...[/bold blue]")
            success = self.exporter.export_html(
                scan_result,
                filename,
                self.last_eol_data
            )
            
            if success:
                self.console.print(f"[bold green]Report saved: {filename}[/bold green]")
                # Also save to reports directory
                reports_dir = Path("reports")
                reports_dir.mkdir(exist_ok=True)
                report_path = reports_dir / filename
                self.exporter.export_html(scan_result, str(report_path), self.last_eol_data)
                self.console.print(f"[bold green]Report also saved to: {report_path}[/bold green]")
            else:
                self.console.print("[red]Failed to export report[/red]")
            
            return 0
            
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Assessment interrupted by user[/yellow]")
            return 130
        except Exception as e:
            logging.error(f"Full assessment failed: {e}", exc_info=True)
            self.display.show_error(f"Assessment failed: {e}")
            return 1


def create_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser.
    
    Returns:
        Configured ArgumentParser
    """
    parser = argparse.ArgumentParser(
        prog='netwatch',
        description='NetWatch - Network EOL Scanner & Security Assessment Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          Launch interactive menu
  %(prog)s --target 192.168.1.0/24  Scan local network
  %(prog)s --target 10.0.0.1 --profile FULL  Full scan of single host
  %(prog)s --target 192.168.1.1 --nse  Enhanced scan with NSE scripts
  %(prog)s --version                Show version
  %(prog)s --verbose                Enable debug logging
        """
    )
    
    parser.add_argument(
        '--target',
        metavar='TARGET',
        help='Target to scan (IP, CIDR, or hostname). Skips menu and scans directly.'
    )
    
    parser.add_argument(
        '--profile',
        choices=['QUICK', 'FULL', 'STEALTH', 'PING', 'IOT', 'SMB'],
        default='QUICK',
        help='Scan profile: QUICK, FULL, STEALTH, PING, IOT, SMB (default: QUICK)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose/debug logging'
    )
    
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    
    parser.add_argument(
        '--nse',
        action='store_true',
        help='Enable NSE (Nmap Scripting Engine) enhanced detection'
    )
    
    parser.add_argument(
        '--check-defaults',
        action='store_true',
        help='Check for default passwords (use with caution, only on your own devices)'
    )
    
    parser.add_argument(
        '-i', '--interactive',
        action='store_true',
        help='Launch interactive mode for guided scanning'
    )
    
    parser.add_argument(
        '--full-assessment',
        action='store_true',
        help='Run complete assessment: discovery, port scan, banners, EOL, auth tests, auto-export to HTML'
    )

    parser.add_argument(
        '--setup',
        action='store_true',
        help='First-time setup: install dependencies, download CVE and EOL data caches'
    )

    parser.add_argument(
        '--update-cache',
        action='store_true',
        help='Manually refresh CVE and EOL caches (run weekly for best results)'
    )

    parser.add_argument(
        '--save-baseline',
        action='store_true',
        help='Save current scan results as the known-good device baseline for rogue detection'
    )

    parser.add_argument(
        '--cache-status',
        action='store_true',
        help='Show current cache status (age, entries) and exit'
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {Settings().version}'
    )

    parser.add_argument(
        '--check-version',
        action='store_true',
        help='Check for a newer NetWatch release on GitHub and exit'
    )

    parser.add_argument(
        '--update',
        action='store_true',
        help='Pull latest NetWatch code from GitHub and reinstall requirements'
    )

    parser.add_argument(
        '--history',
        action='store_true',
        help='Show scan history table and exit'
    )

    parser.add_argument(
        '--diff',
        action='store_true',
        help='Diff the last two saved scans and exit (combine with --since to compare older)'
    )

    parser.add_argument(
        '--since',
        metavar='DAYS',
        type=int,
        default=None,
        help='With --diff: compare latest scan against oldest scan at least N days ago'
    )

    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress progress bars and informational output (findings still shown)'
    )

    parser.add_argument(
        '--db',
        choices=['mini', 'normal', 'large'],
        default='normal',
        metavar='SIZE',
        help='EOL database size for --setup: mini (~25 products), normal (~55), large (~90). Default: normal'
    )

    parser.add_argument(
        '--modules',
        action='store_true',
        help='Show status of all downloadable data modules and exit'
    )

    parser.add_argument(
        '--download',
        metavar='MODULE',
        default=None,
        help='Download a data module (e.g. credentials-full, snmp-community, or "all")'
    )

    return parser


def _check_insecure_protocols(host: str, open_ports: list) -> list:
    """Return findings for inherently insecure protocols on open ports."""
    findings = []
    INSECURE_PORTS = {
        23: (
            Severity.HIGH,
            "Telnet service open — unencrypted remote access",
            "Telnet transmits all data including usernames and passwords in plain text. "
            "Anyone on the same network can capture your login credentials.",
            "Disable Telnet on this device. Use SSH instead (port 22) for remote access. "
            "Log into the device admin panel and disable Telnet in the service settings.",
            "telnet",
        ),
        21: (
            Severity.HIGH,
            "FTP service open — unencrypted file transfer",
            "FTP transfers files and credentials without any encryption. "
            "Passwords and file contents can be intercepted by anyone on the network.",
            "Disable FTP if not needed. If file transfer is required, use SFTP (over SSH) "
            "or FTPS (FTP with TLS) instead. Check device settings to disable plain FTP.",
            "ftp",
        ),
        69: (
            Severity.MEDIUM,
            "TFTP service open — unauthenticated file transfer",
            "TFTP (Trivial FTP) has no authentication and no encryption. "
            "Anyone can read or write files if they know the filename.",
            "Disable TFTP unless it is specifically required (e.g. for PXE booting). "
            "Restrict access with firewall rules if it must remain active.",
            "tftp",
        ),
        161: (
            Severity.MEDIUM,
            "SNMP service open — check for default community strings",
            "SNMP v1 and v2c use unencrypted 'community strings' (passwords sent in cleartext). "
            "Default community strings like 'public' and 'private' are widely known.",
            "1. Disable SNMP if not needed for network monitoring.\n"
            "2. If needed, upgrade to SNMPv3 which supports encryption and authentication.\n"
            "3. Change community strings from default 'public'/'private' values.",
            "snmp",
        ),
        512: (
            Severity.HIGH,
            "rexec service open — unencrypted remote execution",
            "rexec (remote execution) transmits credentials in plain text and has no "
            "modern security. It is obsolete and should not be running.",
            "Disable rexec immediately. Use SSH for secure remote command execution.",
            "rexec",
        ),
        513: (
            Severity.HIGH,
            "rlogin service open — unencrypted remote login",
            "rlogin is an obsolete remote login protocol with no encryption.",
            "Disable rlogin. Use SSH (port 22) for remote access.",
            "rlogin",
        ),
        514: (
            Severity.HIGH,
            "rsh service open — unencrypted remote shell",
            "rsh (remote shell) transmits all data including commands in plain text.",
            "Disable rsh. Use SSH for secure remote shell access.",
            "rsh",
        ),
    }

    for port in open_ports:
        if port in INSECURE_PORTS:
            sev, title, explanation, recommendation, tag = INSECURE_PORTS[port]
            findings.append(Finding(
                severity=sev,
                title=title,
                host=host,
                port=port,
                protocol="tcp",
                category="Insecure Protocols",
                description=f"Port {port} is open and running an insecure protocol.",
                explanation=explanation,
                recommendation=recommendation,
                evidence=f"Port {port} open on {host}",
                tags=["insecure-protocol", tag],
            ))
    return findings


def run_setup_wizard(db_size: str = "normal") -> int:
    """Run the first-time setup wizard.

    Downloads EOL and CVE caches, checks system dependencies.
    Shows progress bars throughout. Safe to run offline (skips network steps).

    Args:
        db_size: "mini", "normal", or "large" — controls which product list is downloaded.
    """
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    import subprocess

    console = Console()
    console.print("\n[bold blue]NetWatch Setup Wizard[/bold blue]")
    console.print("=" * 60)
    console.print("This will prepare NetWatch for first use.\n")

    # ---- Step 1: Check system dependencies ----
    console.print("[bold]Step 1/6: Checking system dependencies[/bold]")
    all_ok = True

    py_version = sys.version_info
    if py_version >= (3, 9):
        console.print(f"  [green]✓[/green] Python {py_version.major}.{py_version.minor}.{py_version.micro}")
    else:
        console.print(f"  [red]✗[/red] Python 3.9+ required (found {py_version.major}.{py_version.minor})")
        all_ok = False

    for tool, cmd in [("nmap", ["nmap", "--version"]), ("git", ["git", "--version"])]:
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=5)
            if result.returncode == 0:
                version_line = result.stdout.decode("utf-8", errors="ignore").splitlines()[0][:60]
                console.print(f"  [green]✓[/green] {tool}: {version_line}")
            else:
                console.print(f"  [yellow]![/yellow] {tool}: found but returned non-zero")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            console.print(f"  [red]✗[/red] {tool}: not found — install {tool} and re-run setup")
            if tool == "nmap":
                all_ok = False  # nmap is required; git is only for optional GHSA

    # Check optional masscan (faster port discovery)
    try:
        result = subprocess.run(["masscan", "--version"], capture_output=True, timeout=5)
        version_line = result.stdout.decode("utf-8", errors="ignore").splitlines()[0][:60]
        console.print(f"  [green]✓[/green] masscan: {version_line} (faster port discovery enabled)")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        console.print(
            "  [dim]  masscan: not installed (optional) — "
            "install for faster scanning: sudo apt install masscan[/dim]"
        )

    if not all_ok:
        console.print("\n[red]Critical dependencies missing. Fix the above and re-run --setup.[/red]")
        return 1

    # ---- Step 2: Install Python packages ----
    console.print("\n[bold]Step 2/6: Installing Python packages[/bold]")
    req_path = Path(__file__).parent / "requirements.txt"
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", str(req_path), "--quiet"],
            capture_output=False,
            timeout=120,
        )
        if result.returncode == 0:
            console.print("  [green]✓[/green] All packages installed")
        else:
            console.print("  [yellow]![/yellow] pip returned non-zero — check output above")
    except subprocess.TimeoutExpired:
        console.print("  [yellow]![/yellow] pip install timed out")
    except Exception as e:
        console.print(f"  [yellow]![/yellow] pip install error: {e}")

    # ---- Check connectivity ----
    cache = UnifiedCacheManager()
    online = cache.check_online()
    if not online:
        console.print("\n[yellow]Warning: No internet connection detected.[/yellow]")
        console.print("  Cache download steps will be skipped.")
        console.print("  Run --setup again when online to complete setup.\n")
        console.print("[yellow]Partial setup complete.[/yellow]")
        return 0

    # ---- Step 3: Download EOL cache ----
    console.print(f"\n[bold]Step 3/6: Downloading EOL data[/bold] [dim](db={db_size})[/dim]")
    try:
        import requests as req_lib
        from eol.product_map import NOT_TRACKED_PRODUCTS

        # Load product list from JSON file based on --db flag
        list_file = Path(__file__).parent / "data" / "cache" / f"product_list_{db_size}.json"
        if list_file.exists():
            with open(list_file, "r", encoding="utf-8") as f:
                list_data = json.load(f)
            products = [p for p in list_data.get("products", []) if p not in NOT_TRACKED_PRODUCTS]
        else:
            # Fallback: derive from PRODUCT_MAP
            from eol.product_map import PRODUCT_MAP
            products = list(set(v for v in PRODUCT_MAP.values() if v not in NOT_TRACKED_PRODUCTS))

        session = req_lib.Session()
        session.headers.update({"User-Agent": "NetWatch/1.2.0"})
        eol_ok = 0
        eol_fail = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            task = progress.add_task("Downloading EOL data", total=len(products))
            for product in products:
                try:
                    url = f"https://endoflife.date/api/{product}.json"
                    resp = session.get(url, timeout=15)
                    if resp.status_code == 200:
                        cache.set_eol(product, resp.json())
                        eol_ok += 1
                    else:
                        eol_fail += 1
                except Exception:
                    eol_fail += 1
                progress.advance(task)

        cache.mark_eol_updated()
        console.print(f"  [green]✓[/green] EOL data: {eol_ok} products cached, {eol_fail} not found")
    except ImportError:
        console.print("  [yellow]![/yellow] requests not installed — skip EOL download")
    except Exception as e:
        console.print(f"  [yellow]![/yellow] EOL download error: {e}")

    # ---- Step 4: Download CVE cache (common product defaults) ----
    console.print("\n[bold]Step 4/6: Downloading CVE data[/bold]")
    console.print("  [dim]Note: GitHub Advisory Database clone is skipped (too large).[/dim]")
    console.print("  [dim]Using OSV.dev API (no key required, no rate limits).[/dim]")
    try:
        # Pre-populate with a curated set of commonly seen product+version pairs
        # These represent versions still commonly found on network devices in the wild
        DEFAULT_PAIRS = [
            ("openssh", "7.4"), ("openssh", "7.6"), ("openssh", "7.9"),
            ("openssh", "8.0"), ("openssh", "8.2"), ("openssh", "8.4"),
            ("openssh", "8.9"), ("openssh", "9.0"), ("openssh", "9.3"),
            ("nginx", "1.14.0"), ("nginx", "1.16.0"), ("nginx", "1.18.0"),
            ("nginx", "1.20.0"), ("nginx", "1.22.0"), ("nginx", "1.24.0"),
            ("apache-http-server", "2.4.29"), ("apache-http-server", "2.4.38"),
            ("apache-http-server", "2.4.41"), ("apache-http-server", "2.4.46"),
            ("apache-http-server", "2.4.49"), ("apache-http-server", "2.4.51"),
            ("apache-http-server", "2.4.54"), ("apache-http-server", "2.4.57"),
            ("openssl", "1.0.1"), ("openssl", "1.0.2"), ("openssl", "1.1.0"),
            ("openssl", "1.1.1"), ("openssl", "3.0.0"), ("openssl", "3.1.0"),
            ("samba", "4.10.0"), ("samba", "4.12.0"), ("samba", "4.14.0"),
            ("samba", "4.16.0"), ("samba", "4.18.0"),
            ("vsftpd", "2.3.4"), ("vsftpd", "3.0.3"), ("vsftpd", "3.0.5"),
            ("mysql", "5.5"), ("mysql", "5.6"), ("mysql", "5.7"), ("mysql", "8.0"),
            ("php", "7.2"), ("php", "7.3"), ("php", "7.4"), ("php", "8.0"),
            ("php", "8.1"), ("php", "8.2"),
            ("redis", "5.0"), ("redis", "6.0"), ("redis", "6.2"), ("redis", "7.0"),
            ("postfix", "3.4"), ("postfix", "3.5"), ("postfix", "3.6"), ("postfix", "3.7"),
            ("dropbear", "2016.74"), ("dropbear", "2017.75"), ("dropbear", "2019.78"),
            ("dropbear", "2020.81"), ("dropbear", "2022.83"),
        ]

        builder = CVECacheBuilder(cache)
        total_cves = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            task = progress.add_task("Downloading CVE data", total=len(DEFAULT_PAIRS))

            def cb(current, total_items, msg):
                progress.update(task, completed=current, description=f"[cyan]{msg}")

            total_cves = builder.build_cache(DEFAULT_PAIRS, progress_callback=cb)
            progress.update(task, completed=len(DEFAULT_PAIRS))

        console.print(f"  [green]✓[/green] CVE data: {len(DEFAULT_PAIRS)} product:version pairs cached, {total_cves} vulnerabilities")
    except Exception as e:
        console.print(f"  [yellow]![/yellow] CVE download error: {e}")

    # ---- Step 5: Download default modules (credentials-mini, wappalyzer-mini) ----
    console.print("\n[bold]Step 5/6: Downloading default data modules[/bold]")
    try:
        mm = ModuleManager()
        for mod_name in ("credentials-mini", "wappalyzer-mini"):
            ok = mm.download(mod_name, quiet=False)
            if ok:
                console.print(f"  [green]✓[/green] {mod_name}")
            else:
                console.print(f"  [yellow]![/yellow] {mod_name}: download failed (will use built-in fallback)")
    except Exception as e:
        console.print(f"  [yellow]![/yellow] Module download error: {e}")

    # ---- Step 6: Show optional modules ----
    console.print("\n[bold]Step 6/6: Optional modules available[/bold]")
    optional_modules = [
        (name, info) for name, info in MODULE_REGISTRY.items()
        if not info["default"]
    ]
    for name, info in optional_modules:
        console.print(f"  [dim]  {name:<24} {info['size_estimate']:>6}  {info['description']}[/dim]")
    console.print("  Run: [bold]python3 netwatch.py --modules[/bold] to see all options")
    console.print("  Run: [bold]python3 netwatch.py --download all[/bold] for full coverage")

    # ---- Done ----
    console.print("\n" + "=" * 60)
    console.print("[bold green]Setup complete.[/bold green]")
    status = cache.get_cache_status()
    console.print(f"  EOL data:       {status['eol_cache_entries']} products cached")
    console.print(f"  CVE data:       {status['cve_cache_entries']} product:version pairs cached")

    # Show module summary
    mm = ModuleManager()
    cred_status = "installed" if mm.is_installed("credentials-mini") else "not installed"
    wapp_status = "installed" if mm.is_installed("wappalyzer-mini") else "not installed"
    console.print(f"  Credentials:    {cred_status}")
    console.print(f"  Wappalyzer:     {wapp_status}")
    console.print(f"  Cache dir:      {status['cache_dir']}")

    console.print("\n  Optional modules available:")
    console.print("  Run: [bold]python3 netwatch.py --modules[/bold] to see all options")
    console.print("  Run: [bold]python3 netwatch.py --download all[/bold] for full coverage")

    console.print("\nNetWatch is ready. Run:")
    console.print("  [bold]python netwatch.py -i[/bold]           (interactive mode)")
    console.print("  [bold]python netwatch.py --target 192.168.1.0/24[/bold]  (direct scan)")
    return 0


def run_update_cache() -> int:
    """Refresh CVE and EOL caches if they are stale."""
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

    console = Console()
    console.print("\n[bold blue]NetWatch Cache Update[/bold blue]")
    console.print("=" * 50)

    cache = UnifiedCacheManager()

    if not cache.check_online():
        console.print("[yellow]No internet connection. Cannot update caches.[/yellow]")
        console.print("Cached data will be used for scans (may be outdated).")
        return 1

    eol_updated = False
    cve_updated = False

    # ---- EOL cache ----
    if cache.is_eol_cache_current():
        age = cache.get_eol_cache_age_days()
        console.print(f"[green]EOL cache is current ({age} days old). Skipping.[/green]")
    else:
        console.print("[cyan]Refreshing EOL data...[/cyan]")
        try:
            import requests as req_lib
            from eol.product_map import PRODUCT_MAP
            session = req_lib.Session()
            session.headers.update({"User-Agent": "NetWatch/1.1.0"})
            products = list(set(PRODUCT_MAP.values()))
            eol_ok = 0

            with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), BarColumn()) as progress:
                task = progress.add_task("EOL data", total=len(products))
                for product in products:
                    try:
                        resp = session.get(f"https://endoflife.date/api/{product}.json", timeout=15)
                        if resp.status_code == 200:
                            cache.set_eol(product, resp.json())
                            eol_ok += 1
                    except Exception:
                        pass
                    progress.advance(task)

            cache.mark_eol_updated()
            console.print(f"  [green]✓[/green] EOL: {eol_ok} products refreshed")
            eol_updated = True
        except Exception as e:
            console.print(f"  [yellow]![/yellow] EOL update failed: {e}")

    # ---- CVE cache ----
    if cache.is_cve_cache_current():
        age = cache.get_cve_cache_age_days()
        console.print(f"[green]CVE cache is current ({age} days old). Skipping.[/green]")
    else:
        console.print("[cyan]Refreshing CVE data...[/cyan]")
        try:
            # Collect all product:version pairs currently in cache and re-query them
            existing_pairs = []
            for key in cache.cve_data.keys():
                if ":" in key:
                    product, version = key.split(":", 1)
                    existing_pairs.append((product, version))

            if existing_pairs:
                builder = CVECacheBuilder(cache)
                with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), BarColumn()) as progress:
                    task = progress.add_task("CVE data", total=len(existing_pairs))

                    def cb(current, total_items, msg):
                        progress.update(task, completed=current)

                    count = builder.build_cache(existing_pairs, progress_callback=cb)
                    progress.update(task, completed=len(existing_pairs))

                console.print(f"  [green]✓[/green] CVE: {len(existing_pairs)} pairs refreshed, {count} vulnerabilities")
                cve_updated = True
            else:
                console.print("  [dim]No existing CVE cache entries to refresh. Run --setup first.[/dim]")
        except Exception as e:
            console.print(f"  [yellow]![/yellow] CVE update failed: {e}")

    # ---- Refresh expired modules ----
    console.print("\n[cyan]Checking installed modules...[/cyan]")
    try:
        mm = ModuleManager()
        results = mm.refresh_expired(quiet=False)
        if not results:
            console.print("  [dim]No modules installed yet. Run --download <module> to install.[/dim]")
    except Exception as e:
        console.print(f"  [yellow]![/yellow] Module refresh error: {e}")

    console.print("\n[green]All modules up to date.[/green]")
    status = cache.get_cache_status()
    console.print(f"  EOL:  {status['eol_cache_entries']} products | age: {status['eol_cache_age_days']} days")
    console.print(f"  CVE:  {status['cve_cache_entries']} pairs    | age: {status['cve_cache_age_days']} days")
    return 0


def show_cache_status() -> int:
    """Print cache status and exit."""
    from rich.console import Console
    from rich.table import Table
    console = Console()
    cache = UnifiedCacheManager()
    status = cache.get_cache_status()

    table = Table(title="NetWatch Cache Status", show_header=True)
    table.add_column("Dataset", style="bold")
    table.add_column("Entries")
    table.add_column("Age (days)")
    table.add_column("Status")

    def status_str(current: bool) -> str:
        return "[green]Current[/green]" if current else "[yellow]Stale — run --update-cache[/yellow]"

    table.add_row(
        "EOL Data",
        str(status["eol_cache_entries"]),
        str(status["eol_cache_age_days"] or "never"),
        status_str(status["eol_cache_current"]),
    )
    table.add_row(
        "CVE Data",
        str(status["cve_cache_entries"]),
        str(status["cve_cache_age_days"] or "never"),
        status_str(status["cve_cache_current"]),
    )
    console.print(table)
    console.print(f"Cache directory: {status['cache_dir']}")
    return 0


def main() -> int:
    """Main entry point.

    Returns:
        Exit code
    """
    parser = create_parser()
    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)

    # --- Handle standalone utility commands (no scan needed) ---
    if args.setup:
        return run_setup_wizard(db_size=getattr(args, 'db', 'normal'))

    if args.check_version:
        mgr = UpdateManager()
        mgr.check_version()
        return 0

    if args.update:
        mgr = UpdateManager()
        return mgr.update_tool()

    if args.update_cache:
        return run_update_cache()

    if args.modules:
        mm = ModuleManager()
        mm.show_modules()
        return 0

    if args.download:
        mm = ModuleManager()
        if args.download.lower() == "all":
            count = mm.download_all()
            print(f"\n{count} modules downloaded.")
        else:
            success = mm.download(args.download)
            if not success:
                return 1
        return 0

    if args.cache_status:
        mgr = UpdateManager()
        mgr.show_cache_status()
        return show_cache_status()

    if args.history:
        history = ScanHistory()
        rows = history.history_table()
        if not rows:
            print("No scan history found. Run a scan first.")
            return 0
        print(f"\n{'Timestamp':<18} {'Target':<22} {'Profile':<8} {'Hosts':<6} {'C':>4} {'H':>4} {'M':>4} {'L':>4}")
        print("-" * 75)
        for r in rows:
            print(f"{r['timestamp']:<18} {r['target']:<22} {r['profile']:<8} "
                  f"{r['hosts']:<6} {r['critical']:>4} {r['high']:>4} "
                  f"{r['medium']:>4} {r['low']:>4}")
        return 0

    if args.diff:
        history = ScanHistory()
        since_days = getattr(args, 'since', None)
        diff = history.diff_since_days(since_days) if since_days else history.diff_last_two()
        if diff is None:
            print("Not enough scan history for a diff. Run at least two scans first.")
            return 0
        print(f"\nDiff: {diff.older_ts[:19]}  ->  {diff.newer_ts[:19]}")
        print("-" * 60)
        for line in diff.summary_lines():
            print(f"  {line}")
        return 0

    # Check for interactive mode
    if args.interactive:
        from ui.interactive_controller import InteractiveController
        controller = InteractiveController()
        return controller.run()
    
    # Check for full assessment mode
    if args.full_assessment:
        if not args.target:
            print("Error: --full-assessment requires a target. Use --target to specify.")
            print("Example: python netwatch.py --full-assessment --target 192.168.1.0/24")
            return 1
        
        # Auto-enable NSE and auth testing for full assessment
        if not args.nse:
            print("[INFO] Auto-enabling NSE scripts for full assessment")
            args.nse = True
        if not args.check_defaults:
            print("[INFO] Auto-enabling default credential testing for full assessment")
            print("[WARNING] Only test devices you own!")
            args.check_defaults = True
        
        # Run full assessment
        app = NetWatch(args)
        return app.run_full_assessment(args.target)
    
    # Check if target was provided for direct scan
    if args.target:
        app = NetWatch(args)
        return app.direct_scan(args.target, args.profile)
    
    # Run standard application (interactive menu)
    app = NetWatch(args)
    return app.run()


if __name__ == '__main__':
    sys.exit(main())
