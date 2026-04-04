"""
NetWatch Display Module.

This module provides rich terminal output including formatted tables,
banners, progress bars, and color-coded results using the Rich library.

Exports:
    Display: Main class for all terminal output formatting

Example:
    from ui.display import Display
    display = Display()
    
    # Show results table
    display.show_results_table(hosts_data)
    
    # Show summary panel
    display.show_summary(stats)
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.text import Text
from rich.style import Style
from rich.box import Box, ROUNDED

from config.settings import Settings, EOL_STATUS, TABLE_MIN_WIDTH
from core.scanner import ScanResult, HostInfo, PortInfo
from eol.checker import EOLStatus, EOLStatusLevel

logger = logging.getLogger(__name__)


class Display:
    """Rich terminal display handler for NetWatch.
    
    Provides formatted output for scan results, tables, progress bars,
    and summary information with color-coded status indicators.
    
    Attributes:
        console: Rich Console instance
        settings: Application settings
        use_color: Whether to use colored output
        
    Example:
        display = Display()
        
        # Show scan results
        display.show_results_table(scan_result)
        
        # Show EOL summary
        display.show_eol_summary(eol_results)
    """
    
    # Status color mapping
    STATUS_COLORS = {
        EOLStatusLevel.CRITICAL: "red",
        EOLStatusLevel.WARNING: "yellow",
        EOLStatusLevel.OK: "green",
        EOLStatusLevel.UNKNOWN: "dim",
    }
    
    def __init__(
        self, 
        settings: Optional[Settings] = None,
        console: Optional[Console] = None,
        use_color: bool = True
    ):
        """Initialize the display handler.
        
        Args:
            settings: Configuration settings
            console: Rich Console instance
            use_color: Whether to enable colored output
        """
        self.settings = settings or Settings()
        self.use_color = use_color
        
        if console:
            self.console = console
        else:
            # Configure console with color setting
            self.console = Console(
                color_system="auto" if use_color else None,
                width=min(TABLE_MIN_WIDTH, 200)
            )
    
    def show_banner(self) -> None:
        """Display the application banner."""
        import sys
        # Use simple ASCII banner to avoid Unicode issues on Windows
        print(f"\n{'='*70}")
        print(f"  NetWatch - Network EOL Scanner v{self.settings.version}")
        print(f"{'='*70}\n")
        print(f"Current time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        sys.stdout.flush()
    
    def create_progress(self) -> Progress:
        """Create a Rich Progress instance for scan tracking.
        
        Returns:
            Progress instance with configured columns
        """
        return Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(complete_style="cyan", finished_style="green"),
            TaskProgressColumn(),
            console=self.console,
            disable=True,  # Disable progress bars on Windows to avoid Unicode issues
        )
    
    def show_results_table(
        self, 
        scan_result: ScanResult,
        eol_data: Optional[Dict[str, Dict[int, Any]]] = None
    ) -> None:
        """Display scan results in a formatted table.
        
        Args:
            scan_result: Results from network scan
            eol_data: Optional EOL status data per host/port
        """
        if not scan_result.hosts:
            self.console.print("[yellow]No hosts discovered.[/yellow]")
            return
        
        # Create main table
        table = Table(
            title=f"Scan Results: {scan_result.target}",
            box=ROUNDED,
            header_style="bold cyan" if self.use_color else "bold",
            show_header=True,
            width=TABLE_MIN_WIDTH,
        )
        
        # Define columns
        table.add_column("IP Address", style="dim", width=15)
        table.add_column("Hostname", width=15)
        table.add_column("Port", justify="right", width=5)
        table.add_column("Service", width=18)
        table.add_column("Version", width=25)
        table.add_column("EOL Status", width=10)
        table.add_column("EOL Date", width=11)
        table.add_column("Days", justify="right", width=6)
        
        # Populate table
        for ip, host in scan_result.hosts.items():
            if not host.ports:
                # Host up but no open ports
                table.add_row(
                    ip,
                    host.hostname or "—",
                    "—",
                    "—",
                    "—",
                    "—",
                    "—",
                    "—",
                )
                continue
            
            for port_num, port in sorted(host.ports.items()):
                # Get EOL data if available
                eol_status = None
                if eol_data and ip in eol_data and port_num in eol_data[ip]:
                    eol_status = eol_data[ip][port_num]
                
                # Format EOL info
                if eol_status:
                    status_str = eol_status.level.value
                    status_style = self.STATUS_COLORS.get(eol_status.level, "white")
                    
                    eol_date = (eol_status.eol_date.strftime("%Y-%m-%d") 
                               if eol_status.eol_date else "-")
                    days_str = str(eol_status.days_remaining) if eol_status.days_remaining is not None else "-"
                else:
                    status_str = "-"
                    status_style = "dim"
                    eol_date = "-"
                    days_str = "-"
                
                # Format service info - prioritize HTTP fingerprint data
                service_str = port.service or "-"
                version_str = port.version or "-"
                
                # If we have HTTP fingerprint data, format it nicely
                if port.http_fingerprint:
                    fp = port.http_fingerprint
                    if fp.device_type and fp.model:
                        service_str = f"{fp.device_type} {fp.model}"
                    elif fp.device_type:
                        service_str = fp.device_type
                    
                    # Build version string with firmware and hardware info
                    version_parts = []
                    if fp.firmware_version:
                        version_parts.append(f"FW:{fp.firmware_version}")
                    if fp.hardware_version:
                        hw = fp.hardware_version[:15]  # Truncate long HW versions
                        version_parts.append(f"HW:{hw}")
                    if version_parts:
                        version_str = " ".join(version_parts)
                
                # Add row with color coding
                row = [
                    ip,
                    host.hostname or "-",
                    str(port.port),
                    service_str[:17],
                    version_str[:24],
                    status_str,
                    eol_date,
                    days_str,
                ]
                
                if self.use_color:
                    table.add_row(*row, style=status_style)
                else:
                    table.add_row(*row)
        
        self.console.print(table)
    
    def show_eol_table(self, eol_results: List[EOLStatus]) -> None:
        """Display EOL check results in a formatted table.
        
        Args:
            eol_results: List of EOL status results
        """
        if not eol_results:
            self.console.print("[yellow]No EOL data available.[/yellow]")
            return
        
        table = Table(
            title="End-of-Life Status",
            box=ROUNDED,
            header_style="bold cyan" if self.use_color else "bold",
            width=TABLE_MIN_WIDTH,
        )
        
        table.add_column("Product", width=20)
        table.add_column("Version", width=12)
        table.add_column("Status", width=12)
        table.add_column("EOL Date", width=12)
        table.add_column("Days", justify="right", width=10)
        table.add_column("Message", width=40)
        
        for result in eol_results:
            status_color = self.STATUS_COLORS.get(result.level, "white")
            
            eol_date = (result.eol_date.strftime("%Y-%m-%d") 
                       if result.eol_date else "—")
            days_str = str(result.days_remaining) if result.days_remaining is not None else "—"
            
            row = [
                result.product,
                result.version,
                result.level.value,
                eol_date,
                days_str,
                result.message[:38] + "..." if len(result.message) > 40 else result.message,
            ]
            
            if self.use_color:
                table.add_row(*row, style=status_color)
            else:
                table.add_row(*row)
        
        self.console.print(table)
    
    def show_summary(self, stats: Dict[str, int]) -> None:
        """Display scan summary panel.
        
        Args:
            stats: Dictionary with summary statistics
                - total_hosts: Total hosts scanned
                - hosts_up: Hosts that responded
                - critical: Count of CRITICAL EOL status
                - warning: Count of WARNING EOL status
                - ok: Count of OK EOL status
                - unknown: Count of UNKNOWN EOL status
        """
        # Calculate totals
        total = stats.get('total_hosts', 0)
        critical = stats.get('critical', 0)
        warning = stats.get('warning', 0)
        ok = stats.get('ok', 0)
        unknown = stats.get('unknown', 0)
        
        # Create summary text
        summary_text = Text()
        summary_text.append(f"Total Hosts Scanned: {total}\n\n")
        
        if self.use_color:
            summary_text.append(f"CRITICAL: {critical}\n", style="bold red")
            summary_text.append(f"WARNING:  {warning}\n", style="bold yellow")
            summary_text.append(f"OK:       {ok}\n", style="bold green")
            summary_text.append(f"UNKNOWN:  {unknown}\n", style="dim")
        else:
            summary_text.append(f"CRITICAL: {critical}\n")
            summary_text.append(f"WARNING:  {warning}\n")
            summary_text.append(f"OK:       {ok}\n")
            summary_text.append(f"UNKNOWN:  {unknown}\n")
        
        # Device identification stats
        devices_id = stats.get('devices_identified', 0)
        devices_total = stats.get('devices_total', 0)
        device_types = stats.get('device_types', {})
        if devices_id > 0:
            type_parts = [f"{v} {k}" for k, v in device_types.items()]
            summary_text.append(
                f"\nDevices identified: {devices_id}/{devices_total}"
            )
            if type_parts:
                summary_text.append(f" ({', '.join(type_parts)})")
            summary_text.append("\n")

        # Add recommendations
        if critical > 0:
            summary_text.append(f"\n⚠ {critical} services have reached EOL and should be updated immediately!", 
                              style="red" if self.use_color else None)
        if warning > 0:
            summary_text.append(f"\n⚠ {warning} services approaching EOL - plan updates soon.",
                              style="yellow" if self.use_color else None)
        
        panel = Panel(
            summary_text,
            title="Summary",
            border_style="blue",
            padding=(1, 2),
        )
        
        self.console.print(panel)
    
    def show_host_details(self, host: HostInfo) -> None:
        """Display detailed information about a single host.
        
        Args:
            host: Host information
        """
        text = Text()
        text.append(f"Host: {host.ip}\n", style="bold cyan")
        text.append(f"  Hostname: {host.hostname or 'Unknown'}\n")
        text.append(f"  State: {host.state}\n")
        text.append(f"  OS Guess: {host.os_guess or 'Unknown'}\n")
        text.append(f"  MAC: {host.mac or 'Unknown'}\n")
        text.append(f"  Vendor: {host.vendor or 'Unknown'}\n")
        text.append(f"  Open Ports: {len(host.ports)}\n")
        
        if host.ports:
            text.append("\n  Services:\n")
            for port_num, port in sorted(host.ports.items()):
                text.append(f"    {port.port}/{port.protocol}: ")
                text.append(f"{port.service}", style="yellow")
                if port.version:
                    text.append(f" ({port.version})")
                text.append("\n")
        
        self.console.print(Panel(text, border_style="blue"))
    
    def show_scan_info(self, scan_result: ScanResult) -> None:
        """Display scan metadata.
        
        Args:
            scan_result: Scan results
        """
        info_text = f"""
Target:     {scan_result.target}
Profile:    {scan_result.profile}
Started:    {scan_result.start_time.strftime('%Y-%m-%d %H:%M:%S')}
Completed:  {scan_result.end_time.strftime('%Y-%m-%d %H:%M:%S') if scan_result.end_time else 'In progress'}
Duration:   {scan_result.duration:.2f} seconds
Hosts:      {len(scan_result.hosts)}
        """
        
        self.console.print(Panel(info_text, title="Scan Information", border_style="dim"))
    
    def show_error(self, message: str) -> None:
        """Display error message.
        
        Args:
            message: Error message
        """
        print(f"ERROR: {message}")
    
    def show_warning(self, message: str) -> None:
        """Display warning message.
        
        Args:
            message: Warning message
        """
        print(f"WARNING: {message}")
    
    def show_success(self, message: str) -> None:
        """Display success message.
        
        Args:
            message: Success message
        """
        print(f"SUCCESS: {message}")
    
    def show_info(self, message: str) -> None:
        """Display info message.
        
        Args:
            message: Info message
        """
        print(f"INFO: {message}")
    
    def show_device_inventory(
        self,
        device_identities: Dict[str, Any],
        eol_data: Optional[Dict[str, Dict[int, Any]]] = None,
    ) -> None:
        """Display device identification results in a Rich table.

        Args:
            device_identities: {ip: DeviceIdentity} dict
            eol_data: Optional {ip: {port: EOLStatus}} for firmware EOL column
        """
        if not device_identities:
            self.console.print("[yellow]No devices identified.[/yellow]")
            return

        table = Table(
            title="Device Identification",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("IP", style="dim", width=17)
        table.add_column("Type", width=18)
        table.add_column("Vendor", width=14)
        table.add_column("Model", width=20)
        table.add_column("Version", width=12)
        table.add_column("Conf.", justify="right", width=6)
        table.add_column("EOL", width=12)

        eol_data = eol_data or {}

        for ip in sorted(device_identities):
            ident = device_identities[ip]
            pct = int(ident.confidence * 100)
            if pct >= 70:
                conf_str = f"[green]{pct}%[/green]"
            elif pct >= 40:
                conf_str = f"[yellow]{pct}%[/yellow]"
            else:
                conf_str = f"[dim]{pct}%[/dim]"

            # Truncate long model/version strings
            model_str = (ident.model or "—")[:20]
            version_str = (ident.version or "—")[:12]

            # Firmware EOL status (port 0)
            eol_entry = eol_data.get(ip, {}).get(0)
            if eol_entry:
                if eol_entry.level == EOLStatusLevel.CRITICAL:
                    eol_date_str = (
                        eol_entry.eol_date.strftime("%Y-%m-%d")
                        if eol_entry.eol_date else "Yes"
                    )
                    eol_str = f"[red]EOL {eol_date_str}[/red]"
                elif eol_entry.level == EOLStatusLevel.WARNING:
                    eol_str = f"[yellow]Soon ({eol_entry.days_remaining}d)[/yellow]"
                elif eol_entry.level == EOLStatusLevel.OK:
                    eol_str = "[green]OK[/green]"
                else:
                    eol_str = "—"
            else:
                eol_str = "—"

            table.add_row(
                ip,
                ident.device_type or "—",
                ident.vendor or "—",
                model_str,
                version_str,
                conf_str,
                eol_str,
            )

        self.console.print()
        self.console.print(table)

    def clear(self) -> None:
        """Clear the console."""
        self.console.clear()
