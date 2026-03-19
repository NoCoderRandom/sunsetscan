"""
NetWatch Interactive Menu Module.

This module provides an interactive menu system for NetWatch CLI,
allowing users to select scan types, configure options, and navigate
the application through a numbered menu interface.

Exports:
    Menu: Main menu class with interactive prompts

Example:
    from ui.menu import Menu
    menu = Menu()
    choice = menu.show_main_menu()
"""

import logging
import os
import sys
from typing import Optional, Tuple, Callable
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm

from config.settings import Settings, MENU_OPTIONS, SCAN_DESCRIPTIONS, ASCII_BANNER

logger = logging.getLogger(__name__)


class Menu:
    """Interactive menu system for NetWatch.
    
    Provides a user-friendly numbered menu interface for selecting
    scan types, viewing settings, and accessing help.
    
    Attributes:
        console: Rich Console for output
        settings: Application settings
        last_scan_target: Store last scan target for recheck
        last_scan_profile: Store last scan profile for recheck
        
    Example:
        menu = Menu()
        
        # Show main menu
        choice = menu.show_main_menu()
        
        # Get target
        target = menu.prompt_target()
        
        # Confirm scan
        if menu.confirm_scan("FULL", "192.168.1.0/24"):
            # Proceed with scan
    """
    
    def __init__(self, settings: Optional[Settings] = None, console: Optional[Console] = None):
        """Initialize the menu system.
        
        Args:
            settings: Configuration settings
            console: Rich Console instance (creates new if None)
        """
        self.settings = settings or Settings()
        self.console = console or Console()
        self.last_scan_target: Optional[str] = None
        self.last_scan_profile: Optional[str] = None
        
    def clear_screen(self) -> None:
        """Clear the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def show_banner(self) -> None:
        """Display the NetWatch ASCII banner."""
        banner_text = ASCII_BANNER.format(version=self.settings.version)
        try:
            self.console.print(banner_text, style="cyan")
        except UnicodeEncodeError:
            # Fallback for Windows consoles
            self.console.print(f"\n{'='*70}")
            self.console.print(f"  NetWatch - Network EOL Scanner v{self.settings.version}")
            self.console.print(f"{'='*70}\n")
        self.console.print(f"Current time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    def show_main_menu(self) -> str:
        """Display the main menu and get user selection.
        
        Returns:
            String indicating menu choice (1-9)
        """
        self.clear_screen()
        self.show_banner()
        
        # Build menu text
        menu_text = Text()
        menu_text.append("MAIN MENU\n", style="bold cyan underline")
        menu_text.append("=" * 50 + "\n\n")
        
        for num, name, desc in MENU_OPTIONS:
            menu_text.append(f"[{num}] ", style="bold yellow")
            menu_text.append(f"{name:<20}", style="bold white")
            menu_text.append(f" — {desc}\n", style="dim")
        
        self.console.print(Panel(menu_text, border_style="blue"))
        
        # Get user choice
        valid_choices = [opt[0] for opt in MENU_OPTIONS]
        choice = Prompt.ask(
            "Enter your choice",
            choices=valid_choices,
            default="1"
        )
        
        return choice
    
    def prompt_target(self, default: Optional[str] = None) -> str:
        """Prompt user for scan target.
        
        Args:
            default: Default target to suggest
            
        Returns:
            Target string (IP, CIDR, or hostname)
        """
        self.console.print("\n[bold cyan]Target Selection[/bold cyan]")
        self.console.print("Enter target as IP, CIDR (e.g., 192.168.1.0/24), or range")
        
        if default:
            target = Prompt.ask("Target", default=default)
        else:
            target = Prompt.ask("Target")
        
        return target.strip()
    
    def confirm_scan(self, profile: str, target: str) -> bool:
        """Display scan confirmation prompt with details.
        
        Args:
            profile: Scan profile name (QUICK, FULL, STEALTH)
            target: Target being scanned
            
        Returns:
            True if user confirms, False otherwise
        """
        desc = SCAN_DESCRIPTIONS.get(profile, {})
        
        # Build confirmation text
        confirm_text = Text()
        confirm_text.append(f"\n→ Starting {desc.get('name', profile)} on {target}\n\n", 
                           style="bold yellow")
        
        # Features
        features = desc.get('features', [])
        for feature in features:
            confirm_text.append(f"  • {feature}\n", style="dim")
        
        # Warnings and info
        confirm_text.append(f"\n  Estimated time: {desc.get('estimated_time', 'unknown')}\n",
                           style="dim")
        
        if desc.get('requires_root', False):
            confirm_text.append("  ⚠ Requires root/admin privileges\n", style="red")
        
        confirm_text.append("\nPress ENTER to continue or CTRL+C to cancel.",
                           style="bold green")
        
        self.console.print(Panel(confirm_text, border_style="yellow", title="Confirm Scan"))
        
        try:
            input()  # Wait for ENTER
            return True
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Scan cancelled.[/yellow]")
            return False
    
    def show_settings(self) -> None:
        """Display current settings."""
        self.console.print("\n[bold cyan]Current Settings[/bold cyan]")
        
        settings_text = f"""
Tool Name:          {self.settings.tool_name}
Version:            {self.settings.version}
Banner Timeout:     {self.settings.banner_timeout} seconds
Cache TTL:          {self.settings.cache_ttl_hours} hours
Warning Threshold:  {self.settings.warning_days_threshold} days
Max Threads:        {self.settings.max_threads}
Socket Timeout:     {self.settings.socket_connect_timeout} seconds
        """
        
        self.console.print(Panel(settings_text, border_style="blue"))
        
        Prompt.ask("\nPress ENTER to return to menu")
    
    def show_help(self) -> None:
        """Display help information."""
        help_text = """
[bold cyan]NetWatch Help[/bold cyan]

NetWatch discovers every device on your network, fingerprints running
software, checks for known vulnerabilities and end-of-life dates,
and produces a professional HTML security report.

[bold]Scan Profiles:[/bold]
  QUICK    Fast scan of top 100 ports               (no root)
  FULL     OS detection + version + NSE scripts      (root)
  STEALTH  SYN scan with slow timing                 (root)
  PING     Host discovery only — no port scan        (no root)
  IOT      Cameras, routers, smart device ports      (no root)
  SMB      Windows shares + EternalBlue check        (root)

[bold]Target Formats:[/bold]
  192.168.1.1            Single IP
  192.168.1.0/24         CIDR range
  192.168.1.*            Wildcard
  192.168.1.1-100        IP range
  192.168.1.1,5,10       Comma list
  router.local           Hostname

[bold]Security Checks (run during Full Assessment):[/bold]
  SSL/TLS     Expired certs, weak ciphers, self-signed
  SSH         Weak algorithms, SSHv1, small host keys
  SMB         SMBv1, EternalBlue, anonymous shares
  FTP         Anonymous login, cleartext credentials
  SNMP        Default community strings (public/private)
  Web         Missing headers, login over HTTP, admin panels
  DNS         DNS hijacking detection
  UPnP        Port-mapping exposure
  mDNS        Zeroconf device discovery
  ARP         Spoofing detection (root)
  CVE         Known vulnerabilities from OSV.dev
  EOL         End-of-life dates from endoflife.date

[bold]Severity Levels:[/bold]
  [red]CRITICAL[/red]  Immediate risk — act today
  [bold red]HIGH[/bold red]      Significant risk — fix this week
  [yellow]MEDIUM[/yellow]    Notable risk — schedule a fix
  [blue]LOW[/blue]       Minor concern — track and plan
  [dim]INFO[/dim]      Informational — no action needed

[bold]Key CLI Commands:[/bold]
  netwatch --target 192.168.1.0/24                 Quick scan
  netwatch --full-assessment --target 192.168.1.0/24  Full report
  netwatch --target 192.168.1.0/24 --profile IOT   IoT device scan
  netwatch --modules                               Show data modules
  netwatch --download all                          Download all modules
  netwatch --history                               View past scans
  netwatch --diff                                  Compare last two scans
  netwatch -i                                      Interactive mode
        """

        self.console.print(help_text)
        Prompt.ask("\nPress ENTER to return to menu")
    
    def prompt_export_format(self) -> str:
        """Prompt user for export format.
        
        Returns:
            'json' or 'html'
        """
        self.console.print("\n[bold cyan]Export Report[/bold cyan]")
        
        format_choice = Prompt.ask(
            "Select format",
            choices=["json", "html"],
            default="json"
        )
        
        return format_choice
    
    def prompt_filename(self, default: str) -> str:
        """Prompt user for export filename.
        
        Args:
            default: Default filename to suggest
            
        Returns:
            Filename string
        """
        filename = Prompt.ask("Filename", default=default)
        return filename
    
    def show_scan_complete(self, stats: dict) -> None:
        """Display scan completion message.
        
        Args:
            stats: Dictionary with scan statistics
        """
        self.console.print(f"\n[bold green]✓ Scan Complete[/bold green]")
        
        stats_text = f"""
Hosts Scanned:      {stats.get('total_hosts', 0)}
Hosts Up:           {stats.get('hosts_up', 0)}
Open Ports Found:   {stats.get('open_ports', 0)}
Services Identified: {stats.get('services', 0)}
Scan Duration:      {stats.get('duration', 'N/A')}s
        """
        
        self.console.print(Panel(stats_text, border_style="green"))
    
    def show_privilege_warning(self) -> None:
        """Display warning about missing root/admin privileges."""
        print("WARNING: Running without root/admin privileges")
        print("")
        print("Some features may be limited:")
        print("- OS detection may not work")
        print("- Stealth SYN scan unavailable")
        print("- Some ports may not be accessible")
        print("")
        print("For best results, run with: sudo netwatch")
    
    def prompt_yes_no(self, question: str, default: bool = False) -> bool:
        """Prompt user with yes/no question.
        
        Args:
            question: Question to ask
            default: Default answer
            
        Returns:
            True for yes, False for no
        """
        return Confirm.ask(question, default=default)
    
    def show_error(self, message: str) -> None:
        """Display error message.
        
        Args:
            message: Error message to display
        """
        self.console.print(f"\n[bold red]✗ Error: {message}[/bold red]")
    
    def show_info(self, message: str) -> None:
        """Display info message.
        
        Args:
            message: Info message to display
        """
        self.console.print(f"[cyan]ℹ {message}[/cyan]")
    
    def show_success(self, message: str) -> None:
        """Display success message.
        
        Args:
            message: Success message to display
        """
        self.console.print(f"[bold green]✓ {message}[/bold green]")
    
    def show_progress(self, message: str, percentage: float) -> None:
        """Update progress display.
        
        Args:
            message: Progress message
            percentage: Completion percentage (0-100)
        """
        bar_width = 30
        filled = int(bar_width * percentage / 100)
        bar = "█" * filled + "░" * (bar_width - filled)
        
        self.console.print(f"\r[{bar}] {percentage:5.1f}% | {message}", 
                          end="", style="cyan")
        if percentage >= 100:
            self.console.print()  # New line when complete
