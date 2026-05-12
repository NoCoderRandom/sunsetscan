"""
SunsetScan Interactive Menu Module.

Modern terminal UI with arrow-key navigation AND number/letter shortcuts.
Uses raw terminal input (no extra dependencies beyond Rich).

Exports:
    Menu: Main menu class with interactive prompts
"""

import logging
import os
import sys
from typing import List, Optional, Tuple
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm

from config.settings import Settings, MENU_OPTIONS, SCAN_DESCRIPTIONS, ASCII_BANNER

logger = logging.getLogger(__name__)


def _read_key() -> str:
    """Read a single keypress from stdin (blocking).

    Returns a string:
        - "up", "down" for arrow keys
        - "enter" for Enter/Return
        - "q" for q/Q
        - the character itself for printable keys
    """
    def read_line_fallback() -> str:
        try:
            line = input()
        except EOFError:
            return "q"
        return line.strip() if line.strip() else "enter"

    if not sys.stdin.isatty():
        return read_line_fallback()

    try:
        import tty
        import termios
    except ImportError:
        return read_line_fallback()

    try:
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)

            if ch == "\x1b":
                # Escape sequence — read two more chars
                seq = sys.stdin.read(2)
                if seq == "[A":
                    return "up"
                if seq == "[B":
                    return "down"
                return "escape"

            if ch in ("\r", "\n"):
                return "enter"

            if ch == "\x03":
                # Ctrl-C
                raise KeyboardInterrupt

            return ch

        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    except (OSError, termios.error):
        # Fallback for environments without termios (e.g. Windows, piped stdin)
        return read_line_fallback()


def _render_menu(
    options: List[Tuple[str, str, str]],
    selected: int,
    version: str,
) -> Text:
    """Build the menu as a Rich Text object with the selected row highlighted."""

    text = Text()
    text.append("MAIN MENU\n", style="bold cyan underline")
    text.append("Use ", style="dim")
    text.append("[Up/Down]", style="bold dim")
    text.append(" to navigate, ", style="dim")
    text.append("[Enter]", style="bold dim")
    text.append(" to select, or press a ", style="dim")
    text.append("[key]", style="bold dim")
    text.append(" shortcut\n\n", style="dim")

    for idx, (key, name, desc) in enumerate(options):
        if idx == selected:
            # Highlighted row
            text.append(f"  > [{key}] ", style="bold cyan")
            text.append(f"{name:<22}", style="bold white on blue")
            text.append(f" {desc}", style="bold white on blue")
            text.append("\n")
        else:
            text.append(f"    [{key}] ", style="yellow")
            text.append(f"{name:<22}", style="white")
            text.append(f" {desc}", style="dim")
            text.append("\n")

    return text


class Menu:
    """Interactive menu with arrow-key navigation and hotkey shortcuts.

    Attributes:
        console: Rich Console for output
        settings: Application settings
        last_scan_target: Store last scan target for recheck
        last_scan_profile: Store last scan profile for recheck
    """

    def __init__(self, settings: Optional[Settings] = None, console: Optional[Console] = None):
        self.settings = settings or Settings()
        self.console = console or Console()
        self.last_scan_target: Optional[str] = None
        self.last_scan_profile: Optional[str] = None

    def clear_screen(self) -> None:
        """Clear the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')

    def show_banner(self) -> None:
        """Display the SunsetScan ASCII banner."""
        banner_text = ASCII_BANNER.format(version=self.settings.version)
        try:
            self.console.print(banner_text, style="cyan")
        except UnicodeEncodeError:
            self.console.print(f"\n{'=' * 70}")
            self.console.print(f"  SunsetScan - Network EOL Scanner v{self.settings.version}")
            self.console.print(f"{'=' * 70}\n")
        self.console.print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", style="dim")

    def show_main_menu(self) -> str:
        """Display the main menu with arrow-key navigation.

        Returns:
            The shortcut key string of the selected option (e.g. "1", "q", "m").
        """
        self.clear_screen()
        self.show_banner()

        options = list(MENU_OPTIONS)
        key_list = [opt[0] for opt in options]
        selected = 0

        # Build a lookup: key -> index for hotkey jumps
        key_to_idx = {opt[0].lower(): i for i, opt in enumerate(options)}

        while True:
            # Render current state
            menu_text = _render_menu(options, selected, self.settings.version)
            self.console.print(Panel(menu_text, border_style="blue", padding=(0, 1)))

            key = _read_key()

            if key == "up":
                selected = (selected - 1) % len(options)
            elif key == "down":
                selected = (selected + 1) % len(options)
            elif key == "enter":
                return key_list[selected]
            elif key.lower() in key_to_idx:
                # Direct hotkey — select and return immediately
                return key.lower() if key.lower() in key_list else key_list[key_to_idx[key.lower()]]
            elif key == "escape":
                pass  # Ignore bare escape

            # Redraw: move cursor up to overwrite the previous panel
            # Count lines: 3 header + len(options) + 2 panel border + 1 blank
            line_count = len(options) + 6
            sys.stdout.write(f"\033[{line_count}A\033[J")
            sys.stdout.flush()

    # ------------------------------------------------------------------
    # Target / confirmation prompts (unchanged public API)
    # ------------------------------------------------------------------

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
            profile: Scan profile name
            target: Target being scanned

        Returns:
            True if user confirms, False otherwise
        """
        desc = SCAN_DESCRIPTIONS.get(profile, {})

        confirm_text = Text()
        confirm_text.append(f"\n  Starting {desc.get('name', profile)} on {target}\n\n",
                            style="bold yellow")

        for feature in desc.get('features', []):
            confirm_text.append(f"  * {feature}\n", style="dim")

        confirm_text.append(f"\n  Estimated time: {desc.get('estimated_time', 'unknown')}\n",
                            style="dim")

        if desc.get('requires_root', False):
            confirm_text.append("  Requires root/admin privileges\n", style="red")

        confirm_text.append("\n  Press ENTER to continue or CTRL+C to cancel.",
                            style="bold green")

        self.console.print(Panel(confirm_text, border_style="yellow", title="Confirm Scan"))

        try:
            input()
            return True
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Scan cancelled.[/yellow]")
            return False

    # ------------------------------------------------------------------
    # Settings / Help / Export prompts
    # ------------------------------------------------------------------

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
[bold cyan]SunsetScan Help[/bold cyan]

SunsetScan discovers every device on your network, fingerprints running
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

[bold]Key CLI Commands:[/bold]
  sunsetscan --target 192.168.1.0/24                 Quick scan
  sunsetscan --full-assessment --target 192.168.1.0/24  Full report
  sunsetscan --target 192.168.1.0/24 --profile IOT   IoT device scan
  sunsetscan --instant                               Instant device scan
  sunsetscan --modules                               Show data modules
  sunsetscan --download all                          Download all modules
  sunsetscan --download hardware-eol                 Download hardware EOL DB
  sunsetscan --history                               View past scans
  sunsetscan --diff                                  Compare last two scans
  sunsetscan -i                                      Interactive mode
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
        """Display scan completion message."""
        self.console.print(f"\n[bold green]Scan Complete[/bold green]")

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
        print("For best results, run with: sudo sunsetscan")

    def prompt_yes_no(self, question: str, default: bool = False) -> bool:
        """Prompt user with yes/no question."""
        return Confirm.ask(question, default=default)

    def show_error(self, message: str) -> None:
        """Display error message."""
        self.console.print(f"\n[bold red]Error: {message}[/bold red]")

    def show_info(self, message: str) -> None:
        """Display info message."""
        self.console.print(f"[cyan]{message}[/cyan]")

    def show_success(self, message: str) -> None:
        """Display success message."""
        self.console.print(f"[bold green]{message}[/bold green]")

    def show_progress(self, message: str, percentage: float) -> None:
        """Update progress display."""
        bar_width = 30
        filled = int(bar_width * percentage / 100)
        bar = "=" * filled + "-" * (bar_width - filled)

        self.console.print(f"\r[{bar}] {percentage:5.1f}% | {message}",
                          end="", style="cyan")
        if percentage >= 100:
            self.console.print()
