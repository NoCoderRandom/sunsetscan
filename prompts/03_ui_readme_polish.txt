SESSION 03: Interactive Menu + README + Console UX Polish
==========================================================

READ THE SESSION LOG FIRST: SESSION_LOG.md

CONTEXT:
After prompts 01-02, the identification-to-EOL pipeline is complete and
version detection is improved. What remains is user-facing polish:

  A) The interactive menu has no way to run device identification or see
     a device inventory. Users must use the CLI --identify flag or run a
     full scan. The interactive menu should expose this capability.

  B) The README doesn't document the device identification engine, the
     --identify flag, the 14 extractors, or the identity-to-EOL bridge.
     This is a major feature that's completely invisible in docs.

  C) Console output can be improved — the device ID table needs better
     formatting for edge cases, scan summary stats should include device
     identification counts, and the full assessment output should show
     identification results prominently.

TASK:

1. ADD DEVICE IDENTIFICATION TO INTERACTIVE MENU
   In ui/interactive_controller.py:

   a) Add a new menu option to the main menu:
      Current:
        [1] Host Operations
        [2] Bulk Operations
        [3] Full Assessment
        [4] Network Menu
        [5] Results & History
        [6] Modules & Data
        [7] Settings
        [0] Exit

      Add:
        [8] Device Inventory    - Identify all devices on the network

      Update the Prompt.ask choices to include "8".

   b) Implement the handler method _run_device_inventory():
      - If no scan result exists, prompt user to run a scan first
      - If scan result exists, import DeviceIdentifier, run identify_preliminary()
        on all hosts, and print the device ID table
      - Reuse SunsetScan._print_device_id_table() — either by importing it or
        by duplicating the Rich Table logic locally (prefer importing if clean)
      - Actually, the cleanest approach: move _print_device_id_table() to
        ui/display.py as a method on Display class, so both sunsetscan.py and
        interactive_controller.py can call it. Pass the device_identities dict
        and optionally the eol_data dict as parameters.

   c) After any scan completes in the interactive controller (when it calls
      SunsetScan.perform_scan or SunsetScan.run_full_assessment), the device ID
      table is already printed by run_security_checks(). But if the user
      wants to see it again, the [8] option should work.

2. MOVE _print_device_id_table TO ui/display.py
   To avoid code duplication between sunsetscan.py and interactive_controller.py:

   a) Add a new method to the Display class in ui/display.py:
      def show_device_inventory(self, device_identities, eol_data=None):
          """Display device identification results in a Rich table."""
          # Same logic as current _print_device_id_table in sunsetscan.py
          # Plus optional EOL column from prompt 01
          # Use self.console for output

   b) In sunsetscan.py, replace _print_device_id_table() body with:
      self.display.show_device_inventory(
          self.last_device_identities,
          self.last_eol_data,
      )

   c) In interactive_controller.py, call:
      display.show_device_inventory(device_identities, eol_data)

3. ADD DEVICE COUNT TO SCAN SUMMARY STATS
   In sunsetscan.py, the calculate_stats() method returns a dict used by
   display.show_summary(). Add device identification stats:

   a) Add to the stats dict:
      - "devices_identified": len(self.last_device_identities)
      - "devices_total": len(scan_result.hosts)  (hosts that are up)
      - "device_types": Counter of device_type values (e.g. {"Router": 2, "NAS": 1})

   b) In ui/display.py show_summary(), display the new stats:
      "Devices identified: 8/12 (Router: 2, NAS: 1, Camera: 3, Unknown: 2)"

   c) In the full assessment output (run_full_assessment), add the device
      identification summary between the finding counts and risk scores.

4. IMPROVE CONSOLE OUTPUT FORMATTING
   a) In the per-host check line (run_security_checks), truncate the
      identity summary to 50 chars max so it doesn't wrap on narrow terminals:
      "  [green]check[/green] 192.168.50.1 — Router — ASUS RT-AX88U v3.0..."

   b) In _print_device_id_table (now show_device_inventory), handle edge cases:
      - Truncate long model names to 20 chars
      - Truncate long version strings to 12 chars
      - If no devices identified, print "[yellow]No devices identified.[/yellow]"
        instead of an empty table

   c) In the --identify output (run_identify_only), after the table, also
      show a one-line summary: "8 devices identified (3 routers, 2 NAS, ...)"

5. UPDATE README.md
   Add a new section after "### Vulnerability Intelligence" called
   "### Device Identification":

   ```markdown
   ### Device Identification
   - **14 evidence extractors** fuse MAC OUI, nmap OS, HTTP fingerprinting,
     TLS certificates, SSH banners, UPnP, SNMP sysDescr, Wappalyzer, mDNS,
     JA3S TLS fingerprints, FTP banners, port heuristics, and nmap service
     fields into a unified device identity per host
   - Identifies vendor, model, firmware version, and device type with
     confidence scoring (agreement bonuses when multiple sources confirm)
   - Supports 130+ vendor aliases for name normalization
   - Results displayed in terminal table and HTML report device inventory
   - Quick asset inventory mode: `--identify` flag skips security checks
   ```

   Update the "All CLI Flags" table to include --identify:
   ```
   --identify              Run device identification only (skip security checks)
   ```

   Update the "Scan Profiles" table if QUICK was changed in prompt 02.

   Add a new section "## Device Identification" (top-level) after
   "## HTML Report" with more detail:

   ```markdown
   ## Device Identification

   SunsetScan automatically identifies network devices by combining evidence
   from 14 different sources. Each source contributes a vendor, model,
   version, or device type with a confidence score. The fusion algorithm
   sums agreeing sources (with bonuses for multi-source agreement) and
   penalizes conflicting evidence.

   ### Quick Asset Inventory

   To see what's on your network without running security checks:

   ```bash
   python3 sunsetscan.py --identify --target 192.168.1.0/24
   ```

   This runs a port scan with banner grabbing and prints a device
   identification table. No security analysis, no report — just a fast
   inventory.

   ### Evidence Sources

   | Source | What it reads | Confidence |
   |--------|--------------|------------|
   | MAC OUI | IEEE vendor prefix from MAC address | 0.40-0.45 |
   | nmap OS | OS fingerprint guess | varies |
   | HTTP fingerprint | Device type, model, firmware from web UI | 0.50+ |
   | HTTP headers | Server, X-Powered-By response headers | 0.20-0.50 |
   | TLS certificate | CN, issuer, organization fields | 0.35 |
   | SSH banner | SSH daemon identification string | 0.10-0.70 |
   | UPnP | SSDP manufacturer, model, device type | 0.75 |
   | SNMP sysDescr | System description from SNMP MIB | 0.85 |
   | Wappalyzer | CPE strings and technology categories | 0.30-0.45 |
   | mDNS/Zeroconf | Service type advertisements | 0.55 |
   | JA3S | TLS handshake fingerprint database | 0.50 |
   | FTP banner | FTP server software identification | 0.25-0.35 |
   | Port heuristics | Open port combination patterns | 0.10-0.70 |
   | nmap services | Service product and version fields | 0.45 |

   Identification results appear in:
   - Terminal device inventory table (during scan and via `--identify`)
   - HTML report topology cards and device inventory section
   - JSON export `device_identities` section
   ```

6. UPDATE version badge in README if we're bumping version
   Check with the session log — if we're still on v1.7.0 don't change it.
   The version bump should be decided by the user, not by this prompt.

VERIFY:
  - python3 -m py_compile ui/display.py
  - python3 -m py_compile ui/interactive_controller.py
  - python3 -m py_compile sunsetscan.py
  - python3 sunsetscan.py --help (verify --identify shown)
  - Verify README renders: check that new markdown sections have no syntax errors
    python3 -c "
    with open('README.md') as f: lines = f.readlines()
    headers = [l.strip() for l in lines if l.startswith('#')]
    for h in headers: print(h)
    "

FILES TO READ FIRST:
  - ui/interactive_controller.py (lines 316-343 for show_main_menu, search for
    "_run_full_assessment_from_menu" to see how scan delegation works)
  - ui/display.py (lines 72-90 for __init__, lines 120-227 for show_results_table
    as a model for building new table methods, lines 280-370 for show_summary)
  - sunsetscan.py (lines 1104-1138 for _print_device_id_table, lines 527-540 for
    calculate_stats area, lines 1456-1473 for full assessment finding counts)
  - README.md (full file — understand structure, find insertion points)
