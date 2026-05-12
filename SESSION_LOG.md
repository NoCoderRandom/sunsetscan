# SunsetScan Session Log

Read this at the start of every session to understand where we left off.
Also check: prompts/ directory for planned work.

---

## Session — 2026-04-05: Device Detection Fix & HTML Report Improvement

### Problem
Device identification was misidentifying devices:
- 192.168.50.1 (ASUS RT-AX92U router) → "generic-httpd" or "Apache"
- 192.168.50.61 (Synology NAS) → "nginx"
- 192.168.50.84 (ASUS AiMesh node) → "generic-httpd"

Root causes:
1. No hostname-based extractor (hostname "RT-AX92U-7130" was ignored)
2. HTTP fingerprinter didn't recognize ASUS `httpd/2.0` Server header or `Main_Login.asp` redirect
3. Port 5000 (Synology DSM) wasn't in `HTTP_PORTS` — never got fingerprinted
4. Generic web server names (nginx, Apache, httpd) were promoted to device-level identity
5. Wappalyzer CPE for nginx (`f5:nginx`) set vendor to "F5" and model to "nginx"
6. HTTP fingerprinter model regexes had false positives (TP-Link "Deco" matched `decodeURIComponent`)

### Fixes applied

| File | Change |
|------|--------|
| `core/device_identifier.py` | **NEW `_extract_from_hostname()`** — 10 hostname patterns (ASUS RT/GT/TUF/ROG, Synology DS/RS, QNAP TS, Ubiquiti, MikroTik, etc.). Confidence 0.6 for vendor match, 0.3 for type-only. Added to both `identify()` and `identify_preliminary()` extractor lists. |
| `core/device_identifier.py` | **`_extract_from_http_fingerprint()`** — Added `_FP_VENDOR_MAP` to properly map vendor-like device_types (ASUS→Router, Synology→NAS, etc.) and `_GENERIC_WEB_TYPES` filter to skip nginx/apache/httpd as device evidence. |
| `core/device_identifier.py` | **`_extract_from_wappalyzer()`** — Added `_GENERIC_SOFTWARE_CPES` filter to skip nginx, Apache, PHP, jQuery etc. from CPE parsing and category mapping. Prevents F5/nginx from polluting device identity. |
| `core/device_identifier.py` | **`_HTTP_SERVER_PATTERNS`** — Added `httpd/2.0` → ASUS Router pattern. |
| `core/device_identifier.py` | **`_PORT_DEVICE_HINTS`** — Added `{5000}` → NAS with confidence 0.25 (single port Synology hint). |
| `core/device_identifier.py` | **`_extract_from_nmap_service_info()`** — Added `samba smbd` → NAS pattern. |
| `core/http_fingerprinter.py` | **COMMON_PATHS** — Added `/Main_Login.asp` (ASUS), `/message.htm` (AiMesh), `/webman/index.cgi` (Synology). |
| `core/http_fingerprinter.py` | **HEADER_SIGNATURES** — Added `httpd/2.0` → ASUS (confidence 0.5) and `Synology` header. |
| `core/http_fingerprinter.py` | **DEVICE_SIGNATURES** — Added ASUS patterns (`Main_Login.asp`, `AiMesh router`), Synology patterns (`synoSDSjslib`, `webman/index.cgi`), QNAP patterns. Fixed ASUS Router Model regex. Fixed TP-Link/Netgear model regexes to avoid false positives. Fixed Synology Firmware regex (was matching CSS cache busters). |
| `core/http_fingerprinter.py` | **`_analyze_response()`** — Vendor-specific body detections now override generic header detections. Model detection now checks vendor match. |
| `core/banner_grabber.py` | **HTTP_PORTS** — Added 5000, 5001 for Synology DSM fingerprinting. |
| `sunsetscan.py` | Fixed pluralization bug ("1 nass" → "1 nas"). |
| `ui/templates/report.html.j2` | Added "Software" column to Open Ports table showing per-port HTTP fingerprint. Added hostname to topology cards when device identity exists. |

### Results after fix

| IP | Type | Vendor | Model | Before |
|----|------|--------|-------|--------|
| 192.168.50.1 | Router | ASUS | RT-AX92U | generic-httpd |
| 192.168.50.61 | NAS | Synology | — | nginx |
| 192.168.50.84 | Router | ASUS | RT-AX92U | generic-httpd |

### Extractor count: 15 (was 14)
New extractor: `_extract_from_hostname`

---

## Session — 2026-04-04 (Part 1): Device Identification Engine (BUILT)

### What was done

Built a complete **Device Identification Engine** that fuses evidence from
12 sources into a unified `DeviceIdentity` (vendor, model, version,
device_type, confidence) per scanned host.

### New files created
| File | Purpose |
|------|---------|
| `core/device_identifier.py` | Main engine — `DeviceIdentifier` class, `DeviceIdentity` dataclass, 12 extractors, weighted fusion algorithm |
| `data/device_aliases.json` | 115 vendor name normalizations (e.g. "Synology Inc." -> "Synology") |

### Files modified
| File | Change |
|------|--------|
| `sunsetscan.py` | Import DeviceIdentifier, instantiate in __init__, run identification loop after security checks in run_security_checks(), emit INFO finding per identified host, pass device_identities to export_html() calls |
| `core/module_manager.py` | Added `mac-oui` module to MODULE_REGISTRY (IEEE OUI CSV, 4MB, default=True), added `_parse_mac_oui()` parser, registered in `_PARSERS` dict |
| `ui/export.py` | Added `device_identities` parameter to `export_html()`, `export_json()`, `_generate_html()`, `_render_jinja()`, and `export()`. Passes dict to Jinja template. Adds `device_identities` section to JSON export. |
| `ui/templates/report.html.j2` | Added CSS for device identity display. Topology cards show device type/vendor/model when identified. New "Device Inventory" table section between topology and findings. Host headers show identified device name. Host meta section has styled identity badge with confidence. |

---

## Session — 2026-04-04 (Part 2): Sessions 02–04 Executed

### What was done

Executed all four planned prompt sessions (01 was done in Part 1, 02–04
done here). The Device Identification Engine was expanded from 12 to 14
extractors, pattern databases were tripled in size, confidence tuning was
added, terminal display was built, and a new `--identify` CLI flag was added.

### Session 02: JA3S + FTP + HTTP Raw Headers

Added to `core/device_identifier.py`:
- **NEW `_extract_from_ja3s()`** — imports `get_last_ja3s_match` from ssl_checker, checks all open ports for JA3S matches, maps app names via `_JA3S_APP_PATTERNS` (16 patterns). Confidence: 0.5
- **NEW `_extract_from_ftp_banner()`** — checks FTP service banners for server software (vsFTPd, ProFTPD, PureFTPd, FileZilla, Microsoft FTP, wu-ftpd) via `_FTP_BANNER_PATTERNS` (6 patterns). Extracts version. Confidence: 0.25–0.35
- **IMPROVED `_extract_from_http_fingerprint()`** — now also reads `fp.raw_headers`, runs `_HTTP_SERVER_PATTERNS` against Server header, checks X-Powered-By/X-Generator/X-Served-By. Returns list of evidence instead of single item.
- **IMPROVED `_extract_from_http_server_headers()`** — falls back to `port_info.http_fingerprint.raw_headers["Server"]` when banner/version are empty

### Session 03: Credentials Model Index + Pattern Expansion

Added to `core/device_identifier.py`:
- **Model-vendor reverse index** — lazy-loads `default_credentials.json`, builds 31-entry `{model -> vendor}` dict. After fusion, if model is recognized but vendor missing/agrees, vendor is set/boosted by 0.3 confidence.
- **`_SSH_BANNER_PATTERNS`** expanded: 9 → 19 patterns. Added ROSSSH, HUAWEI, Comware, LANCOM, Sun_SSH, Serv-U, WeOnlyDo, dropbear version, OpenSSH version, honeypot.
- **`_HTTP_SERVER_PATTERNS`** expanded: 23 → 38 patterns. Added ASUSRT, WatchGuard, SonicWALL, Zyxel, Aruba, Grandstream, Polycom, Yealink, NETGEAR, TP-LINK, D-Link, RomPager, WebIOPi, AkamaiGHost.
- **`_CERT_PATTERNS`** expanded: 18 → 28 patterns. Added Netgear, TP-Link, ASUS, D-Link, Linksys, WatchGuard, SonicWall, Sophos, pfSense, Grandstream.
- **`_PORT_DEVICE_HINTS`** expanded: 21 → 31 rules. Added MikroTik combo, SIP, IPsec, Proxmox, Kubernetes, Prometheus/Cockpit, Plex, Jellyfin, WireGuard, OpenVPN.
- **`data/device_aliases.json`** expanded: 117 → 134 entries. Added WatchGuard, SonicWall, Zyxel, Grandstream, Polycom, Yealink, LANCOM, HPE/H3C, Oracle.

### Session 04: Terminal Display + Confidence Tuning + --identify

Added/changed in `sunsetscan.py`:
- **`_print_device_id_table()`** — Rich Table with columns IP, Type, Vendor, Model, Version, Conf%. Color-coded: green >=70%, yellow 40-69%, dim <40%. Printed after device identification loop.
- **Per-host check line enrichment** — "✓ 192.168.50.1 — Router — ASUS RT-AX88U" instead of "Checked 192.168.50.1". Uses `identify_preliminary()`.
- **`--identify` CLI flag** — runs scan + banners + device identification only (no security checks). New `run_identify_only()` method. Added to `create_parser()` and `main()`.
- **`identify_preliminary()`** added to DeviceIdentifier — runs 9 host-local extractors without needing findings (MAC, nmap, HTTP fingerprint, banners, ports, nmap services, JA3S, FTP).

Added to `core/device_identifier.py` fusion:
- **Agreement bonus** — N distinct sources agreeing multiplies confidence by `(1 + 0.1 * (N-1))`
- **Conflict penalty** — competing values reduce winner by `loser_total * 0.3`
- **Threshold raised** — field minimum from 0.1 to 0.15

### Current extractor count: 14
| # | Extractor | Source | Confidence |
|---|-----------|--------|-----------|
| 1 | `_extract_from_mac_oui` | MAC address / OUI DB | 0.40–0.45 |
| 2 | `_extract_from_nmap_os` | nmap OS fingerprint | varies |
| 3 | `_extract_from_http_fingerprint` | HttpFingerprint + raw_headers | 0.50+ |
| 4 | `_extract_from_http_server_headers` | HTTP Server header / banner | 0.20–0.50 |
| 5 | `_extract_from_tls_cert` | TLS certificate CN/issuer | 0.35 |
| 6 | `_extract_from_ssh_banner` | SSH banner | 0.10–0.70 |
| 7 | `_extract_from_upnp` | UPnP discovery | 0.75 |
| 8 | `_extract_from_snmp` | SNMP sysDescr | 0.85 |
| 9 | `_extract_from_wappalyzer` | Wappalyzer CPE/categories | 0.30–0.45 |
| 10 | `_extract_from_mdns` | mDNS/Zeroconf | 0.55 |
| 11 | `_extract_from_port_heuristics` | Open port combos | 0.10–0.70 |
| 12 | `_extract_from_nmap_service_info` | nmap service fields | 0.45 |
| 13 | `_extract_from_ja3s` | JA3S TLS fingerprint | 0.50 |
| 14 | `_extract_from_ftp_banner` | FTP server banner | 0.25–0.35 |

### Pattern database sizes
| Pattern List | Count |
|-------------|-------|
| `_SSH_BANNER_PATTERNS` | 19 |
| `_HTTP_SERVER_PATTERNS` | 38 |
| `_CERT_PATTERNS` | 28 |
| `_OS_GUESS_PATTERNS` | 15 |
| `_JA3S_APP_PATTERNS` | 16 |
| `_FTP_BANNER_PATTERNS` | 6 |
| `_PORT_DEVICE_HINTS` | 31 |
| `device_aliases.json` | 134 |

### External data sources verified (2026-04-04)
All 10 external sources return HTTP 200 (OSV returns 405 for GET as expected — it requires POST):
endoflife.date API, OSV.dev, NVD API, SecLists (x2), DefaultCreds, webappanalyzer, salesforce/ja3, many-passwords, IEEE OUI.

---

## Known Gaps — Addressed by New Prompts (prompts/01–03)

Analysis performed 2026-04-04. These are the remaining improvements:

1. **Identity→EOL bridge is missing** — Device identification finds "Synology NAS v7.2" but the EOL checker never checks synology-dsm 7.2 against endoflife.date. The two pipelines don't talk to each other. (prompt 01)

2. **HTTP fingerprint firmware versions not checked for EOL** — HttpFingerprint.firmware_version is read by device identifier but never fed to EOL checker. (prompt 01)

3. **QUICK scan profile missing `-sV`** — Default scan gets no version data from nmap, limiting both EOL and identification. (prompt 02)

4. **SNMP sysDescr patterns limited** — Only 15 patterns. Missing Fortinet, WatchGuard, SonicWall, Aruba, Huawei, HP iLO, Dell iDRAC, and others. (prompt 02)

5. **SSH banner OS version not extracted for EOL** — Banners like "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5" contain embedded OS+version but this is not piped to EOL. (prompt 02)

6. **Consumer router/camera EOL not available upstream** — endoflife.date doesn't track MikroTik, Ubiquiti, Netgear, D-Link, TP-Link, ASUS, Hikvision, Dahua. NOT_TRACKED_PRODUCTS skips them. No code fix possible without a custom EOL data source. (documented, not in prompts)

7. **No device identification in interactive menu** — No "Device Inventory" option, no way to run --identify from the menu. (prompt 03)

8. **README does not document device identification** — The --identify flag, device identification engine, and new pattern databases are not in the README. (prompt 03)

### How to use the new prompts
```
prompts/01_identity_eol_bridge.txt        → Connect identification to EOL checking   ✓ DONE
prompts/02_version_detection_expansion.txt → Better version extraction + SNMP + scan profiles  ✓ DONE
prompts/03_ui_readme_polish.txt           → Interactive menu + README + console UX   ✓ DONE
```

---

## Session — 2026-04-04 (Part 3): Prompts 02 + 03 + Masscan Hardening

### What was done

Executed prompts 02 and 03 in sequence, then hardened the masscan integration.

### Prompt 02: Version Detection Expansion

| Area | Change |
|------|--------|
| **QUICK scan profile** | Added `-sV --version-intensity 2` — every default scan now gets service version data |
| **SNMP sysDescr patterns** | Expanded 15 → 25: added FortiOS, WatchGuard Fireware, SonicOS, ArubaOS, Huawei VRP, HP iLO, Dell iDRAC, TrueNAS, OPNsense, Windows Server |
| **Product map** | Added 11 PRODUCT_MAP entries + 5 NOT_TRACKED entries for new SNMP slugs |
| **SSH banner → CVE pipeline** | `_run_cve_checks()` now extracts OpenSSH/dropbear versions from SSH banners and runs CVE lookups |
| **HTTP fingerprint → CVE pipeline** | `_run_cve_checks()` now checks `raw_headers["Server"]` for product/version (e.g. `Apache/2.4.29`) |
| **SSH banner OS hint** | Device identifier returns low-confidence (0.15) Ubuntu release hints from SSH package revision suffix |

### Prompt 03: UI + README + Console Polish

| Area | Change |
|------|--------|
| **Display refactor** | Moved `_print_device_id_table()` to `Display.show_device_inventory()` — shared by sunsetscan.py and interactive controller |
| **Interactive menu** | Added `[8] Device Inventory` option with `_run_device_inventory()` handler |
| **Scan summary stats** | `calculate_stats()` now includes `devices_identified`, `devices_total`, `device_types` Counter |
| **Summary panel** | `show_summary()` displays "Devices identified: X/Y (types)" |
| **Full assessment output** | Device identification summary shown between finding counts and risk scores |
| **Console formatting** | Per-host identity labels truncated to 50 chars; table truncates model (20) and version (12); empty table shows warning |
| **`--identify` summary** | Now shows type breakdown: "8 devices identified (3 routers, 2 NAS, ...)" |
| **README** | Added `### Device Identification` feature summary, `--identify` CLI flag, `## Device Identification` detailed section with evidence source table |

### Masscan Integration Hardening

| Area | Change |
|------|--------|
| **Root detection** | `_masscan_available()` now checks `os.geteuid() == 0` — masscan disabled without root, no wasted time |
| **Profile-specific ports** | New `_extract_profile_ports()` — IOT/SMB profiles pass their port lists to masscan instead of scanning 1-65535 |
| **`-p` conflict fix** | New `_build_nmap_args()` static method strips existing `-p` and `-F` before injecting masscan-discovered ports |
| **Progress feedback** | masscan phase now calls progress callback ("masscan port discovery..." 5%, result count 15%, per-host nmap progress) |
| **stderr logging** | Non-zero masscan exit codes log first stderr line as warning |
| **Timestamps** | Parallel `ScanResult` now has proper `start_time`, `end_time`, `duration` |

### Files modified
| File | Change |
|------|--------|
| `config/settings.py` | QUICK profile: `-sV --version-intensity 2`, updated description |
| `core/snmp_checker.py` | 10 new sysDescr patterns (25 total) |
| `core/device_identifier.py` | SSH banner returns list with Ubuntu version hint |
| `core/port_scanner.py` | Root check, profile-port extraction, `-p` conflict fix, progress, stderr, timestamps |
| `eol/product_map.py` | 11 new PRODUCT_MAP + 5 NOT_TRACKED entries |
| `sunsetscan.py` | `import re`, SSH/HTTP CVE pipelines, device stats in calculate_stats and full assessment, display delegation, identity truncation |
| `ui/display.py` | `show_device_inventory()` method, device stats in `show_summary()` |
| `ui/interactive_controller.py` | `[8] Device Inventory` menu option + handler |
| `README.md` | Device identification docs, `--identify` flag, evidence table, QUICK profile update |

### Tested — all scan profiles verified
Both 192.168.1.0/24 and 192.168.50.0/24 tested with PING, QUICK, FULL, STEALTH, IOT, SMB, `--identify`, and `--full-assessment`. All passed.

### Version
All changes on top of v1.7.0 (commit 3d67efd). Ready to commit.

---

## Session — 2026-04-05: Hybrid Network Intelligence Scanner

### What was done

Built a complete **hybrid passive+active scanning pipeline** that combines
background packet sniffing with SunsetScan's existing active scanners, OUI
vendor lookup, and persistent device history into a single fused identity
per device.

### New files created

| File | Purpose |
|------|---------|
| `core/oui_lookup.py` | Standalone IEEE OUI database loader (32K+ entries from nmap's mac-prefixes file). Exports `OUIDatabase` class and `lookup_vendor(mac)` convenience function. |
| `core/packet_parsers.py` | Protocol-specific packet parsers for mDNS (TXT/SRV/PTR records → names, models, services), SSDP/UPnP (SERVER header, NT type → vendor, device type), and DHCP (option 12 hostname, option 60 OS hint, option 55 fingerprint). Returns `ParsedPacket` dataclass. |
| `core/passive_sniffer.py` | Background scapy packet capture on UDP 5353 (mDNS), 1900 (SSDP), 67/68 (DHCP). Thread-safe storage with configurable max packets. `start()`/`stop()`/`parse_all()` API. Requires root + scapy. |
| `core/device_map.py` | Persistent JSON-backed MAC→identity database at `data/device_map.json`. Tracks first_seen, last_seen, observation_count. Accumulates IPs/hostnames. Confidence boosted by consistent re-observations. Detects new and missing devices. |
| `core/identity_fusion.py` | Multi-source weighted voting engine. Combines active scan (weight 1.0), mDNS (0.85), SSDP (0.75), DHCP (0.7), history (0.6), OUI (0.4). Resolves field conflicts, computes composite confidence with diversity and specificity bonuses. |
| `core/hybrid_scanner.py` | Main orchestrator: `start_passive()` → active scans → `stop_and_fuse()`. Returns `HybridScanResult` with fused identities, new/missing device lists, passive packet stats. |

### Files modified

| File | Change |
|------|--------|
| `sunsetscan.py` | Added imports for HybridScanner, FusedIdentity. Added `self.hybrid_scanner` and `self.last_hybrid_result` to `__init__`. Added Phase 0 (start passive capture) and Phase 8 (stop + fuse) to `run_full_assessment()`. Updated all phase numbers from /7 to /8. Added fused identity summary with source breakdown to output. |
| `core/__init__.py` | Added module docstrings and exports for all 6 new modules. |

### Pipeline flow

```
Phase 0: start_passive() ────────────────────────┐
  │                                                │ (background capture)
  ├── Phase 1/8: Host Discovery (ping + ARP)       │
  ├── Phase 2/8: Port Scanning                     │
  ├── Phase 3/8: Banner Grabbing                   │
  ├── Phase 4/8: NSE Scripts                       │
  ├── Phase 5/8: Credential Testing                │
  ├── Phase 6/8: EOL Check                         │
  ├── Phase 7/8: Security Analysis                 │
  │                                                │
Phase 8: stop_and_fuse() ◄────────────────────────┘
  ├── Parse captured mDNS/SSDP/DHCP packets
  ├── Fuse: active + passive + OUI + history
  ├── Update persistent device_map.json
  └── Report with fused identities
```

### Identity fusion source weights

| Source | Weight | What it provides |
|--------|--------|------------------|
| Active scan | 1.0 × confidence | vendor, model, version, device_type (from 15 extractors) |
| mDNS | 0.85 | hostname, services, model (TXT records) |
| SSDP/UPnP | 0.75 | vendor, device_type, OS hint (SERVER header) |
| DHCP | 0.70 | hostname, OS (option 60), fingerprint (option 55) |
| History | 0.60 | all fields from prior scans (boosted with observations) |
| OUI | 0.40 | vendor only (MAC prefix) |

### Tests completed (non-root)

- OUI lookup: 32,577 entries, Apple/Synology/RaspberryPi/Ubiquiti all resolve ✓
- Packet parsers: Synology SSDP, ASUS IGD, Roku, Windows DHCP, Android DHCP, HP printer mDNS ✓
- Device map: save/load/reload, confidence boost on re-observation, new/missing detection ✓
- Identity fusion: full fusion (6 sources → NAS Synology DS920+ conf=1.0), passive-only (DHCP+mDNS → Mobile Device conf=0.865), conflict resolution (SSDP wins over weaker active) ✓
- All modules parse (ast.parse) and import cleanly ✓

### Needs root testing

Passive sniffer requires root for raw socket capture. Next session should:
1. Run with `sudo` to test live passive capture on 192.168.50.0/24 and 192.168.1.0/24
2. Run full `--full-assessment` with hybrid pipeline enabled
3. Verify device_map.json persistence across runs
4. Verify fused identities appear in HTML report

---

## Session — 2026-04-07: Safe Mode for Low-Power Hosts + Instant-Scan Auto-Detect

### Problem
Running `sudo ./sunsetscan.py --full-assessment` on a Raspberry Pi 5 that also
hosted Pi-hole killed the entire LAN — the laptop lost DNS too. Root causes:
1. masscan at default rate exhausted the Pi's `nf_conntrack` table
2. Parallel nmap workers + masscan starved Pi-hole's CPU → DNS timeouts
3. `-O`/`-A` OS fingerprinting against the gateway tipped the router over

Separately, instant scan still prompted for a target even though ARP only
works on the local L2 segment — the only sensible target is the local subnet.

### New module
`core/host_capability.py` — single source of truth for "is this host weak?"
- `detect_host_profile()` reads `/proc/device-tree/model`, `/proc/cpuinfo`,
  `/proc/meminfo`, `/etc/pihole`, `/proc/*/comm`, and `/sys/class/net/*/wireless`
- `HostProfile` dataclass: `is_raspberry_pi`, `cpu_count`, `total_ram_mb`,
  `pihole_active`, `egress_iface`, `egress_is_wifi`
- `safe_mode_overrides(profile)` → dict of Settings field overrides
- `effective_masscan_rate(profile, profile_name, requested)` clamps to caps
- `downgrade_nmap_args(args, profile)` strips `-O`/`-A`/aggressive timing in safe mode
- Caps: `SAFE_MASSCAN_RATE_CAPS[FULL] = 300`, `WIFI_MASSCAN_RATE_CAPS[FULL] = 150`

### Files modified

| File | Change |
|------|--------|
| `config/settings.py` | Added `safe_mode: bool = False` and `excluded_hosts: Tuple[str, ...] = ()` to frozen Settings dataclass. |
| `core/port_scanner.py` | `_run_masscan` accepts `excluded_hosts` (passed as `--exclude`). Both scan paths route the rate through `effective_masscan_rate()`. |
| `core/scanner.py` | Added `_apply_safety()` chokepoint — strips `-O`/`-A` in safe mode and appends `--exclude` for excluded hosts. |
| `core/network_utils.py` | New `is_local_subnet()` returning tri-state `Optional[bool]` (True/False/None for unknown). Validates input via `ipaddress.ip_address()` so bogus targets return None instead of False. |
| `core/instant_scan.py` | Always resolves the local subnet first; warns and falls back if a non-local target is supplied. |
| `sunsetscan.py` | Calls `detect_host_profile()` in `__init__`, builds Settings with overrides, prints `_announce_host_profile()` banner. New CLI flags `--safe-mode` / `--no-safe-mode`. Instant-scan menu item now skips the target prompt. Updated `--instant` help text. |

### Verified on the Pi
User confirmed live output showing:
> Raspberry Pi 5 Model B Rev 1.0, 4 cores, 8062 MB RAM, Pi-hole active,
> egress wlan0 (Wi-Fi) — safe mode auto-enabled, gateway 192.168.50.1 and
> self 192.168.50.212 excluded.

### Commit
`74b2117` — "feat: safe mode for low-power hosts and instant-scan auto-detect"

---

## Session — 2026-04-07: PEP 668-Safe Installer + Bootstrap One-Liner + CRLF Protection

### Problem
Installation on Pi OS / Debian Bookworm failed with PEP 668
"externally-managed-environment" errors. User had to mix `apt install` and
`pip install` manually. Separately, after a `git pull` on the Pi the script
failed with `env: 'python3\r': No such file or directory` because earlier
checkouts had picked up CRLF line endings.

### What was built

**`install.sh`** (rewritten, ~290 lines)
- 6-step flow: detect OS → install system pkgs → create venv → pip install →
  configure launcher → self-test
- Multi-distro: apt, dnf, yum, pacman, zypper, brew (Tier 1 / Tier 2 matrix)
- All Python deps installed inside `./venv` — never touches system Python
- Sudo wrapper that's empty when running as root (containers OK)
- TTY-aware coloring so `curl|bash` logs stay readable
- Idempotent — reuses existing venv unless `--force`
- Flags: `--force`, `--symlink`, `--no-system`, `--help`
- Import sanity check covers all 12 modules SunsetScan actually loads

**`sunsetscan`** (new launcher script, replaces ad-hoc invocation)
- `readlink` loop resolves symlinks so `/usr/local/bin/sunsetscan` works
- Always execs `$SCRIPT_DIR/venv/bin/python3 sunsetscan.py "$@"`
- Prints a clear pointer to `install.sh` if the venv is missing

**`bootstrap.sh`** (new, for `curl|bash` install)
- Clones (or fast-forward pulls) the repo, then `exec bash install.sh "$@"`
- Honors `INSTALL_DIR` / `BRANCH` / `REPO` env vars
- One-liner:
  `curl -fsSL https://raw.githubusercontent.com/NoCoderRandom/sunsetscan/main/bootstrap.sh | bash`

**`.gitattributes`** (new)
- Forces LF on `*.sh`, `*.py`, `*.j2`, `*.yml`, `*.json`, `*.md`, `*.txt`,
  and the `sunsetscan` launcher
- Marks `*.html`, `*.png`, `*.jpg`, `*.gif`, `*.ico` as binary
- Permanently prevents the `python3\r` shebang failure

**`README.md`** — Installation section rewritten with three documented paths:
1. `curl|bash` bootstrap (fastest)
2. `git clone` + `./install.sh` (recommended)
3. Manual 4-command fallback
Plus Tier 1/Tier 2 distro matrix, installer flag table, "Why a venv?" PEP 668
explainer, tmux/screen tips, update + uninstall instructions, WSL2 notes.

### End-to-end test
Fresh install in `/tmp/nwtest` with `./install.sh --no-system`:
- Created venv, pip-installed pysnmp 7.1.22, scapy 2.7.0, cryptography 46.0.6,
  paramiko 4.0.0, impacket 0.13.0, etc.
- Import sanity check: all 12 modules ✓
- Self-test: `sunsetscan 1.7.0` ✓
- Launcher works directly and via `/tmp` symlink (readlink loop verified) ✓

### Commit
`c2d212d` — "feat: PEP 668-safe installer with venv, bootstrap one-liner, and CRLF protection"
