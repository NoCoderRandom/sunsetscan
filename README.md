# NetWatch

**Network security auditing for humans — powered by nmap, built for everyone.**

[![Version](https://img.shields.io/badge/version-v1.7.0-blue)]
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20WSL2-brightgreen?logo=linux)](https://github.com)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Hardware DB License: CC BY-NC 4.0](https://img.shields.io/badge/hardware%20DB-CC%20BY--NC%204.0-lightgrey)](data/hardware_eol/LICENSE.md)
[![Requires: nmap](https://img.shields.io/badge/requires-nmap-orange)](https://nmap.org)
[![CVE data: OSV.dev](https://img.shields.io/badge/CVE%20data-OSV.dev-blueviolet)](https://osv.dev)
[![EOL data: endoflife.date](https://img.shields.io/badge/EOL%20data-endoflife.date-yellow)](https://endoflife.date)

---

NetWatch is a local-network security auditing tool for **home network owners and IT staff** who want the depth of nmap without learning nmap syntax. Point it at your network and it finds every active device, fingerprints running software, checks against known vulnerability databases and end-of-life records, probes web interfaces for common weaknesses, tests for default credentials, and produces a clean HTML report with **plain-English explanations** and numbered steps to fix each finding. It is **entirely read-only and non-destructive** — nothing on your network is ever modified.

---

## Platform Support

| Platform | Support Level | Notes |
|---|---|---|
| **Linux** (Debian, Ubuntu, Fedora, Arch, etc.) | Full support | Best experience — all features work natively |
| **WSL2** (Windows Subsystem for Linux) | Full support | Recommended way to run on Windows machines |
| **macOS** | Partial | Core scanning works; some features (ARP, passive capture) may require extra setup |
| **Windows** (native CMD/PowerShell) | Not supported | Missing raw sockets, `os.geteuid()`, `/proc`, `ip route`, and `termios` — use WSL2 instead |

> **Why Linux?** NetWatch relies on raw sockets (ARP scanning, passive packet capture), Linux-specific APIs (`/proc`, `ip route`), and privilege checks (`os.geteuid()`) that are not available on native Windows. WSL2 provides a full Linux kernel and is the recommended path for Windows users.

---

## Installation

NetWatch ships with an installer that takes care of system tools (`nmap`, `masscan`, `git`, `python3-venv`), creates a project-local Python virtual environment, and installs all Python dependencies inside it. **You will never be asked to `pip install` anything as root** — that's important on modern Debian/Pi OS, see [Why a venv?](#why-a-venv) below.

### Tier-1 platforms (fully tested)

Debian, Ubuntu, Raspberry Pi OS (Bookworm and newer), Linux Mint, Pop!_OS.

### Tier-2 platforms (best-effort, same script)

Fedora, RHEL, CentOS, Rocky, Alma, Arch, Manjaro, openSUSE, macOS.

### Three ways to install — pick one

#### 1. One-line bootstrap (recommended for new users)

Clones the repo into `~/netwatch` and runs the installer:

```bash
curl -fsSL https://raw.githubusercontent.com/NoCoderRandom/netwatch/main/bootstrap.sh | bash
```

Want it somewhere else? Set `INSTALL_DIR`:

```bash
INSTALL_DIR=/opt/netwatch curl -fsSL https://raw.githubusercontent.com/NoCoderRandom/netwatch/main/bootstrap.sh | bash
```

> **A note on `curl | bash`**: it's convenient but it does mean running a script you haven't read. If you'd rather inspect first, use option 2 or 3.

#### 2. Clone and install

```bash
git clone https://github.com/NoCoderRandom/netwatch.git
cd netwatch
./install.sh
```

#### 3. Manual install (full control, four commands)

```bash
sudo apt install -y nmap masscan git python3 python3-venv python3-pip libpcap-dev build-essential avahi-utils
git clone https://github.com/NoCoderRandom/netwatch.git && cd netwatch
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
./netwatch --version
```

(Substitute your distro's package manager for `apt` — `dnf`, `pacman`, `zypper`, or `brew`. The avahi package is `avahi-tools` on Fedora/RHEL, `avahi` on Arch, `avahi-utils` on openSUSE, and not needed on macOS.)

### After installing — first run

```bash
sudo ./netwatch --setup            # download EOL/CVE/credential databases (once)
sudo ./netwatch --instant          # ARP-only inventory of your local subnet
sudo ./netwatch --full-assessment --target 192.168.1.0/24
```

The `./netwatch` launcher auto-activates the venv — you don't need to `source venv/bin/activate` ever. It also works correctly under `sudo`.

### Installer flags

| Flag | Effect |
|---|---|
| (no flags) | Default install: system packages + venv + Python deps + self-test |
| `--force` | Delete and rebuild the venv from scratch (use after upgrading Python) |
| `--symlink` | Also install `/usr/local/bin/netwatch` so you can run `netwatch` from anywhere |
| `--no-system` | Skip the apt/dnf/etc step (use if your system tools are already installed) |
| `--help` | Show all options |

Re-running `./install.sh` is safe and idempotent — it detects existing components and reuses them.

### Why a venv?

Modern Debian-based distributions (Debian Bookworm, Raspberry Pi OS Bookworm, Ubuntu 23.04+) ship with [PEP 668](https://peps.python.org/pep-0668/) enforcement. This makes `pip install` **fail** when run as root against the system Python:

```
error: externally-managed-environment
× This environment is externally managed
```

Two of NetWatch's dependencies (`pysnmp` v6 in particular) need newer versions than the apt repositories ship, so a pure-apt install isn't possible. The installer's solution is the standard one: install system tools (nmap, masscan, libpcap, avahi-utils) via apt, and put NetWatch's Python dependencies in a project-local `./venv` directory. Nothing system-wide is touched, so PEP 668 doesn't apply, and uninstalling NetWatch is just `rm -rf ~/netwatch`.

### Optional: keep NetWatch running in the background

A full assessment of a /24 subnet on a Raspberry Pi can take 10–30 minutes. Use `tmux` or `screen` so the scan survives an SSH disconnect:

```bash
sudo apt install -y tmux
tmux new -s netwatch
sudo ./netwatch --full-assessment --target 192.168.1.0/24
# Ctrl+B then D to detach. "tmux attach -t netwatch" to come back later.
```

### Updating NetWatch

```bash
cd ~/netwatch
git pull
./install.sh                # idempotent — picks up any new dependencies
```

### Uninstalling

```bash
rm -rf ~/netwatch
sudo rm -f /usr/local/bin/netwatch    # only if you used --symlink
```

### WSL2 on Windows

Windows is not directly supported (NetWatch needs raw sockets, `/proc`, and `os.geteuid`), but WSL2 works fine:

```powershell
wsl --install -d Ubuntu     # in PowerShell, as Administrator
```

Restart, open **Ubuntu** from the Start menu, then follow the standard install above. WSL2 uses a virtual network adapter — pass your real subnet with `--target` if auto-detection picks the wrong one.

---

## Requirements

| Requirement | Minimum | Notes |
|---|---|---|
| **Python** | 3.9+ | 3.12 recommended |
| **nmap** | Any recent | Must be on system PATH |
| **OS** | Linux (native or WSL2) | See [Platform Support](#platform-support) |
| **masscan** | Any | Optional — faster port discovery |
| **avahi-utils** | Any | Optional — provides `avahi-browse`, used for reliable mDNS discovery of Apple / Bonjour / Sleep-Proxy devices. Falls back to python `zeroconf` if absent. |
| **git** | Any | Optional — used for `--setup` and `--update` |
| **Privileges** | Standard user | Root/sudo needed for FULL, STEALTH, SMB profiles, ARP detection, and passive capture |

---

## Quick Start

```bash
# Interactive mode (recommended for first-time users)
sudo python3 netwatch.py -i

# Full security assessment with HTML report
sudo python3 netwatch.py --full-assessment --target 192.168.1.0/24

# Quick scan of your network
python3 netwatch.py --target 192.168.1.0/24

# IoT device scan (cameras, routers, smart devices)
python3 netwatch.py --target 192.168.1.0/24 --profile IOT

# Quick device inventory (no security checks)
python3 netwatch.py --identify --target 192.168.1.0/24

# Download all data modules for extended detection
python3 netwatch.py --download all
```

---

## Features

### Network Discovery
- Discovers all active hosts via fast ping sweep
- Resolves hostnames and detects MAC addresses with vendor/manufacturer lookup
- Flexible target input: CIDR, wildcard, IP range, comma-separated, or hostname
- Optional masscan integration for faster port discovery on large networks
- Hybrid scanning: passive background capture (mDNS/SSDP/DHCP) combined with active scanning

### Port and Service Scanning
- Six scan profiles: QUICK, FULL, STEALTH, PING, IOT, SMB
- Concurrent banner grabbing across all open ports (50-thread pool)
- OS fingerprinting with confidence percentage
- NSE (Nmap Scripting Engine) integration for enhanced device detection
- HTTP fingerprinting to identify routers, cameras, NAS devices, printers, and IoT
- Automatic root-privilege fallback: FULL/STEALTH profiles gracefully degrade when run without sudo
- Parallel security analysis — all per-host checks (SSL, SSH, FTP, SMB, SNMP, Web) run concurrently across hosts and within each host using thread pools
- Phase 7 security analysis completes in under 10 seconds regardless of network size
- Pre-scan readiness check — warns if nmap is missing, CVE/EOL databases are empty, or default modules are not installed. Runs before every scan, does not block scanning.

### Security Checks
NetWatch runs 12 security checker modules during a full assessment:

| Checker | What it finds |
|---|---|
| **SSL/TLS** | Expired/self-signed certs, weak ciphers, TLS 1.0/1.1, SSL 2.0/3.0, small RSA keys |
| **SSH** | Weak key exchange, weak ciphers/MACs, SSHv1, small host keys, raw KEXINIT analysis |
| **SMB** | SMBv1, EternalBlue (MS17-010), anonymous shares, SMB signing disabled, NTLM disclosure |
| **FTP** | Anonymous login, cleartext credentials, missing STARTTLS |
| **SNMP** | Default community strings (public/private), SNMPv1, sysDescr extraction |
| **Web** | Missing security headers, login forms over HTTP, directory listing, exposed admin panels |
| **DNS** | DNS hijacking detection (compares against Cloudflare 1.1.1.1) |
| **UPnP** | SSDP discovery, WAN port-mapping exposure on routers |
| **mDNS** | Zeroconf/Bonjour device discovery, finds hosts that evade port scans |
| **ARP** | ARP spoofing detection, MAC address change tracking (requires root) |
| **Default credentials** | Factory-default passwords on routers, NAS, cameras, printers (opt-in) |
| **Insecure protocols** | Telnet, FTP, TFTP, rsh, rlogin, rexec flagged by severity |

### Vulnerability Intelligence
- **CVE correlation** — maps detected service versions to known CVEs using OSV.dev
- **EOL checking** — 150+ products checked against endoflife.date
- **Hardware lifecycle checking** — downloadable NetWatch hardware EOL database
  flags routers, switches, NAS, cameras, printers, and access points with
  confirmed unsupported status or vendor lifecycle signals that need review
- **JA3S TLS fingerprinting** — identifies server software from TLS handshake signatures
- Fully offline during scans — no external API calls are made during scanning. endoflife.date, OSV.dev, and GitHub module sources are only contacted by `--setup`, `--update-cache`, and `--download`. Scans work without any internet connection as long as caches are populated.
- Weekly CVE refresh, monthly EOL refresh — controlled by you

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
- Persistent MAC-to-identity mapping across scans

### Modular Data System
NetWatch includes 9 downloadable data modules that extend detection capabilities:

| Module | Source | What it adds |
|---|---|---|
| `credentials-mini` | danielmiessler/SecLists | Top 50 default credentials (default) |
| `credentials-full` | ihebski/DefaultCreds-cheat-sheet | 2860+ vendor-specific credentials |
| `wappalyzer-mini` | enthec/webappanalyzer | Top 500 web technologies (default) |
| `wappalyzer-full` | enthec/webappanalyzer | All 7515 web technologies |
| `ja3-signatures` | salesforce/ja3 | TLS fingerprint database |
| `snmp-community` | danielmiessler/SecLists | Extended SNMP community strings |
| `camera-credentials` | many-passwords/many-passwords | IP camera/DVR/NVR default passwords |
| `mac-oui` | IEEE Standards Association | MAC prefix vendor database (default) |
| `hardware-eol` | NoCoderRandom/netwatch | Hardware lifecycle/EOL database (default; database license: CC BY-NC 4.0) |

```bash
netwatch --modules                # Show module status
netwatch --download all           # Download everything
netwatch --download ja3-signatures  # Download one module
```

### Rogue Device Detection
- Save a snapshot of your network as a trusted baseline
- Future scans automatically flag unknown MAC addresses not in the baseline
- Detects known devices on unexpected IP addresses

### Risk Scoring
Every device receives a risk score (0-100) based on the severity and count of findings:

| Score | Band |
|---|---|
| 0-10 | Minimal Risk |
| 11-30 | Low Risk |
| 31-60 | Medium Risk |
| 61-80 | High Risk |
| 81-100 | Critical Risk |

### Reporting
- **Professional HTML report** — severity dashboard, per-host sections, finding cards with plain-English explanations, prioritised recommendations
- **JSON export** — machine-readable structured output
- Reports are fully self-contained — one HTML file, no external dependencies
- All findings colour-coded: Critical, High, Medium, Low, Info

### Scan History and Diffing
- Every scan is automatically saved as a gzip-compressed JSON snapshot
- View past scans with `--history`
- Compare any two scans with `--diff` to see new hosts, closed ports, new/resolved findings
- Compare against a scan from N days ago with `--diff --since N`
- History retained for 90 days by default

### User Interface
- Guided **interactive mode** (`-i`) — multi-level menus for scanning, analysis, export, modules
- **Old-style menu** — launches when run with no arguments
- Direct CLI mode — scriptable and automation-friendly
- Rich colour terminal output with progress bars, spinners, and summary panels

---

## All CLI Flags

| Flag | Description | Root |
|---|---|---|
| `--target TARGET` | IP, CIDR range, hostname, or range to scan | No |
| `--profile PROFILE` | Scan profile: QUICK, FULL, STEALTH, PING, IOT, SMB (default: QUICK) | Varies |
| `-i`, `--interactive` | Launch guided interactive mode | No |
| `--full-assessment` | Complete assessment: all phases + auto HTML export | No |
| `--identify` | Run device identification only (skip security checks) | No |
| `--nse` | Enable Nmap Scripting Engine for enhanced detection | No |
| `--check-defaults` | Test for factory-default credentials (your own devices only) | No |
| `--save-baseline` | Save scan as trusted device baseline for rogue detection | No |
| `--setup` | First-time setup wizard (dependencies + cache download) | No |
| `--update-cache` | Manually refresh CVE and EOL data caches | No |
| `--cache-status` | Show cache age and entry counts, then exit | No |
| `--modules` | Show status of all downloadable data modules | No |
| `--download MODULE` | Download a data module (or "all") | No |
| `--db SIZE` | EOL database size for `--setup`: mini, normal, large (default: normal) | No |
| `--history` | Show scan history table and exit | No |
| `--diff` | Diff last two saved scans and exit | No |
| `--since DAYS` | With `--diff`: compare against scan at least N days old | No |
| `--check-version` | Check for newer NetWatch release on GitHub | No |
| `--update` | Pull latest code from GitHub and reinstall requirements | No |
| `--verbose` | Enable debug logging | No |
| `--no-color` | Disable colour output (useful for log files) | No |
| `--quiet` | Suppress progress bars (findings still shown) | No |
| `--version` | Show version number and exit | No |

---

## Scan Profiles

| Profile | nmap flags | Speed | Root | Best for |
|---|---|---|---|---|
| **PING** | `-sn` | ~30s | No | Finding active devices quickly |
| **QUICK** | `-T4 -F -sV --version-intensity 2` | 1-3 min | No | First look at a network (with light version detection) |
| **FULL** | `-T4 -A -sV -O --osscan-guess` | 5-15 min | Yes | Deep analysis of specific hosts |
| **STEALTH** | `-sS -T2 -sV` | 10-30 min | Yes | Low-noise scanning |
| **IOT** | `-T4 -sV -p 23,80,443,8080,8443,554,1900,5000,5001,7547,49152 --open` | 1-3 min | No | Cameras, routers, smart devices |
| **SMB** | `-T4 -sV -p 135,139,445,137,138 --script smb-security-mode,smb2-security-mode,smb-vuln-ms17-010 --open` | 1-3 min | Yes | Windows shares, EternalBlue check |

> **Tip:** FULL and STEALTH automatically fall back to non-root flags when run without sudo. OS detection will be unavailable but port scanning and service detection still work.

---

## Cache Management

NetWatch never calls external APIs during a scan. All data is read from local cache files in `data/cache/`.

| File | Contents | Refresh interval |
|---|---|---|
| `data/cache/cve_cache.json` | CVE data keyed by product:version | Every 7 days |
| `data/cache/*.json` | EOL dates for 150+ products, stored per product | Every 30 days |
| `data/cache/hardware_eol/netwatch_hardware_eol.json` | Hardware lifecycle/EOL database | Every 30 days |
| `data/cache/cache_meta.json` | Timestamps of last updates | Automatic |

```bash
netwatch --cache-status     # See current cache state
netwatch --update-cache     # Refresh stale caches
```

Scans work normally with stale or missing cache — you just may have outdated CVE data.

---

## Rogue Device Detection

```bash
# Step 1: Save baseline when all known devices are present
sudo python3 netwatch.py --target 192.168.1.0/24 --save-baseline

# Step 2: Future scans automatically compare against baseline
sudo python3 netwatch.py --target 192.168.1.0/24
```

| Finding | Severity | Meaning |
|---|---|---|
| Unknown device detected | Medium | MAC not in baseline — new or unauthorised device |
| Device IP changed | Low | Known MAC on a different IP (usually normal DHCP) |
| Previously seen device offline | Info | Baseline device not responding |

> **Note:** Baseline requires root/sudo for MAC address detection via nmap.

---

## HTML Report

Every `--full-assessment` produces a self-contained HTML report with:

- **Severity dashboard** — badge counts (Critical/High/Medium/Low/Info), colour bar, summary statistics
- **Risk scores** — per-device 0-100 score with risk band label
- **All findings table** — every finding across all hosts, sorted by severity
- **Per-host sections** — collapsible section per device with finding cards, open ports table, EOL status
- **Finding cards** — severity badge, title, "What was found", "What this means" (plain English), "What to do" (numbered steps), evidence, CVE IDs
- **Recommendations** — prioritised action list

Reports open in any browser with no internet required.

---

## Device Identification

NetWatch automatically identifies network devices by combining evidence
from 14 different sources. Each source contributes a vendor, model,
version, or device type with a confidence score. The fusion algorithm
sums agreeing sources (with bonuses for multi-source agreement) and
penalizes conflicting evidence.

### Quick Asset Inventory

To see what's on your network without running security checks:

```bash
python3 netwatch.py --identify --target 192.168.1.0/24
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
- Interactive mode menu option [8] Device Inventory

---

## Severity Levels

| Level | Colour | CVSS range | What it means | When to act |
|---|---|---|---|---|
| **CRITICAL** | Red | >= 9.0 | Default credentials, exploitable CVE, SSL 2.0 | Today |
| **HIGH** | Orange | 7.0-8.9 | Telnet/FTP open, expired cert, TLS 1.0, EOL software | This week |
| **MEDIUM** | Yellow | 4.0-6.9 | Self-signed cert, UPnP exposure, rogue device, missing HSTS | Schedule fix |
| **LOW** | Blue | < 4.0 | EOL approaching, missing X-Frame-Options, device IP changed | Track and plan |
| **INFO** | Grey | - | Device identified, cert details, DNS check passed | No action |

---

## Project Structure

```
netwatch/
├── netwatch.py                    # Entry point — CLI, scan pipeline, setup wizard
├── requirements.txt               # Python dependencies
├── install.sh                     # Automated installer for Linux/macOS
├── install.bat                    # Automated installer for Windows (basic)
├── README.md                      # This file
│
├── config/
│   └── settings.py                # All constants, timeouts, scan profiles, menu options
│
├── core/
│   ├── scanner.py                 # nmap wrapper (ScanResult, HostInfo, PortInfo)
│   ├── port_scanner.py            # Masscan pipeline + PortScanOrchestrator
│   ├── banner_grabber.py          # Concurrent raw socket banner grabbing
│   ├── http_fingerprinter.py      # HTTP device/firmware fingerprinting
│   ├── nse_scanner.py             # Nmap Scripting Engine integration
│   ├── auth_tester.py             # Default credential testing (HTTP, device-specific)
│   ├── input_parser.py            # Flexible target format parsing
│   ├── network_utils.py           # Subnet detection, IP helpers, WSL detection
│   ├── findings.py                # Finding dataclass, Severity enum, FindingRegistry
│   ├── risk_scorer.py             # Per-device risk scoring (0-100)
│   ├── cache_manager.py           # Unified CVE + EOL cache (data/cache/)
│   ├── cve_checker.py             # CVE lookup + CVECacheBuilder (OSV.dev)
│   ├── ssl_checker.py             # TLS certificate, cipher suite, JA3S fingerprinting
│   ├── ssh_checker.py             # SSH version, algorithms, KEXINIT analysis
│   ├── smb_checker.py             # SMBv1, EternalBlue, shares, NTLM disclosure
│   ├── ftp_checker.py             # Anonymous FTP, STARTTLS
│   ├── snmp_checker.py            # SNMP community strings, sysDescr (pysnmp v4+v7)
│   ├── web_checker.py             # HTTP headers, admin panels, Wappalyzer
│   ├── dns_checker.py             # DNS hijack and rebinding detection
│   ├── upnp_checker.py            # SSDP discovery, UPnP risk assessment
│   ├── mdns_checker.py            # mDNS/Zeroconf device discovery
│   ├── arp_checker.py             # ARP spoofing detection
│   ├── device_identifier.py       # 14-source device identification engine
│   ├── identity_fusion.py         # Multi-source identity fusion and scoring
│   ├── oui_lookup.py              # IEEE OUI MAC vendor resolution
│   ├── device_map.py              # Persistent MAC→identity mapping
│   ├── passive_sniffer.py         # Background mDNS/SSDP/DHCP packet capture
│   ├── packet_parsers.py          # Protocol-specific packet parsing
│   ├── instant_scan.py            # ARP sweep + passive capture quick scan
│   ├── hybrid_scanner.py          # Passive+active scan orchestrator
│   ├── baseline.py                # Rogue device baseline comparison
│   ├── hardware_eol.py            # Downloaded hardware lifecycle database lookup
│   ├── scan_history.py            # Scan snapshot persistence and diffing
│   ├── module_manager.py          # Downloadable data module system
│   └── update_manager.py          # Version check and self-update
│
├── eol/
│   ├── checker.py                 # EOL API queries and version comparison
│   ├── cache.py                   # Per-product JSON cache
│   └── product_map.py             # 150+ software name -> endoflife.date slug mappings
│
├── ui/
│   ├── menu.py                    # Old-style numbered menu (no-args mode)
│   ├── display.py                 # Rich terminal tables, progress bars, banners
│   ├── export.py                  # JSON and HTML report generation
│   ├── interactive_controller.py  # Interactive mode (-i) with multi-level menus
│   └── templates/
│       └── report.html.j2         # Jinja2 HTML report template
│
└── data/
    ├── default_credentials.json   # Factory-default credentials database
    ├── device_map.json            # Persistent MAC→identity map
    ├── baseline.json              # Saved device baseline (--save-baseline)
    ├── cache/
    │   ├── cve_cache.json         # CVE data keyed by product:version
    │   ├── <product>.json         # EOL data keyed by product slug
    │   ├── hardware_eol/          # Downloaded hardware lifecycle database
    │   └── cache_meta.json        # Cache update timestamps
    ├── history/                   # Gzip scan snapshots (auto-saved)
    └── modules/                   # Downloaded data modules
```

---

## Troubleshooting

**nmap not found**

```bash
# Debian/Ubuntu
sudo apt install nmap

# Fedora
sudo dnf install nmap

# Arch
sudo pacman -S nmap

# macOS
brew install nmap
```

**Permission denied / OS detection not working**

FULL, STEALTH, and SMB profiles require elevated privileges. Without root, these profiles automatically fall back to non-root flags (OS detection and SYN scan disabled, but port/version scanning still works).

```bash
# For full capabilities:
sudo python3 netwatch.py --target 192.168.1.0/24 --profile FULL
```

**WSL2 suggests wrong network (172.x.x.x)**

On WSL2, NetWatch detects the virtual adapter and falls back to `192.168.1.0/24`. If your home network uses a different subnet, specify it with `--target`:

```bash
python3 netwatch.py --target 192.168.0.0/24
```

**Cache warnings at scan start**

```
WARNING: CVE data is 12 days old — run: python netwatch.py --update-cache
```

Scans work fine with stale data. Run `--update-cache` to refresh.

**SNMP checks not working**

NetWatch supports both pysnmp v4 (synchronous) and v7 (async). If you see import errors, update pysnmp:

```bash
pip install --upgrade pysnmp
```

---

## Disclaimer — Authorised Use Only

> **NetWatch is a security auditing tool intended for use on networks and devices that you own or have explicit written permission to test.**

Running network scans against systems you do not own or have authorisation to test may be **illegal** regardless of intent. The authors accept no liability for misuse.

NetWatch is **entirely non-destructive and read-only**. It does not exploit vulnerabilities, deliver payloads, or modify any configuration on any scanned device. The `--check-defaults` credential testing uses common factory defaults and does not brute-force accounts.

---

## License

The NetWatch repository and application code are licensed under the MIT License — Copyright 2024 NetWatch Contributors.

Only the NetWatch hardware EOL database artifacts under `data/hardware_eol/` are licensed separately: This database is licensed under the Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0). See [data/hardware_eol/LICENSE.md](data/hardware_eol/LICENSE.md).

---

## Acknowledgements

- [nmap](https://nmap.org) — scanning engine
- [python-nmap](https://pypi.org/project/python-nmap/) — Python nmap interface
- [endoflife.date](https://endoflife.date) — EOL data API
- [OSV.dev](https://osv.dev) — vulnerability database
- [Rich](https://rich.readthedocs.io) — terminal formatting
- [Jinja2](https://jinja.palletsprojects.com) — HTML report templating
- [cryptography](https://cryptography.io) — TLS certificate inspection
- [scapy](https://scapy.net) — raw packet capture and ARP scanning
- [danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) — credential and SNMP lists
- [ihebski/DefaultCreds-cheat-sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet) — vendor credentials
- [enthec/webappanalyzer](https://github.com/AliasIO/wappalyzer) — web technology detection
- [salesforce/ja3](https://github.com/salesforce/ja3) — TLS fingerprinting
- [many-passwords](https://github.com/many-passwords/many-passwords) — camera/DVR credentials
